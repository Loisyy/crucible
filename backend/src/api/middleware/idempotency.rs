use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;
use serde_json::json;

use crate::api::handlers::profiling::AppState;
use crate::error::AppError;

const IDEMPOTENCY_TTL_SECONDS: u64 = 86_400;
const IDEMPOTENCY_LOCK_TTL_MS: u64 = 30_000;
const IDEMPOTENCY_ROUTE: &str = "/api/alerts/ingest";

fn build_replayed_response(cached_response: String) -> Response {
    let mut response = Response::new(Body::from(cached_response));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.headers_mut().insert(
        "x-idempotency-replayed",
        HeaderValue::from_static("true"),
    );
    response
}

/// Cache successful `POST /api/alerts/ingest` responses by idempotency key with atomic mutual exclusion.
///
/// When `Idempotency-Key` is present:
/// - cache hit: replay the stored body immediately.
/// - cache miss: atomically reserve key using `SET resource token NX PX <ttl>` to prevent concurrent duplicate execution.
/// - on completion: atomically persist successful `200 OK` response and release reservation lock via Redis pipeline.
pub async fn idempotency_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let key = request
        .headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let Some(key) = key else {
        return Ok(next.run(request).await);
    };

    let cache_key = format!("idempotency:{IDEMPOTENCY_ROUTE}:{key}");
    let lock_key = format!("idempotency:lock:{IDEMPOTENCY_ROUTE}:{key}");
    let mut conn = state.redis.get_multiplexed_async_connection().await?;

    // 1. Check if a completed response is already cached from a previous request
    if let Some(cached_response) = conn.get::<_, Option<String>>(&cache_key).await? {
        return Ok(build_replayed_response(cached_response));
    }

    // 2. Atomically reserve key using SET resource token NX PX <ttl> to prevent concurrent race conditions
    let lock_token = uuid::Uuid::new_v4().to_string();
    let lock_res: Option<String> = redis::cmd("SET")
        .arg(&lock_key)
        .arg(&lock_token)
        .arg("NX")
        .arg("PX")
        .arg(IDEMPOTENCY_LOCK_TTL_MS)
        .query_async(&mut conn)
        .await?;

    let lock_acquired = lock_res.as_deref() == Some("OK");
    if !lock_acquired {
        // Another concurrent request is currently holding the reservation.
        // Poll briefly in case the in-flight request finishes and caches the response.
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Some(cached_response) = conn.get::<_, Option<String>>(&cache_key).await? {
                return Ok(build_replayed_response(cached_response));
            }
        }

        return Err(AppError::Conflict(
            "A request with this idempotency key is currently being processed".to_string(),
        ));
    }

    // 3. Execute downstream handler
    let response = next.run(request).await;
    if response.status() != StatusCode::OK {
        let _: Result<(), _> = conn.del(&lock_key).await;
        return Ok(response);
    }

    // 4. Capture response body
    let (parts, body) = response.into_parts();
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let _: Result<(), _> = conn.del(&lock_key).await;
            return Err(AppError::InternalError(format!("failed to read response body: {error}")));
        }
    };

    let body_text = match String::from_utf8(body_bytes.to_vec()) {
        Ok(text) => text,
        Err(error) => {
            let _: Result<(), _> = conn.del(&lock_key).await;
            return Err(AppError::InternalError(format!("response body was not UTF-8: {error}")));
        }
    };

    // 5. Atomically persist completed response and release reservation lock via Redis pipeline
    let mut pipe = redis::pipe();
    pipe.set_ex(&cache_key, body_text.clone(), IDEMPOTENCY_TTL_SECONDS);
    pipe.del(&lock_key);
    pipe.query_async::<()>(&mut conn).await?;

    let mut rebuilt = Response::from_parts(parts, Body::from(body_text));
    rebuilt.headers_mut().insert(
        "x-idempotency-replayed",
        HeaderValue::from_static("false"),
    );
    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::handlers::profiling::AppState,
        config::{reload::ConfigManager, AppConfig},
        services::{
            contract_benchmark::ContractBenchmarkService, error_recovery::ErrorManager,
            log_aggregator::LogAggregator, sys_metrics::MetricsExporter,
        },
    };
    use axum::{middleware, routing::post, Json, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tower::ServiceExt;

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn duplicate_request_replays_original_response() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_handler = counter.clone();

        let redis = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let app_state = Arc::new(AppState {
            db: None,
            metrics_exporter: Arc::new(MetricsExporter::new()),
            error_manager: Arc::new(ErrorManager::new()),
            config_manager: Arc::new(ConfigManager::new(AppConfig::default())),
            log_aggregator: Arc::new(LogAggregator::new().0),
            contract_benchmark_service: Arc::new(ContractBenchmarkService::new()),
            redis: redis.clone(),
        });

        let app = Router::new()
            .route(
                IDEMPOTENCY_ROUTE,
                post(move || {
                    let counter = counter_for_handler.clone();
                    async move {
                        let value = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        Json(json!({ "request_number": value }))
                    }
                })
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    idempotency_middleware,
                )),
            )
            .with_state(app_state);

        let request = || {
            Request::builder()
                .method("POST")
                .uri(IDEMPOTENCY_ROUTE)
                .header("content-type", "application/json")
                .header("Idempotency-Key", "duplicate-check-1")
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        let second = app.oneshot(request()).await.unwrap();

        let first_body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let second_body = to_bytes(second.into_body(), usize::MAX).await.unwrap();

        assert_eq!(first_body, second_body);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_build_replayed_response_headers() {
        let payload = r#"{"status":"ok"}"#.to_string();
        let response = build_replayed_response(payload);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get("x-idempotency-replayed").unwrap(),
            "true"
        );
    }

    #[test]
    fn test_conflict_error_status_code() {
        use axum::response::IntoResponse;
        let err = AppError::Conflict(
            "A request with this idempotency key is currently being processed".into(),
        );
        let res = err.into_response();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }
}
