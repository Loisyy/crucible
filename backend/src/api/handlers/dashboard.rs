//! Dashboard data API handler.
//!
//! Provides dashboard endpoints for aggregated system metrics, contract
//! metrics, and active runtime state.
//! Results are cached in Redis for [`CACHE_TTL_SECS`] seconds to reduce load
//! on downstream services.
//!
//! # Example
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::{Router, routing::get};
//! use backend::api::handlers::dashboard::{DashboardState, get_dashboard};
//!
//! # async fn example() {
//! // state is constructed with your real service instances
//! # }
//! ```

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use redis::{AsyncCommands, Client as RedisClient};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, warn};
use utoipa::ToSchema;

use crate::services::{
    error_recovery::{ErrorManager, RecoveryTask},
    log_alerts::{Alert, AlertManager},
    sys_metrics::{MetricsExporter, SystemMetrics},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CACHE_KEY: &str = "dashboard:summary";
const CACHE_TTL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while building the dashboard response.
#[derive(Debug, Error)]
pub enum DashboardError {
    /// A Redis error occurred.
    #[error("Cache error: {0}")]
    Cache(#[from] redis::RedisError),

    /// A database error occurred.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// JSON serialization/deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The requested resource was not found.
    #[error("{0}")]
    NotFound(String),
}

impl IntoResponse for DashboardError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            DashboardError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        error!(error = %self, status = %status, "Dashboard handler error");
        let body = serde_json::json!({ "error": self.to_string() });
        (status, Json(body)).into_response()
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Aggregated dashboard data returned by `GET /api/dashboard`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    /// Current system metrics snapshot.
    pub metrics: SystemMetrics,
    /// Recovery tasks that are currently active.
    pub active_recovery_tasks: Vec<RecoveryTask>,
    /// Alerts that have fired and not yet been resolved.
    pub active_alerts: Vec<Alert>,
}

/// Aggregated dashboard metrics for the build and contract overview.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardMetrics {
    pub total_contracts: u64,
    pub total_transactions: u64,
    pub avg_processing_time_ms: f64,
    pub failed_transactions_24h: u64,
    pub timestamp: DateTime<Utc>,
}

/// Contract-specific usage metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct ContractStats {
    pub contract_id: String,
    pub invocation_count: u64,
    pub last_invoked: Option<DateTime<Utc>>,
    pub avg_gas_cost: f64,
}

/// Request payload for batch contract stats aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct BatchContractStatsRequest {
    pub contract_ids: Vec<String>,
}

/// Query parameters for batch contract stats aggregation.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchContractStatsQuery {
    pub contract_ids: Option<String>,
}

/// Aggregated response containing batched contract statistics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct BatchContractStatsResponse {
    pub stats: Vec<ContractStats>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Shared application state for the dashboard handler.
pub struct DashboardState {
    pub metrics_exporter: Arc<MetricsExporter>,
    pub error_manager: Arc<ErrorManager>,
    pub alert_manager: Arc<AlertManager>,
    pub db: PgPool,
    pub redis: RedisClient,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/dashboard` — return aggregated dashboard data.
///
/// Attempts to serve a cached response from Redis. On cache miss (or cache
/// error) the data is assembled from the live services and the cache is
/// populated before responding.
#[tracing::instrument(skip(state))]
pub async fn get_dashboard(
    State(state): State<Arc<DashboardState>>,
) -> Result<impl IntoResponse, DashboardError> {
    // --- try cache ---
    match try_cache_get(&state.redis, CACHE_KEY).await {
        Ok(Some(cached)) => {
            debug!("Dashboard cache hit");
            return Ok(Json(cached));
        }
        Ok(None) => debug!("Dashboard cache miss"),
        Err(e) => warn!(error = %e, "Dashboard cache read failed; falling back to live data"),
    }

    let (metrics, active_recovery_tasks, active_alerts) = tokio::join!(
        state.metrics_exporter.get_metrics(),
        state.error_manager.get_active_tasks(),
        state.alert_manager.get_active_alerts(),
    );

    let data = DashboardData {
        metrics,
        active_recovery_tasks,
        active_alerts,
    };

    // --- populate cache (best-effort) ---
    if let Err(e) = try_cache_set(&state.redis, CACHE_KEY, &data).await {
        warn!(error = %e, "Failed to populate dashboard cache");
    }

    Ok(Json(data))
}

/// `GET /api/v1/dashboard/metrics` — return aggregate contract and pipeline metrics.
#[utoipa::path(
    get,
    path = "/api/v1/dashboard/metrics",
    responses((status = 200, description = "Dashboard metrics", body = DashboardMetrics)),
    tag = "dashboard"
)]
#[tracing::instrument(skip(state))]
pub async fn get_dashboard_metrics(
    State(state): State<Arc<DashboardState>>,
) -> Result<impl IntoResponse, DashboardError> {
    match try_cache_get(&state.redis, "dashboard:metrics").await {
        Ok(Some(cached)) => return Ok(Json(cached)),
        Ok(None) => debug!("Dashboard metrics cache miss"),
        Err(e) => warn!(error = %e, "Dashboard metrics cache read failed; falling back to live data"),
    }

    let total_contracts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contracts")
        .fetch_one(&state.db)
        .await?;
    let total_transactions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
        .fetch_one(&state.db)
        .await?;
    let avg_processing_time_ms: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(processing_time_ms) FROM transactions WHERE processing_time_ms IS NOT NULL",
    )
    .fetch_one(&state.db)
    .await?;
    let failed_transactions_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM transactions WHERE status = 'failed' AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(&state.db)
    .await?;

    let metrics = DashboardMetrics {
        total_contracts: total_contracts as u64,
        total_transactions: total_transactions as u64,
        avg_processing_time_ms: avg_processing_time_ms.unwrap_or(0.0),
        failed_transactions_24h: failed_transactions_24h as u64,
        timestamp: Utc::now(),
    };

    if let Err(e) = try_cache_set(&state.redis, "dashboard:metrics", &metrics).await {
        warn!(error = %e, "Failed to populate dashboard metrics cache");
    }

    Ok(Json(metrics))
}

/// Query aggregated stats for a batch of contract IDs using a single consolidated SQL query
/// with `GROUP BY` and window ranking, eliminating N+1 database queries.
pub async fn fetch_batch_contract_stats(
    pool: &PgPool,
    contract_ids: &[String],
) -> Result<Vec<ContractStats>, DashboardError> {
    if contract_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Consolidated query joining contracts and transactions with GROUP BY and window function:
    // Computes invocation count, last invoked timestamp, and average gas cost for all requested contracts in a single pass.
    let rows: Vec<(String, i64, Option<DateTime<Utc>>, Option<f64>)> = sqlx::query_as(
        r#"
        WITH aggregated AS (
            SELECT 
                c.contract_id,
                COUNT(t.id) AS invocation_count,
                MAX(t.created_at) AS last_invoked,
                AVG(t.gas_cost) AS avg_gas_cost,
                ROW_NUMBER() OVER (PARTITION BY c.contract_id ORDER BY MAX(t.created_at) DESC NULLS LAST) AS _rn
            FROM contracts c
            LEFT JOIN transactions t ON c.contract_id = t.contract_id
            WHERE c.contract_id = ANY($1)
            GROUP BY c.contract_id
        )
        SELECT contract_id, invocation_count, last_invoked, avg_gas_cost
        FROM aggregated
        ORDER BY contract_id ASC
        "#,
    )
    .bind(contract_ids)
    .fetch_all(pool)
    .await?;

    let stats = rows
        .into_iter()
        .map(|(contract_id, count, last_invoked, avg_gas)| ContractStats {
            contract_id,
            invocation_count: count as u64,
            last_invoked,
            avg_gas_cost: avg_gas.unwrap_or(0.0),
        })
        .collect();

    Ok(stats)
}

/// `GET /api/v1/dashboard/contracts/:contract_id/stats` — return contract usage statistics.
#[utoipa::path(
    get,
    path = "/api/v1/dashboard/contracts/{contract_id}/stats",
    params(
        ("contract_id" = String, Path, description = "Contract identifier")
    ),
    responses(
        (status = 200, description = "Contract stats", body = ContractStats),
        (status = 404, description = "Contract not found")
    ),
    tag = "dashboard"
)]
#[tracing::instrument(skip(state))]
pub async fn get_contract_stats(
    Path(contract_id): Path<String>,
    State(state): State<Arc<DashboardState>>,
) -> Result<impl IntoResponse, DashboardError> {
    let cache_key = format!("dashboard:contract_stats:{contract_id}");

    match try_cache_get(&state.redis, &cache_key).await {
        Ok(Some(cached)) => return Ok(Json(cached)),
        Ok(None) => debug!(contract_id = %contract_id, "Contract stats cache miss"),
        Err(e) => warn!(error = %e, contract_id = %contract_id, "Contract stats cache read failed; falling back to live data"),
    }

    let batch = fetch_batch_contract_stats(&state.db, &[contract_id.clone()]).await?;
    let stats = batch.into_iter().next().ok_or_else(|| {
        DashboardError::NotFound(format!("Contract {contract_id} not found"))
    })?;

    if let Err(e) = try_cache_set(&state.redis, &cache_key, &stats).await {
        warn!(error = %e, contract_id = %stats.contract_id, "Failed to populate contract stats cache");
    }

    Ok(Json(stats))
}

/// `POST /api/v1/dashboard/contracts/stats/batch` — return batch contract usage statistics in a single request.
#[utoipa::path(
    post,
    path = "/api/v1/dashboard/contracts/stats/batch",
    request_body = BatchContractStatsRequest,
    responses(
        (status = 200, description = "Batch contract stats", body = BatchContractStatsResponse)
    ),
    tag = "dashboard"
)]
#[tracing::instrument(skip(state))]
pub async fn get_batch_contract_stats(
    State(state): State<Arc<DashboardState>>,
    Json(payload): Json<BatchContractStatsRequest>,
) -> Result<impl IntoResponse, DashboardError> {
    let stats = get_batch_contract_stats_inner(&state, payload.contract_ids).await?;
    Ok(Json(BatchContractStatsResponse { stats }))
}

/// `GET /api/v1/dashboard/contracts/stats` — return batch contract usage statistics via query string.
#[tracing::instrument(skip(state))]
pub async fn get_batch_contract_stats_query(
    State(state): State<Arc<DashboardState>>,
    axum::extract::Query(query): axum::extract::Query<BatchContractStatsQuery>,
) -> Result<impl IntoResponse, DashboardError> {
    let contract_ids = query
        .contract_ids
        .map(|s| {
            s.split(',')
                .map(|item| item.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let stats = get_batch_contract_stats_inner(&state, contract_ids).await?;
    Ok(Json(BatchContractStatsResponse { stats }))
}

async fn get_batch_contract_stats_inner(
    state: &DashboardState,
    contract_ids: Vec<String>,
) -> Result<Vec<ContractStats>, DashboardError> {
    if contract_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut unique_ids = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for id in contract_ids {
        if seen.insert(id.clone()) {
            unique_ids.push(id);
        }
    }

    let mut results: Vec<ContractStats> = Vec::with_capacity(unique_ids.len());
    let mut uncached_ids: Vec<String> = Vec::new();

    // Check Redis cache for each contract
    for id in &unique_ids {
        let cache_key = format!("dashboard:contract_stats:{id}");
        match try_cache_get::<ContractStats>(&state.redis, &cache_key).await {
            Ok(Some(cached)) => {
                results.push(cached);
            }
            Ok(None) => {
                uncached_ids.push(id.clone());
            }
            Err(e) => {
                warn!(error = %e, contract_id = %id, "Contract stats cache read failed; fetching live");
                uncached_ids.push(id.clone());
            }
        }
    }

    // Single consolidated SQL query for all cache misses
    if !uncached_ids.is_empty() {
        let fetched = fetch_batch_contract_stats(&state.db, &uncached_ids).await?;

        for stats in fetched {
            let cache_key = format!("dashboard:contract_stats:{}", stats.contract_id);
            if let Err(e) = try_cache_set(&state.redis, &cache_key, &stats).await {
                warn!(error = %e, contract_id = %stats.contract_id, "Failed to populate contract stats cache");
            }
            results.push(stats);
        }
    }

    // Deterministic sort order by contract_id
    results.sort_by(|a, b| a.contract_id.cmp(&b.contract_id));

    Ok(results)
}

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

async fn try_cache_get<T>(redis: &RedisClient, key: &str) -> Result<Option<T>, DashboardError>
where
    T: DeserializeOwned,
{
    let mut conn = redis.get_multiplexed_async_connection().await?;
    let raw: Option<String> = conn.get(key).await?;
    match raw {
        Some(s) => Ok(Some(serde_json::from_str(&s)?)),
        None => Ok(None),
    }
}

async fn try_cache_set<T>(
    redis: &RedisClient,
    key: &str,
    data: &T,
) -> Result<(), DashboardError>
where
    T: Serialize,
{
    let serialized = serde_json::to_string(data)?;
    let mut conn = redis.get_multiplexed_async_connection().await?;
    let _: () = conn.set_ex(key, serialized, CACHE_TTL_SECS).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    fn make_state() -> Arc<DashboardState> {
        Arc::new(DashboardState {
            metrics_exporter: Arc::new(MetricsExporter::new()),
            error_manager: Arc::new(ErrorManager::new()),
            alert_manager: Arc::new(AlertManager::new()),
            db: PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://postgres:postgres@localhost/crucible_test")
                .unwrap(),
            // Use a URL that will fail to connect — the handler degrades gracefully.
            redis: RedisClient::open("redis://127.0.0.1:1/").unwrap(),
        })
    }

    fn make_app(state: Arc<DashboardState>) -> Router {
        Router::new()
            .route("/api/dashboard", get(get_dashboard))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_dashboard_returns_200_without_redis() {
        let app = make_app(make_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_dashboard_response_shape() {
        let app = make_app(make_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(json.get("metrics").is_some());
        assert!(json.get("active_recovery_tasks").is_some());
        assert!(json.get("active_alerts").is_some());
    }

    #[tokio::test]
    async fn test_dashboard_metrics_fields() {
        let state = make_state();
        state.metrics_exporter.update_metrics(42.0, 2048, 120, 4096, 2048).await;

        let app = make_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["metrics"]["cpu_usage"], 42.0);
        assert_eq!(json["metrics"]["memory_usage"], 2048);
        assert_eq!(json["metrics"]["uptime"], 120);
    }

    #[tokio::test]
    async fn test_dashboard_includes_recovery_tasks() {
        use crate::services::error_recovery::RecoveryError;

        let state = make_state();
        state
            .error_manager
            .handle_error(RecoveryError::Internal("boom".into()), "worker_a")
            .await
            .unwrap();

        let app = make_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let tasks = json["active_recovery_tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["name"], "worker_a");
    }

    #[test]
    fn test_dashboard_data_serialization_roundtrip() {
        let data = DashboardData {
            metrics: SystemMetrics::default(),
            active_recovery_tasks: vec![],
            active_alerts: vec![],
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: DashboardData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.active_recovery_tasks.len(), 0);
        assert_eq!(back.active_alerts.len(), 0);
    }

    #[tokio::test]
    async fn test_batch_contract_stats_empty_request() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/api/dashboard/contracts/stats/batch",
                axum::routing::post(get_batch_contract_stats),
            )
            .with_state(state);

        let req_body = serde_json::to_vec(&BatchContractStatsRequest {
            contract_ids: vec![],
        })
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dashboard/contracts/stats/batch")
                    .header("content-type", "application/json")
                    .body(Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: BatchContractStatsResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.stats.len(), 0);
    }

    #[tokio::test]
    async fn test_batch_contract_stats_query_empty() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/api/dashboard/contracts/stats",
                axum::routing::get(get_batch_contract_stats_query),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/dashboard/contracts/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: BatchContractStatsResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.stats.len(), 0);
    }

    #[test]
    fn test_batch_contract_stats_roundtrip() {
        let req = BatchContractStatsRequest {
            contract_ids: vec!["c1".to_string(), "c2".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: BatchContractStatsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.contract_ids, vec!["c1", "c2"]);

        let resp = BatchContractStatsResponse {
            stats: vec![ContractStats {
                contract_id: "c1".to_string(),
                invocation_count: 5,
                last_invoked: None,
                avg_gas_cost: 123.45,
            }],
        };
        let resp_json = serde_json::to_string(&resp).unwrap();
        let resp_back: BatchContractStatsResponse = serde_json::from_str(&resp_json).unwrap();
        assert_eq!(resp_back.stats.len(), 1);
        assert_eq!(resp_back.stats[0].contract_id, "c1");
        assert_eq!(resp_back.stats[0].invocation_count, 5);
    }
}
