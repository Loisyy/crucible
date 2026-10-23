use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::profiling::AppState;
use crate::error::AppError;

/// Maximum allowed alert ingestion payload size (1 MB) to prevent flood DoS.
pub const MAX_ALERT_PAYLOAD_SIZE: usize = 1_048_576;

/// Request body for `POST /api/alerts/ingest` and `POST /api/v1/alerts/ingest`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AlertIngestRequest {
    pub source: String,
    pub message: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

/// Response body for `POST /api/alerts/ingest` and `POST /api/v1/alerts/ingest`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AlertIngestResponse {
    pub alert_id: String,
    pub accepted: bool,
    pub source: String,
    pub message: String,
    pub severity: String,
    pub metadata: Option<Value>,
    pub received_at: DateTime<Utc>,
}

/// Helper function to extract a service token from authorization or API key headers.
pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers.get("Authorization").or_else(|| headers.get("authorization")) {
        if let Ok(auth_str) = auth_val.to_str() {
            if let Some(token) = auth_str
                .strip_prefix("Bearer ")
                .or_else(|| auth_str.strip_prefix("bearer "))
            {
                return Some(token.trim().to_string());
            }
        }
    }
    if let Some(val) = headers.get("X-API-Key").or_else(|| headers.get("x-api-key")) {
        if let Ok(key) = val.to_str() {
            return Some(key.trim().to_string());
        }
    }
    if let Some(val) = headers.get("X-Alert-Token").or_else(|| headers.get("x-alert-token")) {
        if let Ok(key) = val.to_str() {
            return Some(key.trim().to_string());
        }
    }
    if let Some(val) = headers.get("X-Service-Token").or_else(|| headers.get("x-service-token")) {
        if let Ok(key) = val.to_str() {
            return Some(key.trim().to_string());
        }
    }
    None
}

/// Helper function to extract an HMAC signature from webhook signature headers.
pub fn extract_hmac_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(val) = headers
        .get("X-Hub-Signature-256")
        .or_else(|| headers.get("x-hub-signature-256"))
    {
        if let Ok(sig) = val.to_str() {
            return Some(sig.trim().to_string());
        }
    }
    if let Some(val) = headers
        .get("X-Alert-Signature")
        .or_else(|| headers.get("x-alert-signature"))
    {
        if let Ok(sig) = val.to_str() {
            return Some(sig.trim().to_string());
        }
    }
    if let Some(val) = headers
        .get("X-Signature-SHA256")
        .or_else(|| headers.get("x-signature-sha256"))
    {
        if let Ok(sig) = val.to_str() {
            return Some(sig.trim().to_string());
        }
    }
    None
}

/// Constant-time verification of a service token against expected tokens.
pub fn verify_service_token(token: &str, expected_tokens: &[String]) -> bool {
    let token_bytes = token.trim().as_bytes();
    for expected in expected_tokens {
        let expected_bytes = expected.trim().as_bytes();
        if token_bytes.len() == expected_bytes.len() && token_bytes.ct_eq(expected_bytes).into() {
            return true;
        }
    }
    false
}

/// Computes HMAC-SHA256 according to RFC 2104 / FIPS 198.
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..32].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; 64];
    let mut outer_pad = [0u8; 64];
    for i in 0..64 {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: H((K' ^ ipad) || data)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&inner_pad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ^ opad) || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&outer_pad);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    outer_hash.into()
}

/// Constant-time verification of an HMAC-SHA256 signature against payload bytes.
pub fn verify_hmac_signature(secret: &[u8], body: &[u8], provided_hex: &str) -> bool {
    let clean_hex = provided_hex
        .strip_prefix("sha256=")
        .unwrap_or(provided_hex)
        .trim();
    let Ok(expected_bytes) = hex::decode(clean_hex) else {
        return false;
    };

    let result = compute_hmac_sha256(secret, body);
    result.as_slice().ct_eq(&expected_bytes).into()
}

/// Middleware that protects the alert ingestion endpoint against flood DoS and unauthorized access.
///
/// Requires either:
/// 1. A valid service token or API key (`Authorization: Bearer <token>`, `X-API-Key`, or `X-Alert-Token`)
/// 2. A valid HMAC-SHA256 webhook signature (`X-Hub-Signature-256`, `X-Alert-Signature`)
pub async fn alert_auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    if std::env::var("ALERT_INGEST_ALLOW_ANONYMOUS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
    {
        return Ok(next.run(request).await);
    }

    let (parts, body) = request.into_parts();

    // 1. Buffer the body with a strict maximum limit to prevent memory exhaustion DoS
    let bytes = match to_bytes(body, MAX_ALERT_PAYLOAD_SIZE).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "error": "payload_too_large",
                        "message": format!(
                            "Payload exceeds maximum allowed size of {} bytes",
                            MAX_ALERT_PAYLOAD_SIZE
                        )
                    })
                    .to_string(),
                ))
                .unwrap());
        }
    };

    // 2. Collect expected service tokens
    let mut expected_tokens = Vec::new();
    if let Ok(t) = std::env::var("ALERT_INGEST_TOKEN") {
        if !t.trim().is_empty() {
            expected_tokens.push(t);
        }
    }
    if let Ok(t) = std::env::var("ALERT_INGEST_API_KEY") {
        if !t.trim().is_empty() {
            expected_tokens.push(t);
        }
    }
    if let Ok(t) = std::env::var("ALERT_SERVICE_TOKEN") {
        if !t.trim().is_empty() {
            expected_tokens.push(t);
        }
    }
    if let Ok(t) = std::env::var("ADMIN_API_TOKEN") {
        if !t.trim().is_empty() {
            expected_tokens.push(t);
        }
    }
    if let Ok(t) = std::env::var("OPERATOR_API_TOKEN") {
        if !t.trim().is_empty() {
            expected_tokens.push(t);
        }
    }

    let mut is_authenticated = false;

    // Check Service Token / API Key
    if let Some(token) = extract_token_from_headers(&parts.headers) {
        if !expected_tokens.is_empty() {
            if verify_service_token(&token, &expected_tokens) {
                is_authenticated = true;
            }
        } else {
            // Default dev/test tokens if no specific environment variable is set
            if token == "dev-alert-token" || token == "crucible-alerts-secret" {
                is_authenticated = true;
            }
        }
    }

    // Check Webhook HMAC signature
    if !is_authenticated {
        if let Some(sig) = extract_hmac_from_headers(&parts.headers) {
            let mut webhook_secrets = Vec::new();
            if let Ok(s) = std::env::var("ALERT_WEBHOOK_SECRET") {
                if !s.trim().is_empty() {
                    webhook_secrets.push(s);
                }
            }
            if let Ok(s) = std::env::var("ALERT_HMAC_SECRET") {
                if !s.trim().is_empty() {
                    webhook_secrets.push(s);
                }
            }
            if let Ok(s) = std::env::var("ALERT_INGESTION_SECRET") {
                if !s.trim().is_empty() {
                    webhook_secrets.push(s);
                }
            }

            if webhook_secrets.is_empty() {
                webhook_secrets.push("dev-alert-hmac-secret".to_string());
            }

            for secret in webhook_secrets {
                if verify_hmac_signature(secret.as_bytes(), &bytes, &sig) {
                    is_authenticated = true;
                    break;
                }
            }
        }
    }

    if !is_authenticated {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "unauthorized",
                    "message": "Alert ingestion requires a valid service token or webhook HMAC signature"
                })
                .to_string(),
            ))
            .unwrap());
    }

    // Reconstruct request with the buffered body for downstream handlers
    let reconstructed_req = Request::from_parts(parts, Body::from(bytes));
    Ok(next.run(reconstructed_req).await)
}

/// Ingests one alert event.
#[utoipa::path(
    post,
    path = "/api/alerts/ingest",
    request_body = AlertIngestRequest,
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Optional key used to make retries idempotent for 24 hours"),
        ("Authorization" = Option<String>, Header, description = "Bearer service token"),
        ("X-API-Key" = Option<String>, Header, description = "Alert ingestion API key"),
        ("X-Hub-Signature-256" = Option<String>, Header, description = "HMAC-SHA256 webhook signature")
    ),
    responses(
        (status = 200, description = "Alert ingested", body = AlertIngestResponse),
        (status = 400, description = "Invalid payload"),
        (status = 401, description = "Unauthorized - service token or HMAC signature required"),
        (status = 413, description = "Payload too large")
    ),
    tag = "alerts"
)]
pub async fn ingest_alert(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<AlertIngestRequest>,
) -> Result<Json<AlertIngestResponse>, AppError> {
    if payload.source.trim().is_empty() {
        return Err(AppError::BadRequest("source is required".to_string()));
    }
    if payload.message.trim().is_empty() {
        return Err(AppError::BadRequest("message is required".to_string()));
    }

    let response = AlertIngestResponse {
        alert_id: Uuid::new_v4().to_string(),
        accepted: true,
        source: payload.source,
        message: payload.message,
        severity: payload
            .severity
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "info".to_string()),
        metadata: payload.metadata,
        received_at: Utc::now(),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_token_from_various_headers() {
        let mut headers = HeaderMap::new();
        assert!(extract_token_from_headers(&headers).is_none());

        headers.insert("Authorization", "Bearer test-secret-token".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("test-secret-token".to_string())
        );

        headers.remove("Authorization");
        headers.insert("X-API-Key", "api-key-123".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("api-key-123".to_string())
        );

        headers.remove("X-API-Key");
        headers.insert("X-Alert-Token", "alert-token-xyz".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("alert-token-xyz".to_string())
        );
    }

    #[test]
    fn test_verify_service_token_constant_time() {
        let expected = vec!["token_alpha".to_string(), "token_beta".to_string()];
        assert!(verify_service_token("token_alpha", &expected));
        assert!(verify_service_token("token_beta", &expected));
        assert!(!verify_service_token("token_gamma", &expected));
        assert!(!verify_service_token("token_alph", &expected));
    }

    #[test]
    fn test_compute_and_verify_hmac_signature() {
        let secret = b"my_super_secret_webhook_key";
        let body = b"{\"source\":\"security_sensor\",\"message\":\"unauthorized_probe\"}";

        let raw_bytes = compute_hmac_sha256(secret, body);
        let raw_hex = hex::encode(raw_bytes);

        // With sha256= prefix
        let with_prefix = format!("sha256={}", raw_hex);
        assert!(verify_hmac_signature(secret, body, &with_prefix));

        // Without prefix
        assert!(verify_hmac_signature(secret, body, &raw_hex));

        // Tampered body
        let tampered_body = b"{\"source\":\"security_sensor\",\"message\":\"tampered\"}";
        assert!(!verify_hmac_signature(secret, tampered_body, &with_prefix));

        // Wrong secret
        let wrong_secret = b"wrong_secret_key";
        assert!(!verify_hmac_signature(wrong_secret, body, &with_prefix));
    }
}
