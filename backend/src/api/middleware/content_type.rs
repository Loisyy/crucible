use axum::{
    extract::Request,
    http::{header, Method},
    middleware::Next,
    response::Response,
};

use crate::error::AppError;

/// Middleware that validates the Content-Type header on mutating requests.
///
/// For POST, PUT, and PATCH requests, this middleware ensures the client
/// sends `Content-Type: application/json`. Safe methods (GET, HEAD, OPTIONS)
/// are allowed through without validation.
///
/// Returns `415 Unsupported Media Type` if the Content-Type is missing or
/// the parsed primary media type does not match `application/json`.
pub async fn require_json_content_type(req: Request, next: Next) -> Result<Response, AppError> {
    if req.method() == Method::GET || req.method() == Method::HEAD || req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if is_json_content_type(content_type) {
        Ok(next.run(req).await)
    } else {
        Err(AppError::UnsupportedMediaType(
            "Expected Content-Type: application/json".into(),
        ))
    }
}

/// Helper to validate if a Content-Type header string represents `application/json`.
/// Splits off any optional parameters (e.g. `; charset=utf-8`) and checks primary media type case-insensitively.
pub fn is_json_content_type(header_val: &str) -> bool {
    let media_type = header_val.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_json_content_type_valid() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/json;charset=utf-8"));
        assert!(is_json_content_type("APPLICATION/JSON"));
        assert!(is_json_content_type("APPLICATION/JSON; charset=utf-8"));
        assert!(is_json_content_type("  application/json  ; boundary=something "));
    }

    #[test]
    fn test_is_json_content_type_invalid_and_bypass_prevention() {
        // Bypass attempts that starts_with would incorrectly accept
        assert!(!is_json_content_type("application/json_evil"));
        assert!(!is_json_content_type("application/json5"));
        assert!(!is_json_content_type("application/json-patch+json"));

        // Other content types
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/xml"));
        assert!(!is_json_content_type("multipart/form-data"));
        assert!(!is_json_content_type(""));
    }
}
