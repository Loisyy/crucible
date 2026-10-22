#![allow(dead_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Sanitizes HTML content to prevent XSS attacks
/// Uses a conservative allowlist approach - only allows safe tags
fn sanitize_html(input: &str) -> String {
    // Use a simple HTML escaping for documentation content
    // This prevents any HTML/JavaScript from being interpreted
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDoc {
    pub name: String,
    pub type_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDoc {
    pub name: String,
    pub description: String,
    pub params: Vec<ParamDoc>,
    pub returns: String,
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDoc {
    pub name: String,
    pub description: String,
    pub fields: Vec<ParamDoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDoc {
    pub contract_name: String,
    pub version: String,
    pub description: String,
    pub functions: Vec<FunctionDoc>,
    pub events: Vec<EventDoc>,
    pub generated_at: chrono::DateTime<Utc>,
}

pub struct DocGeneratorService {
    #[allow(dead_code)]
    db: PgPool,
}

impl DocGeneratorService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn generate(
        &self,
        contract_name: &str,
        source_code: &str,
    ) -> Result<ContractDoc, sqlx::Error> {
        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut description = String::new();
        let mut pending_doc = String::new();

        for line in source_code.lines() {
            let trimmed = line.trim();
            if let Some(doc) = trimmed.strip_prefix("///") {
                pending_doc.push_str(doc.trim());
                pending_doc.push(' ');
            } else if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
                let fn_name = trimmed
                    .trim_start_matches("pub ")
                    .trim_start_matches("fn ")
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !fn_name.is_empty() {
                    functions.push(FunctionDoc {
                        name: fn_name,
                        // Sanitize description to prevent XSS in OpenAPI docs
                        description: sanitize_html(pending_doc.trim()),
                        params: vec![],
                        returns: "unknown".to_string(),
                        visibility: if trimmed.starts_with("pub") {
                            "public".to_string()
                        } else {
                            "private".to_string()
                        },
                    });
                }
                pending_doc.clear();
            } else if trimmed.contains("events().publish") {
                let event_name = trimmed
                    .split('(')
                    .nth(1)
                    .and_then(|s| s.split(',').next())
                    .unwrap_or("unknown")
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                    .to_string();
                if !event_name.is_empty() {
                    events.push(EventDoc {
                        name: event_name,
                        // Sanitize event description to prevent XSS
                        description: sanitize_html(pending_doc.trim()),
                        fields: vec![],
                    });
                }
                pending_doc.clear();
            } else if !trimmed.is_empty() {
                if description.is_empty() && !pending_doc.is_empty() {
                    // Sanitize contract description
                    description = sanitize_html(pending_doc.trim());
                }
                pending_doc.clear();
            }
        }

        Ok(ContractDoc {
            contract_name: contract_name.to_string(),
            version: "0.1.0".to_string(),
            description,
            functions,
            events,
            generated_at: Utc::now(),
        })
    }

    pub fn generate_markdown(&self, doc: &ContractDoc) -> String {
        let mut md = format!("# {}\n\n", doc.contract_name);
        if !doc.description.is_empty() {
            // Markdown already sanitized from generate(), but double-sanitize for safety
            md.push_str(&format!("{}", sanitize_html(&doc.description)));
            md.push_str("\n\n");
        }
        if !doc.functions.is_empty() {
            md.push_str("## Functions\n\n");
            for f in &doc.functions {
                md.push_str(&format!("### `{}`\n\n{}", f.name, sanitize_html(&f.description)));
                md.push_str("\n\n");
            }
        }
        if !doc.events.is_empty() {
            md.push_str("## Events\n\n");
            for e in &doc.events {
                md.push_str(&format!("### `{}`\n\n{}", e.name, sanitize_html(&e.description)));
                md.push_str("\n\n");
            }
        }
        md
    }

    pub fn generate_json(&self, doc: &ContractDoc) -> serde_json::Value {
        serde_json::to_value(doc).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_html_escapes_script_tags() {
        let malicious = "<script>alert('XSS')</script>";
        let sanitized = sanitize_html(malicious);
        assert_eq!(sanitized, "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;");
        assert!(!sanitized.contains("<script>"));
    }

    #[test]
    fn test_sanitize_html_escapes_event_handlers() {
        let malicious = "<img src=x onerror=\"alert('XSS')\">";
        let sanitized = sanitize_html(malicious);
        assert!(!sanitized.contains("onerror="));
        assert!(sanitized.contains("&lt;"));
    }

    #[test]
    fn test_sanitize_html_escapes_entities() {
        let input = "Normal & safe <content>";
        let sanitized = sanitize_html(input);
        assert_eq!(sanitized, "Normal &amp; safe &lt;content&gt;");
    }

    #[test]
    fn test_sanitize_html_preserves_text() {
        let text = "This is a normal docstring";
        let sanitized = sanitize_html(text);
        assert_eq!(sanitized, text);
    }

    #[tokio::test]
    async fn test_doc_generation_sanitizes_descriptions() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost/crucible_test")
            .unwrap();
        let service = DocGeneratorService::new(db);

        let source = r#"
        /// This function <script>alert('XSS')</script> does something
        pub fn dangerous_fn() {}
        "#;

        let doc = service.generate("TestContract", source).await.unwrap();
        assert!(doc.functions.len() > 0);
        assert!(!doc.functions[0].description.contains("<script>"));
        assert!(doc.functions[0].description.contains("&lt;script&gt;"));
    }
}
