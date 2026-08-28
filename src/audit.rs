//! Envelope-only audit logging.
//!
//! Every tool call emits a structured `tracing::info` event at target
//! `withings_mcp::audit`.
//!
//! ## What is and isn't logged
//!
//! Envelope fields **are** logged: `event`, `method` (MCP tool name),
//! `resource` (the measurement type or date range asked for), `outcome`,
//! `latency_ms`, `result_count`, `error_class`, and `token_hash` (16 hex
//! chars of `sha256(bearer)`).
//!
//! Content fields **are not** logged: measurement values, Withings user ids,
//! access or refresh tokens, authorization headers, or any other value read
//! out of the account. A body-weight series is exactly the kind of thing a
//! log should not carry, and `result_count` answers the operational question
//! without it.

use std::time::Instant;

use rmcp::ErrorData;
use sha2::{Digest, Sha256};
use tracing::info;

/// Coarse outcome class for an audit event. Stable strings for Grafana/Loki.
pub mod outcome {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";
    pub const RATE_LIMITED: &str = "rate_limited";
}

/// First 16 hex chars of `sha256(bearer)` — a stable pseudonymous token id
/// for correlation without ever logging the token.
#[must_use]
pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// JSON-RPC application code: the caller exceeded their per-minute quota
/// here, before Withings was called at all.
pub const RATE_LIMITED_CODE: i32 = -32029;

/// JSON-RPC application code: Withings answered `status: 601` to a call we
/// forwarded.
pub const WITHINGS_RATE_LIMITED_CODE: i32 = -32012;

/// The class a caller and a dashboard both key on.
///
/// **This is the only place a JSON-RPC code becomes a class.** The audit
/// event's `outcome`, its `error_class` field and the `data.class` a client
/// sees on the wire are all derived from this function, so they cannot
/// disagree about one event. Do not add a second mapping anywhere: a caller
/// telling "unreadable" from "no measurements" writes one comparison on
/// `data.class`, and it only works while both rate limits land in the same
/// class.
#[must_use]
pub const fn error_class(err: &ErrorData) -> &'static str {
    class_for_code(err.code.0)
}

#[must_use]
pub const fn class_for_code(code: i32) -> &'static str {
    match code {
        -32700 => "parse",
        -32600 => "invalid_request",
        -32601 => "method_not_found",
        -32602 => "invalid_params",
        -32603 => "internal",
        RATE_LIMITED_CODE | WITHINGS_RATE_LIMITED_CODE => outcome::RATE_LIMITED,
        _ => "other",
    }
}

/// Emit a `tool_call` audit event. Call at the END of every tool body, on
/// both success and error paths. Also bumps the matching Prometheus metric.
pub fn tool_call(
    tool: &'static str,
    token_hash: &str,
    resource: Option<&str>,
    outcome: &'static str,
    started: Instant,
    result_count: Option<usize>,
    err_class: Option<&'static str>,
) {
    let elapsed = started.elapsed();
    // `resource` may be a raw, caller-supplied tool parameter (even on
    // validation-failure paths), so sanitise it before emission to stop an
    // attacker injecting newlines or fake `outcome=` fragments into logs.
    let safe_resource: Option<&str> = resource.map(|r| if is_safe_id(r) { r } else { "<invalid>" });
    info!(
        target: "withings_mcp::audit",
        event = "tool_call",
        method = tool,
        token_hash,
        resource = safe_resource,
        outcome,
        latency_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        result_count,
        error_class = err_class,
    );
    crate::metrics::record_tool_call(tool, outcome, elapsed);
}

/// Audit-safe identifier check: no whitespace or control characters, no query
/// or fragment, bounded length.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 1024
        && !id.contains(['?', '#'])
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | ',' | '/'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_16_hex_chars() {
        let hash = token_hash("any-bearer-string");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hash, token_hash("another-bearer"));
    }

    #[test]
    fn is_safe_id_accepts_the_shapes_tools_pass() {
        assert!(is_safe_id("weight"));
        assert!(is_safe_id("1,6,8,76"));
        assert!(is_safe_id("2026-08-29"));
        assert!(!is_safe_id("has space"));
        assert!(!is_safe_id("inject\noutcome=ok"));
        assert!(!is_safe_id(""));
    }

    #[test]
    fn both_rate_limits_share_one_class_and_nothing_else_does() {
        assert_eq!(class_for_code(RATE_LIMITED_CODE), outcome::RATE_LIMITED);
        assert_eq!(
            class_for_code(WITHINGS_RATE_LIMITED_CODE),
            outcome::RATE_LIMITED
        );
        assert_eq!(
            error_class(&ErrorData::internal_error("x", None)),
            "internal"
        );
        assert_eq!(
            error_class(&ErrorData::invalid_params("x", None)),
            "invalid_params"
        );
        assert_eq!(class_for_code(-32099), "other");
    }

    #[test]
    fn outcomes_are_stable_strings() {
        assert_eq!(outcome::OK, "ok");
        assert_eq!(outcome::ERROR, "error");
        assert_eq!(outcome::RATE_LIMITED, "rate_limited");
    }
}
