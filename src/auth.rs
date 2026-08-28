//! Axum middleware for the inbound bearer.
//!
//! Unlike a server that forwards the caller's own upstream key, this one
//! authenticates against a value the deployment configured: the Withings
//! credential belongs to the server, and a caller presenting anything at all
//! would otherwise reach a real person's body metrics.
//!
//! Comparison is constant time and length-independent — the digests are
//! compared rather than the strings, so a mismatch in length is not a shorter
//! comparison.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The bearer a caller presented, after it matched. Carried in the request
/// extensions so the rate limiter can key on its hash.
#[derive(Clone)]
pub struct AccessToken(pub String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AccessToken").field(&"<redacted>").finish()
    }
}

/// The configured bearer, pre-hashed once at startup.
pub struct ExpectedToken {
    digest: [u8; 32],
}

impl std::fmt::Debug for ExpectedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpectedToken").finish_non_exhaustive()
    }
}

impl ExpectedToken {
    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            digest: digest(token),
        }
    }

    /// Constant-time comparison against the configured value.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        digest(presented).ct_eq(&self.digest).unwrap_u8() == 1
    }
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

/// Require a bearer matching the configured value.
pub async fn bearer_auth(
    State(expected): State<Arc<ExpectedToken>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(request.headers().get(header::AUTHORIZATION)) else {
        return unauthorized();
    };
    if !expected.matches(&token) {
        return unauthorized();
    }
    request.extensions_mut().insert(AccessToken(token));
    next.run(request).await
}

/// Extract a case-sensitive RFC 6750 Bearer value.
fn extract_bearer(header: Option<&HeaderValue>) -> Option<String> {
    let raw = header?.to_str().ok()?.trim();
    let (scheme, value) = raw.split_once(' ')?;
    if scheme.as_bytes().ct_eq(b"Bearer").unwrap_u8() != 1 {
        return None;
    }
    let token = value.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

fn unauthorized() -> Response {
    // A shared secret, not RFC 6750 OAuth. A Bearer challenge makes some
    // clients start OAuth discovery against a server that serves none.
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_well_formed_bearer() {
        let header = HeaderValue::from_static("Bearer inbound-token");
        assert_eq!(
            extract_bearer(Some(&header)).as_deref(),
            Some("inbound-token")
        );
    }

    #[test]
    fn rejects_lowercase_basic_and_empty_schemes() {
        for raw in ["bearer token", "Basic token", "Bearer ", "token"] {
            assert!(
                extract_bearer(Some(&HeaderValue::from_str(raw).unwrap())).is_none(),
                "{raw}"
            );
        }
        assert!(extract_bearer(None).is_none());
    }

    #[test]
    fn trims_whitespace_around_token() {
        let header = HeaderValue::from_static("Bearer   token   ");
        assert_eq!(extract_bearer(Some(&header)).as_deref(), Some("token"));
    }

    #[test]
    fn the_expected_token_matches_only_itself() {
        let expected = ExpectedToken::new("correct-horse");
        assert!(expected.matches("correct-horse"));
        assert!(!expected.matches("correct-hors"));
        assert!(!expected.matches("correct-horsee"));
        assert!(!expected.matches(""));
        // A prefix must not pass. This is the failure a naive
        // `starts_with` comparison has, and it is invisible in normal use.
        assert!(!expected.matches("correct"));
    }

    #[test]
    fn unauthorized_has_no_www_authenticate() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn neither_the_expected_nor_the_presented_token_prints() {
        assert!(!format!("{:?}", ExpectedToken::new("s3cret")).contains("s3cret"));
        assert!(!format!("{:?}", AccessToken("s3cret".to_owned())).contains("s3cret"));
    }
}
