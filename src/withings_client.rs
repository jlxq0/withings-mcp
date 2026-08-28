//! Thin first-party client for the Withings public API.
//!
//! Two surfaces: the `OAuth2` token service at `/v2/oauth2`, and the measure
//! service at `/measure`. Both answer HTTP 200 for application errors and put
//! the real outcome in a `status` field, so a status check on the HTTP layer
//! alone reports success for an expired token.
//!
//! Client secrets and tokens are sent as form fields and never appear in a
//! `Debug` value, an error message, or a URL.

use std::fmt;
use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use url::Url;

/// Withings' public API root. Both the `OAuth2` and measure services live here.
pub const DEFAULT_API_BASE_URL: &str = "https://wbsapi.withings.net";

/// Withings' authorisation page, where the user grants consent. Not an API
/// host — it is only ever rendered into a URL a person opens.
pub const AUTHORIZE_URL: &str = "https://account.withings.com/oauth2_user/authorize2";

/// The only scope this server asks for. Body metrics and nothing else.
pub const SCOPE: &str = "user.metrics";

/// `status` in a Withings response body. `0` is success and everything else
/// is an application error delivered with HTTP 200.
mod status {
    /// The request succeeded.
    pub const OK: i64 = 0;
    /// Bad user id.
    pub const BAD_USERID: i64 = 247;
    /// The caller is not authorised for this user.
    pub const NOT_AUTHORIZED: i64 = 250;
    /// Bad OAuth signature.
    pub const BAD_OAUTH_SIGNATURE: i64 = 342;
    /// The access token is invalid or expired.
    pub const INVALID_TOKEN: i64 = 401;
    /// Invalid parameters.
    pub const INVALID_PARAMS: i64 = 503;
    /// Too many requests.
    pub const TOO_MANY_REQUESTS: i64 = 601;
}

#[derive(Debug, Error)]
pub enum WithingsError {
    #[error("withings_not_authorized")]
    Unauthorized,
    #[error("withings_invalid_grant")]
    InvalidGrant,
    #[error("invalid Withings request: {0}")]
    InvalidInput(String),
    #[error("Withings API rate limit exceeded")]
    RateLimited,
    #[error("Withings API returned status {status}")]
    Api { status: i64 },
    #[error("Withings API returned HTTP {status}")]
    Upstream { status: u16 },
    #[error("Withings API transport failed")]
    Transport(#[source] reqwest::Error),
    #[error("Withings API returned invalid JSON")]
    InvalidJson(#[source] serde_json::Error),
}

impl WithingsError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "withings_not_authorized",
            Self::InvalidGrant => "withings_invalid_grant",
            Self::InvalidInput(_) => "withings_invalid_input",
            Self::RateLimited => "withings_rate_limited",
            Self::Api { .. } => "withings_api_error",
            Self::Upstream { .. } => "withings_upstream_error",
            Self::Transport(_) => "withings_transport_error",
            Self::InvalidJson(_) => "withings_invalid_response",
        }
    }
}

/// One `OAuth2` token response.
///
/// `refresh_token` is present on both grants: Withings rotates it on every
/// refresh, so the value here always replaces the one that produced it.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub userid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scope: String,
    pub expires_in: u64,
}

/// Redacts both tokens. A `TokenResponse` reaches a log only through this.
impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("userid", &self.userid)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// Withings' `OAuth2` client credentials.
#[derive(Clone)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

/// Build the URL a person opens to grant consent.
///
/// `state` is echoed back to the callback and is what stops a stranger
/// completing the flow against this deployment with their own account.
#[must_use]
pub fn authorize_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let mut url = String::from(AUTHORIZE_URL);
    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("scope", SCOPE)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state);
    url.push('?');
    url.push_str(&query.finish());
    url
}

/// `url` re-exports the `form_urlencoded` crate, so we do not name it as a
/// separate dependency and cannot end up with two versions of it.
use url::form_urlencoded;

#[derive(Clone)]
pub struct WithingsClient {
    http: reqwest::Client,
    base_url: Url,
}

impl fmt::Debug for WithingsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithingsClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl WithingsClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let mut base_url = Url::parse(base_url)?;
        anyhow::ensure!(
            matches!(base_url.scheme(), "http" | "https") && base_url.host_str().is_some(),
            "Withings base URL must be an absolute http(s) URL"
        );
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("withings-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, base_url })
    }

    /// Exchange an authorisation code for the first token pair.
    ///
    /// The code is single-use and short-lived; a second call with the same
    /// code is an `InvalidGrant`, not a transport failure.
    pub async fn exchange_code(
        &self,
        credentials: &ClientCredentials,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, WithingsError> {
        if code.trim().is_empty() {
            return Err(WithingsError::InvalidInput("code must not be empty".into()));
        }
        self.request_token(&[
            ("action", "requesttoken"),
            ("grant_type", "authorization_code"),
            ("client_id", &credentials.client_id),
            ("client_secret", &credentials.client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .await
    }

    /// Trade a refresh token for a fresh pair.
    ///
    /// The response carries a **new** refresh token. The one passed in here is
    /// dead as soon as the returned access token is used, so a caller that
    /// does not persist the new value has silently spent its credential.
    pub async fn refresh(
        &self,
        credentials: &ClientCredentials,
        refresh_token: &str,
    ) -> Result<TokenResponse, WithingsError> {
        if refresh_token.trim().is_empty() {
            return Err(WithingsError::InvalidInput(
                "refresh token must not be empty".into(),
            ));
        }
        self.request_token(&[
            ("action", "requesttoken"),
            ("grant_type", "refresh_token"),
            ("client_id", &credentials.client_id),
            ("client_secret", &credentials.client_secret),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn request_token(&self, form: &[(&str, &str)]) -> Result<TokenResponse, WithingsError> {
        let url = self.join("v2/oauth2")?;
        let response = self
            .http
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(WithingsError::Transport)?;
        let body = read_envelope(response).await?;
        serde_json::from_value(body).map_err(WithingsError::InvalidJson)
    }

    /// `measure?action=getmeas` with a bearer access token.
    ///
    /// `meastypes` is a comma-separated list of Withings meastype numbers.
    /// The dates are Unix seconds; `lastupdate` is the incremental cursor and
    /// is mutually exclusive with the date range at Withings' end.
    pub async fn get_measures(
        &self,
        access_token: &str,
        query: &MeasureQuery,
    ) -> Result<Value, WithingsError> {
        let url = self.join("measure")?;
        let mut form: Vec<(&str, String)> = vec![("action", "getmeas".to_owned())];
        if !query.meastypes.is_empty() {
            form.push(("meastypes", query.meastypes_param()));
        }
        if let Some(category) = query.category {
            form.push(("category", category.to_string()));
        }
        if let Some(startdate) = query.startdate {
            form.push(("startdate", startdate.to_string()));
        }
        if let Some(enddate) = query.enddate {
            form.push(("enddate", enddate.to_string()));
        }
        if let Some(lastupdate) = query.lastupdate {
            form.push(("lastupdate", lastupdate.to_string()));
        }
        if let Some(offset) = query.offset {
            form.push(("offset", offset.to_string()));
        }
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .form(&form)
            .send()
            .await
            .map_err(WithingsError::Transport)?;
        read_envelope(response).await
    }

    fn join(&self, path: &str) -> Result<Url, WithingsError> {
        self.base_url
            .join(path)
            .map_err(|error| WithingsError::InvalidInput(error.to_string()))
    }
}

/// Parameters for `measure?action=getmeas`.
#[derive(Debug, Default, Clone)]
pub struct MeasureQuery {
    pub meastypes: Vec<u16>,
    pub category: Option<u8>,
    pub startdate: Option<i64>,
    pub enddate: Option<i64>,
    pub lastupdate: Option<i64>,
    pub offset: Option<u32>,
}

impl MeasureQuery {
    fn meastypes_param(&self) -> String {
        self.meastypes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Unwrap the `{"status": N, "body": {...}}` envelope every Withings service
/// answers with.
///
/// Withings returns HTTP 200 for application errors, so the HTTP status alone
/// cannot tell a working call from an expired token. Both layers are checked
/// here, and this is the only place either becomes a `WithingsError`.
async fn read_envelope(response: reqwest::Response) -> Result<Value, WithingsError> {
    let http_status = response.status();
    if !http_status.is_success() {
        return Err(map_http_status(http_status));
    }
    let bytes = response.bytes().await.map_err(WithingsError::Transport)?;
    let envelope: Value = serde_json::from_slice(&bytes).map_err(WithingsError::InvalidJson)?;
    let status = envelope
        .get("status")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            WithingsError::InvalidJson(serde_json::Error::io(std::io::Error::other(
                "response envelope has no numeric `status`",
            )))
        })?;
    if status != status::OK {
        return Err(map_api_status(status));
    }
    Ok(envelope.get("body").cloned().unwrap_or(Value::Null))
}

/// Map a Withings `status` to an error.
///
/// This is the only place a Withings status becomes an error variant, so the
/// wire code, the audit class and the metric label cannot disagree about one
/// call. `INVALID_TOKEN` is separated from `NOT_AUTHORIZED` because only the
/// first is recoverable by refreshing.
const fn map_api_status(status: i64) -> WithingsError {
    match status {
        status::INVALID_TOKEN => WithingsError::Unauthorized,
        status::NOT_AUTHORIZED | status::BAD_USERID | status::BAD_OAUTH_SIGNATURE => {
            WithingsError::InvalidGrant
        }
        status::TOO_MANY_REQUESTS => WithingsError::RateLimited,
        status::INVALID_PARAMS => WithingsError::Api {
            status: status::INVALID_PARAMS,
        },
        other => WithingsError::Api { status: other },
    }
}

const fn map_http_status(status: StatusCode) -> WithingsError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => WithingsError::Unauthorized,
        StatusCode::TOO_MANY_REQUESTS => WithingsError::RateLimited,
        other => WithingsError::Upstream {
            status: other.as_u16(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn credentials() -> ClientCredentials {
        ClientCredentials {
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
        }
    }

    fn token_body() -> Value {
        json!({
            "status": 0,
            "body": {
                "userid": "1234567",
                "access_token": "access-1",
                "refresh_token": "refresh-2",
                "scope": "user.metrics",
                "expires_in": 10800,
                "csrf_token": "csrf",
                "token_type": "Bearer"
            }
        })
    }

    #[tokio::test]
    async fn exchange_code_posts_the_documented_form_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("action=requesttoken"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("client_secret=client-secret"))
            .and(body_string_contains("code=auth-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = WithingsClient::new(&server.uri()).unwrap();
        let tokens = client
            .exchange_code(
                &credentials(),
                "auth-code",
                "https://example.test/oauth/callback",
            )
            .await
            .unwrap();
        assert_eq!(tokens.userid, "1234567");
        assert_eq!(tokens.refresh_token, "refresh-2");
        assert_eq!(tokens.expires_in, 10800);
        server.verify().await;
    }

    #[tokio::test]
    async fn refresh_returns_the_rotated_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=refresh-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = WithingsClient::new(&server.uri()).unwrap();
        let tokens = client.refresh(&credentials(), "refresh-1").await.unwrap();
        // Rotation is the whole point: the value that comes back is not the
        // one that was sent, and a caller keeping the old one is holding a
        // credential that dies as soon as this access token is used.
        assert_eq!(tokens.refresh_token, "refresh-2");
        assert_ne!(tokens.refresh_token, "refresh-1");
        server.verify().await;
    }

    #[tokio::test]
    async fn an_expired_token_arrives_as_http_200_and_becomes_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": 401, "error": "invalid_token"})),
            )
            .mount(&server)
            .await;

        let client = WithingsClient::new(&server.uri()).unwrap();
        let error = client
            .get_measures("stale", &MeasureQuery::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, WithingsError::Unauthorized),
            "HTTP 200 with status 401 must not read as success: {error:?}"
        );
    }

    #[tokio::test]
    async fn rate_limit_and_invalid_grant_are_distinct() {
        for (status, expected) in [
            (601, "withings_rate_limited"),
            (250, "withings_invalid_grant"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/measure"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": status})))
                .mount(&server)
                .await;
            let client = WithingsClient::new(&server.uri()).unwrap();
            let error = client
                .get_measures("token", &MeasureQuery::default())
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected, "status {status}");
        }
    }

    #[tokio::test]
    async fn get_measures_sends_the_bearer_and_the_meastypes_list() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .and(header("authorization", "Bearer access-1"))
            .and(body_string_contains("action=getmeas"))
            // `,` percent-encodes to %2C in a form body.
            .and(body_string_contains("meastypes=1%2C6%2C8%2C76"))
            .and(body_string_contains("startdate=100"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": 0, "body": {"measuregrps": []}})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = WithingsClient::new(&server.uri()).unwrap();
        let body = client
            .get_measures(
                "access-1",
                &MeasureQuery {
                    meastypes: vec![1, 6, 8, 76],
                    startdate: Some(100),
                    ..MeasureQuery::default()
                },
            )
            .await
            .unwrap();
        assert!(body.get("measuregrps").is_some());
        server.verify().await;
    }

    #[tokio::test]
    async fn an_envelope_without_a_status_is_an_error_not_an_empty_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"body": {}})))
            .mount(&server)
            .await;
        let client = WithingsClient::new(&server.uri()).unwrap();
        let error = client
            .get_measures("token", &MeasureQuery::default())
            .await
            .unwrap_err();
        assert!(matches!(error, WithingsError::InvalidJson(_)), "{error:?}");
    }

    #[test]
    fn empty_inputs_are_rejected_before_a_request_is_made() {
        let error = WithingsError::InvalidInput("code must not be empty".into());
        assert_eq!(error.code(), "withings_invalid_input");
    }

    #[test]
    fn authorize_url_carries_scope_state_and_redirect() {
        let url = authorize_url("id", "https://example.test/oauth/callback", "state-value");
        assert!(url.starts_with(AUTHORIZE_URL));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=user.metrics"));
        assert!(url.contains("state=state-value"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.test%2Foauth%2Fcallback"));
    }

    #[test]
    fn debug_output_redacts_both_tokens_and_the_client_secret() {
        let tokens = TokenResponse {
            userid: "1234567".to_owned(),
            access_token: "super-secret-access".to_owned(),
            refresh_token: "super-secret-refresh".to_owned(),
            scope: SCOPE.to_owned(),
            expires_in: 10800,
        };
        let rendered = format!("{tokens:?}");
        assert!(!rendered.contains("super-secret-access"), "{rendered}");
        assert!(!rendered.contains("super-secret-refresh"), "{rendered}");
        let rendered = format!("{:?}", credentials());
        assert!(!rendered.contains("client-secret"), "{rendered}");
    }

    #[test]
    fn base_url_must_be_absolute() {
        assert!(WithingsClient::new("wbsapi.withings.net").is_err());
        assert!(WithingsClient::new(DEFAULT_API_BASE_URL).is_ok());
    }
}
