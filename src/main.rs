//! withings-mcp: read-only streamable-HTTP MCP server for Withings body
//! metrics.
//!
//! The server holds one authorised Withings credential and exchanges it for
//! short-lived access tokens itself. Callers present a bearer the deployment
//! configured; it is not forwarded anywhere.

mod audit;
mod auth;
mod config;
mod exchange;
mod mcp;
mod measures;
mod metrics;
mod rate_limit;
mod session;
mod telemetry;
mod token;
mod withings_client;

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::auth::{AccessToken, ExpectedToken, bearer_auth};
use crate::config::{Config, Secret};
use crate::mcp::WithingsMcpService;
use crate::rate_limit::{InitializeLimiter, Limiter};
use crate::token::{FileStore, MemoryStore, TokenManager, TokenStore};
use crate::withings_client::{ClientCredentials, WithingsClient};

#[tokio::main]
async fn main() -> Result<()> {
    // `exchange` is a one-shot that trades an authorisation code for a
    // refresh token and prints it. It runs before tracing is configured and
    // before any listener is opened, because it is used from a terminal
    // before the deployment exists.
    if std::env::args().nth(1).as_deref() == Some("exchange") {
        return exchange::run().await;
    }

    init_tracing();
    metrics::init();
    let config = Config::from_env()?;
    let bind_addr = config.bind_addr;
    let metrics_bind_addr = config.metrics_bind_addr;
    let app = build_app(&config)?;

    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "withings-mcp listening (public)");

    let metrics_listener = TcpListener::bind(metrics_bind_addr).await?;
    info!(%metrics_bind_addr, "withings-mcp metrics listening (internal)");
    let metrics_app = Router::new().route("/metrics", get(metrics::metrics_handler));

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => {
            result?;
        }
        result = axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(shutdown_signal()) => {
            result?;
        }
        () = shutdown_signal() => {}
    }
    Ok(())
}

/// Pick where the rotated refresh token is written.
///
/// Withings rotates on every refresh, so an in-memory store means the
/// configured seed authenticates once per restart and then cannot. That is a
/// legitimate choice for a local run and a trap for a deployment, so it says
/// so at startup rather than three hours later.
fn build_token_store(path: Option<&std::path::Path>) -> Box<dyn TokenStore> {
    let Some(path) = path else {
        warn!(
            "no token state path configured; the rotated refresh token is kept in memory only \
             and will not survive a restart"
        );
        return Box::new(MemoryStore::new());
    };
    info!(path = %path.display(), "persisting rotated refresh tokens");
    Box::new(FileStore::new(path))
}

fn build_app(config: &Config) -> Result<Router> {
    let withings = WithingsClient::new(&config.api_base_url)?;
    let store = build_token_store(config.token_state_path.as_deref());
    let tokens = Arc::new(TokenManager::new(
        withings.clone(),
        ClientCredentials {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.expose().to_owned(),
        },
        store,
        config.seed_refresh_token.as_ref().map(Secret::expose),
    )?);
    // Say at startup whether there is a credential at all. Without this the
    // first symptom of an unseeded server is a tool call failing, which reads
    // as a Withings problem rather than a configuration one.
    match tokens.peek()? {
        Some(stored) if stored.access_token.is_empty() => {
            info!("holding a seed refresh token; the first tool call will refresh");
        }
        // No userid: it is account content, and this line is in every
        // release's startup log. `no_log_line_carries_a_userid` pins both.
        Some(_) => info!("holding stored Withings tokens"),
        None => warn!(
            "no Withings credential: set the seed refresh token, or complete the oauth callback"
        ),
    }
    let limiter = Arc::new(
        Limiter::new(config.rate_limit_reads_per_min)
            .ok_or_else(|| anyhow::anyhow!("rate-limit quota must be greater than zero"))?,
    );
    Ok(build_router(config, withings, tokens, &limiter))
}

fn build_router(
    config: &Config,
    withings: WithingsClient,
    tokens: Arc<TokenManager>,
    limiter: &Arc<Limiter>,
) -> Router {
    let initialize_limiter = Arc::new(InitializeLimiter::new(
        config.initialize_replenish,
        config.initialize_burst,
    ));
    let expected = Arc::new(ExpectedToken::new(config.auth_token.expose()));

    let service_tokens = Arc::clone(&tokens);
    let service_withings = withings.clone();
    let service_limiter = Arc::clone(limiter);
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(WithingsMcpService::new(
                service_withings.clone(),
                Arc::clone(&service_tokens),
                Arc::clone(&service_limiter),
            ))
        },
        Arc::new(session::CappedSessionManager::new()),
        StreamableHttpServerConfig::default().with_allowed_hosts(config.allowed_hosts.clone()),
    );

    // Bearer auth must stay nested under /mcp. In axum 0.7 a `.layer()` on a
    // merged router becomes a catch-all, so unknown paths (including OAuth
    // well-known discovery) would 401 and a client would treat this as an
    // OAuth resource.
    let mcp_routes = Router::new()
        .fallback_service(mcp_service)
        .layer(middleware::from_fn_with_state(
            initialize_limiter,
            initialize_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(expected, bearer_auth));

    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-authorization-server",
            any(oauth_probe_not_found),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            any(oauth_probe_not_found),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            any(oauth_probe_not_found),
        )
        .route(
            "/.well-known/openid-configuration",
            any(oauth_probe_not_found),
        )
        .route("/oauth-protected-resource/mcp", any(oauth_probe_not_found))
        .route("/openid-configuration", any(oauth_probe_not_found))
        .route(
            "/oauth/callback",
            get(oauth_callback).with_state(Arc::new(CallbackState {
                withings,
                tokens,
                credentials: ClientCredentials {
                    client_id: config.client_id.clone(),
                    client_secret: config.client_secret.expose().to_owned(),
                },
                redirect_uri: config.redirect_uri.clone(),
                oauth_state: config.oauth_state.clone(),
            })),
        )
        .nest("/mcp", mcp_routes)
        .layer(TraceLayer::new_for_http())
}

struct CallbackState {
    withings: WithingsClient,
    tokens: Arc<TokenManager>,
    credentials: ClientCredentials,
    redirect_uri: Option<String>,
    oauth_state: Option<Secret>,
}

#[derive(Debug, Deserialize)]
struct CallbackParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

/// Complete the browser leg of the authorisation-code flow.
///
/// This endpoint cannot carry the MCP bearer — the caller is a browser
/// following a Withings redirect — and it *replaces the server's credential*,
/// which is the most consequential thing here. So it is off unless the
/// deployment names a `state` value, and the value must match in constant
/// time. Without that, anyone who reaches the origin can point this server at
/// their own Withings account.
async fn oauth_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let Some(expected_state) = &state.oauth_state else {
        return (
            StatusCode::NOT_FOUND,
            "oauth callback is not enabled on this deployment\n",
        )
            .into_response();
    };
    let presented = params.state.unwrap_or_default();
    if presented
        .as_bytes()
        .ct_eq(expected_state.expose().as_bytes())
        .unwrap_u8()
        != 1
    {
        warn!("oauth callback rejected: state mismatch");
        return (StatusCode::FORBIDDEN, "state mismatch\n").into_response();
    }
    let Some(redirect_uri) = &state.redirect_uri else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "no redirect uri configured\n",
        )
            .into_response();
    };
    let Some(code) = params.code.filter(|code| !code.trim().is_empty()) else {
        return (StatusCode::BAD_REQUEST, "no authorisation code\n").into_response();
    };
    match state
        .withings
        .exchange_code(&state.credentials, &code, redirect_uri)
        .await
    {
        Err(error) => {
            warn!(code = error.code(), "oauth callback exchange failed");
            (
                StatusCode::BAD_GATEWAY,
                format!("exchange failed: {}\n", error.code()),
            )
                .into_response()
        }
        Ok(response) => {
            if let Err(error) = state.tokens.adopt(&response).await {
                warn!(%error, "oauth callback could not persist the new tokens");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "authorised, but the tokens could not be stored\n",
                )
                    .into_response()
            } else {
                info!("adopted a new Withings authorisation from the oauth callback");
                (StatusCode::OK, "authorised. you can close this tab.\n").into_response()
            }
        }
    }
}

async fn oauth_probe_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn initialize_rate_limit(
    State(limiter): State<Arc<InitializeLimiter>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    if !is_fresh_mcp_session_request(&request) {
        return next.run(request).await;
    }
    let Some(token) = request.extensions().get::<AccessToken>() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing token extension\n",
        )
            .into_response();
    };
    let bearer_hash = audit::token_hash(&token.0);
    if limiter.check(&bearer_hash).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many MCP initialize requests; try again later\n",
        )
            .into_response();
    }
    next.run(request).await
}

fn is_fresh_mcp_session_request(request: &Request<Body>) -> bool {
    request.method() == Method::POST && request.headers().get("mcp-session-id").is_none()
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("withings_mcp=info,tower_http=info,axum=info,info"));
    let otel_layer = telemetry::try_build_otel_layer();
    let json_layer = std::env::var("WITHINGS_MCP_LOG_FORMAT").as_deref() == Ok("json");
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer);
    if json_layer {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }
}

#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler at startup");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler at startup");
    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv() => info!("received SIGINT"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const INBOUND: &str = "inbound-secret";
    const ORIGIN: &str = "withings-mcp.example";

    fn test_config(api_base_url: &str) -> Config {
        Config::new(
            api_base_url,
            SocketAddr::from(([0, 0, 0, 0], 3000)),
            Secret::new(INBOUND),
            "client-id",
            Secret::new("client-secret"),
        )
        .unwrap()
    }

    fn token_body(access: &str, refresh: &str) -> serde_json::Value {
        json!({
            "status": 0,
            "body": {
                "userid": "1234567",
                "access_token": access,
                "refresh_token": refresh,
                "scope": "user.metrics",
                "expires_in": 10800,
                "token_type": "Bearer"
            }
        })
    }

    /// A measure body in the shape Withings' documentation describes. Invented
    /// numbers: nothing in this repository is anyone's real measurement.
    fn measure_body() -> serde_json::Value {
        json!({
            "status": 0,
            "body": {
                "updatetime": 1_724_900_000_i64,
                "timezone": "Asia/Singapore",
                "measuregrps": [{
                    "grpid": 2,
                    "attrib": 0,
                    "date": 1_724_800_000_i64,
                    "category": 1,
                    "measures": [
                        {"value": 70_500, "type": 1, "unit": -3},
                        {"value": 1_820, "type": 6, "unit": -2}
                    ]
                }]
            }
        })
    }

    fn build(config: &Config) -> Router {
        build_with_store(config, Box::new(MemoryStore::new()), Some("seed"))
    }

    fn build_with_store(config: &Config, store: Box<dyn TokenStore>, seed: Option<&str>) -> Router {
        let withings = WithingsClient::new(&config.api_base_url).unwrap();
        let tokens = Arc::new(
            TokenManager::new(
                withings.clone(),
                ClientCredentials {
                    client_id: config.client_id.clone(),
                    client_secret: config.client_secret.expose().to_owned(),
                },
                store,
                seed,
            )
            .unwrap(),
        );
        let limiter = Arc::new(Limiter::new(100_000).unwrap());
        build_router(config, withings, tokens, &limiter)
    }

    fn router(api_base_url: &str) -> Router {
        build(&test_config(api_base_url))
    }

    /// A router whose `allowed_hosts` came from configuration rather than the
    /// loopback default, the way the environment variable supplies it in a
    /// deployment.
    fn router_with_hosts(api_base_url: &str, hosts: &[&str]) -> Router {
        let mut config = test_config(api_base_url);
        config.allowed_hosts = hosts.iter().map(|host| (*host).to_owned()).collect();
        build(&config)
    }

    async fn initialize_with_host(app: Router, host: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, host)
                .header(header::AUTHORIZATION, format!("Bearer {INBOUND}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    /// The published default must not carry any deployment's public origin.
    /// rmcp answers 403 to a `Host` outside `allowed_hosts`, so on the default
    /// config a public origin is just another rejected host.
    #[tokio::test]
    async fn default_allowed_hosts_are_loopback_only() {
        for (host, rejected) in [
            ("localhost", false),
            ("127.0.0.1", false),
            (ORIGIN, true),
            ("evil.example", true),
        ] {
            let status = initialize_with_host(router("https://example.test"), host).await;
            assert_eq!(
                status == StatusCode::FORBIDDEN,
                rejected,
                "{host} returned {status}"
            );
        }
    }

    #[tokio::test]
    async fn a_configured_public_host_is_accepted() {
        let status =
            initialize_with_host(router_with_hosts("https://example.test", &[ORIGIN]), ORIGIN)
                .await;
        assert_ne!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn health_is_public_without_a_bearer() {
        let response = router("https://example.test")
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn mcp_without_a_bearer_returns_a_bare_401() {
        let response = router("https://example.test")
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert!(!response.headers().contains_key("resource_metadata"));
    }

    /// The difference from a passthrough server: a well-formed bearer that is
    /// not *the* bearer is rejected. Without this, anyone reaching the origin
    /// reads a real person's body metrics.
    #[tokio::test]
    async fn a_wrong_bearer_is_rejected_rather_than_forwarded() {
        for authorization in [
            "Bearer wrong-secret",
            "Bearer inbound-secre",
            "Bearer inbound-secrets",
            "Bearer ",
            "Basic aW5ib3VuZC1zZWNyZXQ=",
        ] {
            let response = router("https://example.test")
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header(header::AUTHORIZATION, authorization)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{authorization} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn oauth_discovery_and_unknown_paths_are_plain_404() {
        for uri in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/openid-configuration",
            "/oauth-protected-resource/mcp",
            "/openid-configuration",
            "/no-such-path",
        ] {
            let response = router("https://example.test")
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert!(
                response.headers().get(header::WWW_AUTHENTICATE).is_none(),
                "{uri}"
            );
        }
    }

    /// Drive a tool call and return the JSON-RPC envelope a client receives.
    async fn tool_call_envelope(app: Router, tool: &str, arguments: &str) -> serde_json::Value {
        let initialize = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, ORIGIN)
                    .header(header::AUTHORIZATION, format!("Bearer {INBOUND}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initialize.status(), StatusCode::OK);
        let session_id = initialize.headers().get("mcp-session-id").unwrap().clone();
        let call = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, ORIGIN)
                    .header(header::AUTHORIZATION, format!("Bearer {INBOUND}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-session-id", session_id)
                    .header("mcp-protocol-version", "2025-06-18")
                    .body(Body::from(format!(
                        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(call.into_body(), 256 * 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        let line = text.lines().rfind(|line| line.starts_with("data: {"));
        assert!(line.is_some(), "no JSON-RPC frame in response: {text}");
        serde_json::from_str(line.unwrap().trim_start_matches("data: ")).unwrap()
    }

    /// The first tool call refreshes, because a seeded store carries an
    /// already-expired access token, and only then reads.
    ///
    /// Both mocks are `expect(1)`, so this fails if the read skips the
    /// refresh or if the refresh runs twice.
    #[tokio::test]
    async fn the_first_read_refreshes_first_and_then_calls_measure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=seed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("acc-1", "rot-1")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .and(wiremock::matchers::header("authorization", "Bearer acc-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(measure_body()))
            .expect(1)
            .mount(&server)
            .await;

        let app = router_with_hosts(&server.uri(), &[ORIGIN]);
        let envelope = tool_call_envelope(app, "latest_measurements", "{}").await;
        let content = &envelope["result"]["structuredContent"];
        let measurements = content["measurements"].as_array().unwrap();
        assert_eq!(measurements.len(), 2, "{content}");
        let weight = measurements.iter().find(|m| m["name"] == "weight").unwrap();
        // 70500 with unit -3. An unscaled 70500 would be the confidently
        // wrong number this pins.
        assert!((weight["value"].as_f64().unwrap() - 70.5).abs() < 1e-9);
        assert_eq!(weight["unit"], "kg");
        // Two of the four types had no reading, and are named rather than
        // reported as zero.
        let missing = content["no_reading_in_window"].as_array().unwrap();
        assert_eq!(missing.len(), 2, "{content}");
        server.verify().await;
    }

    /// A Withings rate limit and an empty read must not be the same silence.
    ///
    /// One predicate on `data.class` catches both limits; an empty series is a
    /// successful result and matches nothing.
    #[tokio::test]
    async fn a_rate_limit_never_arrives_as_an_empty_read() {
        let throttling = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("acc-1", "rot-1")))
            .mount(&throttling)
            .await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            // Withings answers HTTP 200 with `status: 601`.
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": 601})))
            .mount(&throttling)
            .await;
        let envelope = tool_call_envelope(
            router_with_hosts(&throttling.uri(), &[ORIGIN]),
            "list_measurements",
            "{}",
        )
        .await;
        assert!(envelope.get("result").is_none(), "expected an error");
        assert_eq!(envelope["error"]["data"]["class"], "rate_limited");
        let message = envelope["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("minute"),
            "the retry interval is gone from the human message: {message:?}"
        );

        let empty = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("acc-1", "rot-1")))
            .mount(&empty)
            .await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": 0, "body": {"measuregrps": []}})),
            )
            .mount(&empty)
            .await;
        let envelope = tool_call_envelope(
            router_with_hosts(&empty.uri(), &[ORIGIN]),
            "list_measurements",
            "{}",
        )
        .await;
        let content = &envelope["result"]["structuredContent"];
        assert_eq!(content["returned"], 0, "{envelope}");
        assert!(envelope["error"].is_null());
    }

    /// A refresh token Withings has retired reaches the caller as a statement
    /// that re-authorisation is needed, not as an internal error.
    #[tokio::test]
    async fn a_dead_refresh_token_says_re_authorisation_is_required() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": 250})))
            .mount(&server)
            .await;
        let envelope =
            tool_call_envelope(router_with_hosts(&server.uri(), &[ORIGIN]), "whoami", "{}").await;
        assert_eq!(envelope["error"]["data"]["code"], "withings_invalid_grant");
        assert!(
            envelope["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("re-authorisation"),
            "{envelope}"
        );
    }

    /// `measurement_types` reads nothing from Withings, so it must answer
    /// even where no credential works at all.
    #[tokio::test]
    async fn measurement_types_needs_no_withings_call() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let envelope = tool_call_envelope(
            router_with_hosts(&server.uri(), &[ORIGIN]),
            "measurement_types",
            "{}",
        )
        .await;
        let types = envelope["result"]["structuredContent"]["types"]
            .as_array()
            .unwrap();
        assert_eq!(types.len(), 4, "{envelope}");
        assert_eq!(types[0]["name"], "weight");
        assert_eq!(types[0]["meastype"], 1);
        server.verify().await;
    }

    /// Every tool is annotated read-only, and there is no tool that writes.
    ///
    /// `bin/tool-scope.sh` generates an agent's deny list from these
    /// annotations, so a hint that says `false` here silently widens an agent
    /// rather than mislabelling a tool.
    #[tokio::test]
    async fn every_tool_is_annotated_read_only_and_none_writes() {
        let app = router_with_hosts("https://example.test", &[ORIGIN]);
        let initialize = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, ORIGIN)
                    .header(header::AUTHORIZATION, format!("Bearer {INBOUND}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_id = initialize.headers().get("mcp-session-id").unwrap().clone();
        let listed = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, ORIGIN)
                    .header(header::AUTHORIZATION, format!("Bearer {INBOUND}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-session-id", session_id)
                    .header("mcp-protocol-version", "2025-06-18")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(listed.into_body(), 256 * 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        let line = text
            .lines()
            .rfind(|line| line.starts_with("data: {"))
            .unwrap();
        let envelope: serde_json::Value =
            serde_json::from_str(line.trim_start_matches("data: ")).unwrap();
        let tools = envelope["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4, "{envelope}");
        for tool in tools {
            assert_eq!(
                tool["annotations"]["readOnlyHint"],
                json!(true),
                "{} is not annotated read-only",
                tool["name"]
            );
        }
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(
            !names.iter().any(|name| name.starts_with("create_")
                || name.starts_with("update_")
                || name.starts_with("delete_")
                || name.starts_with("set_")),
            "a write-shaped tool appeared: {names:?}"
        );
    }

    #[tokio::test]
    async fn the_oauth_callback_is_off_unless_a_state_value_is_configured() {
        let response = router("https://example.test")
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?code=abc&state=anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// With the callback on, a wrong `state` must not reach the exchange. It
    /// replaces the server's credential, so an unguarded callback lets anyone
    /// reaching the origin point this server at their own account.
    #[tokio::test]
    async fn the_oauth_callback_rejects_a_wrong_state_before_exchanging() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("acc", "rot")))
            .expect(0)
            .mount(&server)
            .await;
        let mut config = test_config(&server.uri());
        config.oauth_state = Some(Secret::new("expected-state"));
        config.redirect_uri = Some("https://example.test/oauth/callback".to_owned());
        let app = build(&config);
        for query in [
            "?code=abc&state=wrong",
            "?code=abc",
            "?code=abc&state=expected-stat",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/oauth/callback{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn a_matching_state_exchanges_the_code_and_adopts_the_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=fresh-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("acc-9", "rot-9")))
            .expect(1)
            .mount(&server)
            .await;
        let mut config = test_config(&server.uri());
        config.oauth_state = Some(Secret::new("expected-state"));
        config.redirect_uri = Some("https://example.test/oauth/callback".to_owned());

        let withings = WithingsClient::new(&config.api_base_url).unwrap();
        let tokens = Arc::new(
            TokenManager::new(
                withings.clone(),
                ClientCredentials {
                    client_id: config.client_id.clone(),
                    client_secret: config.client_secret.expose().to_owned(),
                },
                Box::new(MemoryStore::new()),
                None,
            )
            .unwrap(),
        );
        let app = build_router(
            &config,
            withings,
            Arc::clone(&tokens),
            &Arc::new(Limiter::new(100).unwrap()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?code=fresh-code&state=expected-state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let stored = tokens.peek().unwrap().unwrap();
        assert_eq!(stored.refresh_token, "rot-9");
        assert_eq!(stored.userid, "1234567");
        server.verify().await;
    }

    /// Captures every event on this thread as JSON lines.
    ///
    /// `#[tokio::test]` runs on one thread, so a thread-local default sees the
    /// events rmcp's spawned session tasks emit too.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            let writer = self.clone();
            tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .json()
                    .with_max_level(tracing::Level::DEBUG)
                    .with_writer(move || writer.clone())
                    .finish(),
            )
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        /// The fields of every `Withings call failed` event.
        fn failures(&self) -> Vec<serde_json::Value> {
            self.text()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|event| event["fields"]["message"] == "Withings call failed")
                .map(|event| event["fields"].clone())
                .collect()
        }
    }

    /// `test_config` with `ORIGIN` allowed, as `tool_call_envelope` sends it.
    fn origin_config(api_base_url: &str) -> Config {
        let mut config = test_config(api_base_url);
        config.allowed_hosts = vec![ORIGIN.to_owned()];
        config
    }

    /// Every credential and private value the failure tests hand the server.
    /// None may reach a client or a log line. Invented values throughout.
    const PRIVATE: &[&str] = &[
        INBOUND,
        "client-secret",
        "seed-secret-value",
        "acc-secret-value",
        "rot-secret-value",
        "invented-private-detail",
        "1234567",
    ];

    fn assert_nothing_private(what: &str, text: &str) {
        for private in PRIVATE {
            assert!(
                !text.contains(private),
                "{what} carries {private:?}: {text}"
            );
        }
    }

    /// A refresh Withings refuses with an unmapped status names its stage and
    /// its number, on the wire and in one log event, and carries nothing
    /// private. `whoami` never calls `measure`, so it failing the same way as
    /// a read is what isolates the refresh. The seed is still what the store
    /// holds afterwards: nothing was persisted.
    ///
    /// `503` is Withings' documented "invalid params" status. Which refresh
    /// input it objects to is not something this server can see.
    #[tokio::test]
    async fn a_refresh_failure_names_its_stage_and_status_and_nothing_private() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"status": 503, "error": "invented-private-detail 1234567"}),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .respond_with(ResponseTemplate::new(200).set_body_json(measure_body()))
            .expect(0)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");

        let captured = Captured::default();
        let _guard = captured.install();
        for tool in ["whoami", "latest_measurements"] {
            let app = build_with_store(
                &origin_config(&server.uri()),
                Box::new(FileStore::new(&state)),
                Some("seed-secret-value"),
            );
            let envelope = tool_call_envelope(app, tool, "{}").await;
            let data = &envelope["error"]["data"];
            assert_eq!(data["code"], "withings_api_error", "{tool}: {envelope}");
            assert_eq!(data["class"], "internal", "{tool}: {envelope}");
            assert_eq!(data["stage"], "refresh", "{tool}: {envelope}");
            assert_eq!(data["withings_status"], 503, "{tool}: {envelope}");
            assert_nothing_private(tool, &envelope.to_string());
        }
        let failures = captured.failures();
        assert_eq!(failures.len(), 2, "{}", captured.text());
        for fields in &failures {
            assert_eq!(fields["stage"], "refresh", "{fields}");
            assert_eq!(fields["withings_status"], 503, "{fields}");
            assert_eq!(fields["code"], "withings_api_error", "{fields}");
        }
        assert_nothing_private("the log", &captured.text());

        let stored = FileStore::new(&state).load().unwrap().unwrap();
        assert_eq!(stored.refresh_token, "seed-secret-value");
        assert_eq!(stored.expires_at, 0);
        server.verify().await;
    }

    /// The same status from `measure`, after a refresh in Withings'
    /// documented shape succeeded, names the other stage.
    #[tokio::test]
    async fn a_measure_failure_names_its_stage_and_status_and_nothing_private() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": 0,
                "body": {
                    "access_token": "acc-secret-value",
                    "refresh_token": "rot-secret-value",
                    "expires_in": 10800
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/measure"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": 503, "error": "invented-private-detail"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let captured = Captured::default();
        let _guard = captured.install();
        let app = build_with_store(
            &origin_config(&server.uri()),
            Box::new(MemoryStore::new()),
            Some("seed-secret-value"),
        );
        let envelope = tool_call_envelope(app, "list_measurements", "{}").await;
        let data = &envelope["error"]["data"];
        assert_eq!(data["stage"], "measure", "{envelope}");
        assert_eq!(data["withings_status"], 503, "{envelope}");
        assert_nothing_private("the envelope", &envelope.to_string());
        let failures = captured.failures();
        assert_eq!(failures.len(), 1, "{}", captured.text());
        assert_eq!(failures[0]["stage"], "measure");
        assert_eq!(failures[0]["withings_status"], 503);
        assert_nothing_private("the log", &captured.text());
        server.verify().await;
    }

    /// `whoami` keeps reporting the account after a refresh in Withings'
    /// documented shape, which carries no `userid` or `scope`: both come
    /// forward from the stored record, and `userid` stays a string.
    #[tokio::test]
    async fn whoami_keeps_the_account_across_a_refresh_that_omits_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("refresh_token=rot-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": 0,
                "body": {"access_token": "acc-1", "refresh_token": "rot-1", "expires_in": 10800}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let store = MemoryStore::new();
        store
            .save(&crate::token::StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "acc-0".to_owned(),
                refresh_token: "rot-0".to_owned(),
                scope: "user.metrics".to_owned(),
                expires_at: 0,
            })
            .unwrap();
        let app = build_with_store(&origin_config(&server.uri()), Box::new(store), None);
        let envelope = tool_call_envelope(app, "whoami", "{}").await;
        let content = &envelope["result"]["structuredContent"];
        assert_eq!(content["userid"], "1234567", "{envelope}");
        assert_eq!(content["scope"], "user.metrics", "{envelope}");
        server.verify().await;
    }

    /// A consent whose response does not name the account is refused and the
    /// stored credential is left alone. Only a refresh inherits identity.
    #[tokio::test]
    async fn the_oauth_callback_refuses_an_authorisation_without_a_userid() {
        let server = MockServer::start().await;
        let mut body = token_body("acc-9", "rot-9");
        body["body"].as_object_mut().unwrap().remove("userid");
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let mut config = test_config(&server.uri());
        config.oauth_state = Some(Secret::new("expected-state"));
        config.redirect_uri = Some("https://example.test/oauth/callback".to_owned());

        let store = MemoryStore::new();
        let existing = crate::token::StoredTokens {
            userid: "7654321".to_owned(),
            access_token: "acc-0".to_owned(),
            refresh_token: "rot-0".to_owned(),
            scope: "user.metrics".to_owned(),
            expires_at: 0,
        };
        store.save(&existing).unwrap();
        let withings = WithingsClient::new(&config.api_base_url).unwrap();
        let tokens = Arc::new(
            TokenManager::new(
                withings.clone(),
                ClientCredentials {
                    client_id: config.client_id.clone(),
                    client_secret: config.client_secret.expose().to_owned(),
                },
                Box::new(store),
                None,
            )
            .unwrap(),
        );
        let app = build_router(
            &config,
            withings,
            Arc::clone(&tokens),
            &Arc::new(Limiter::new(100).unwrap()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/callback?code=fresh-code&state=expected-state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        let text = String::from_utf8_lossy(&to_bytes(response.into_body(), 4096).await.unwrap())
            .into_owned();
        assert!(!text.contains("rot-9"), "{text}");
        assert_eq!(tokens.peek().unwrap().unwrap(), existing);
        server.verify().await;
    }

    /// Startup reports that a credential is held, and not whose. A stored
    /// record's userid is account content; this line runs on every release
    /// start, so it would put the id in every deployment's log. Invented id.
    #[tokio::test]
    async fn startup_with_stored_tokens_does_not_log_the_userid() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        FileStore::new(&state)
            .save(&crate::token::StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "acc-secret-value".to_owned(),
                refresh_token: "rot-secret-value".to_owned(),
                scope: "user.metrics".to_owned(),
                expires_at: 0,
            })
            .unwrap();
        let mut config = test_config("https://example.test");
        config.token_state_path = Some(state);

        let captured = Captured::default();
        let _guard = captured.install();
        let _app = build_app(&config).unwrap();
        let text = captured.text();
        assert!(text.contains("holding stored Withings tokens"), "{text}");
        assert_nothing_private("the startup log", &text);
    }

    /// A static check over every source file: no tracing field is named
    /// `userid` and no `%`/`?`-captured value is a userid. The runtime tests
    /// cover the paths they drive; this covers a log line added on a path no
    /// test drives. `exchange.rs` prints the userid to the operator's own
    /// terminal on purpose, with `eprintln!`, which neither pattern matches.
    #[test]
    fn no_log_line_carries_a_userid() {
        let field = concat!("user", "id");
        let sources = [
            ("audit.rs", include_str!("audit.rs")),
            ("auth.rs", include_str!("auth.rs")),
            ("config.rs", include_str!("config.rs")),
            ("exchange.rs", include_str!("exchange.rs")),
            ("main.rs", include_str!("main.rs")),
            ("mcp.rs", include_str!("mcp.rs")),
            ("measures.rs", include_str!("measures.rs")),
            ("metrics.rs", include_str!("metrics.rs")),
            ("rate_limit.rs", include_str!("rate_limit.rs")),
            ("session.rs", include_str!("session.rs")),
            ("telemetry.rs", include_str!("telemetry.rs")),
            ("token.rs", include_str!("token.rs")),
            ("withings_client.rs", include_str!("withings_client.rs")),
        ];
        for (file, source) in sources {
            for (number, line) in source.lines().enumerate() {
                let compact: String = line.split_whitespace().collect();
                let named_field = compact.contains(&format!("{field}=%"))
                    || compact.contains(&format!("{field}=?"))
                    || compact.contains(&format!("{field}={field}"));
                let captured = line
                    .split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')'))
                    .any(|token| token.starts_with(['%', '?']) && token.contains(field));
                assert!(
                    !named_field && !captured,
                    "{file}:{} logs a {field}: {line}",
                    number + 1
                );
            }
        }
    }
}
