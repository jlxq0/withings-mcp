//! Process-level configuration.
//!
//! Unlike a server that forwards the caller's own API key, this one holds a
//! credential of its own, so the Withings client id, client secret and seed
//! refresh token are process configuration and are read here. None of them
//! has a default and none of them appears in this file.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::withings_client::DEFAULT_API_BASE_URL;

const ENV_API_BASE_URL: &str = "WITHINGS_MCP_API_BASE_URL";
const ENV_BIND_ADDR: &str = "WITHINGS_MCP_BIND_ADDR";
const ENV_METRICS_BIND_ADDR: &str = "WITHINGS_MCP_METRICS_BIND_ADDR";
const ENV_POD_IP: &str = "POD_IP";
const ENV_RATE_LIMIT_READS: &str = "WITHINGS_MCP_RATE_LIMIT_READS_PER_MIN";
const ENV_INITIALIZE_BURST: &str = "WITHINGS_MCP_RATE_LIMIT_INITIALIZE_BURST";
const ENV_INITIALIZE_REPLENISH_SECS: &str = "WITHINGS_MCP_RATE_LIMIT_INITIALIZE_REPLENISH_SECS";
const ENV_ALLOWED_HOSTS: &str = "WITHINGS_MCP_ALLOWED_HOSTS";
const ENV_AUTH_TOKEN: &str = "WITHINGS_MCP_AUTH_TOKEN";
const ENV_CLIENT_ID: &str = "WITHINGS_MCP_CLIENT_ID";
const ENV_CLIENT_SECRET: &str = "WITHINGS_MCP_CLIENT_SECRET";
const ENV_REFRESH_TOKEN: &str = "WITHINGS_MCP_REFRESH_TOKEN";
const ENV_TOKEN_STATE_PATH: &str = "WITHINGS_MCP_TOKEN_STATE_PATH";
const ENV_REDIRECT_URI: &str = "WITHINGS_MCP_REDIRECT_URI";
const ENV_OAUTH_STATE: &str = "WITHINGS_MCP_OAUTH_STATE";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
// A connector opens a fresh session on every reconnect, and a reconnect loop
// bursts several in seconds. The real ceilings are elsewhere: MAX_SESSIONS
// caps concurrency globally and the read quota caps actual work, so this
// bucket only has to stop a runaway client.
const DEFAULT_INITIALIZE_BURST: u32 = 32;
const DEFAULT_INITIALIZE_REPLENISH_SECS: u32 = 60;
// Loopback only. The public origin a deployment answers on is deployment
// configuration and belongs in `WITHINGS_MCP_ALLOWED_HOSTS`, not in a
// published source file — this repository is public. A deployment that does
// not set the variable serves loopback and rejects everything else with 403,
// which is the safe direction to fail.
const DEFAULT_ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// A secret read from the environment. Debug output is always redacted, so a
/// `{config:?}` in a log line cannot print one.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Withings API base URL without a trailing slash.
    pub api_base_url: String,
    pub bind_addr: SocketAddr,
    pub metrics_bind_addr: SocketAddr,
    pub rate_limit_reads_per_min: u32,
    /// Fresh `initialize` requests one bearer may burst before throttling.
    pub initialize_burst: u32,
    /// How long it takes to replenish a single `initialize` token.
    pub initialize_replenish: Duration,
    pub allowed_hosts: Vec<String>,
    /// The bearer a caller must present. There is no default: a server with
    /// nothing configured here refuses to start rather than serving open.
    pub auth_token: Secret,
    pub client_id: String,
    pub client_secret: Secret,
    /// Seed refresh token. Used only when the token store holds nothing,
    /// because Withings rotates and the stored value is newer by
    /// construction.
    pub seed_refresh_token: Option<Secret>,
    /// Where the rotated refresh token is written. `None` keeps it in memory,
    /// which loses it on exit.
    pub token_state_path: Option<PathBuf>,
    /// The redirect URI registered with Withings. Required by both the code
    /// exchange and the authorisation URL, and it must match byte for byte.
    pub redirect_uri: Option<String>,
    /// Value the `state` query parameter must equal for `/oauth/callback` to
    /// act. Absent disables the callback entirely.
    pub oauth_state: Option<Secret>,
}

impl Config {
    /// Build a configuration with every optional value at its default.
    ///
    /// This is the shape `from_env` starts from, so the defaults asserted
    /// against it here are the ones a deployment that sets nothing gets.
    pub fn new(
        api_base_url: impl Into<String>,
        bind_addr: SocketAddr,
        auth_token: Secret,
        client_id: impl Into<String>,
        client_secret: Secret,
    ) -> Result<Self> {
        let api_base_url = strip_trailing_slash(api_base_url.into());
        validate_url(&api_base_url, ENV_API_BASE_URL)?;
        Ok(Self {
            api_base_url,
            bind_addr,
            metrics_bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            rate_limit_reads_per_min: DEFAULT_RATE_LIMIT_READS,
            initialize_burst: DEFAULT_INITIALIZE_BURST,
            initialize_replenish: Duration::from_secs(u64::from(DEFAULT_INITIALIZE_REPLENISH_SECS)),
            allowed_hosts: default_allowed_hosts(),
            auth_token,
            client_id: client_id.into(),
            client_secret,
            seed_refresh_token: None,
            token_state_path: None,
            redirect_uri: None,
            oauth_state: None,
        })
    }

    pub fn from_env() -> Result<Self> {
        let api_base_url =
            std::env::var(ENV_API_BASE_URL).unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_owned());
        let bind_addr_string =
            std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".to_owned());
        let bind_addr = SocketAddr::from_str(&bind_addr_string)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_string}"))?;

        let mut config = Self::new(
            api_base_url,
            bind_addr,
            Secret::new(required(ENV_AUTH_TOKEN)?),
            required(ENV_CLIENT_ID)?,
            Secret::new(required(ENV_CLIENT_SECRET)?),
        )?;
        config.metrics_bind_addr = resolve_metrics_bind_addr(
            std::env::var(ENV_METRICS_BIND_ADDR).ok().as_deref(),
            std::env::var(ENV_POD_IP).ok().as_deref(),
        )?;
        config.rate_limit_reads_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_READS, DEFAULT_RATE_LIMIT_READS)?;
        config.initialize_burst = parse_rate_limit(ENV_INITIALIZE_BURST, DEFAULT_INITIALIZE_BURST)?;
        config.initialize_replenish = Duration::from_secs(u64::from(parse_rate_limit(
            ENV_INITIALIZE_REPLENISH_SECS,
            DEFAULT_INITIALIZE_REPLENISH_SECS,
        )?));
        config.allowed_hosts = parse_allowed_hosts(std::env::var(ENV_ALLOWED_HOSTS).ok())?;
        config.seed_refresh_token = optional(ENV_REFRESH_TOKEN).map(Secret::new);
        config.token_state_path = optional(ENV_TOKEN_STATE_PATH).map(PathBuf::from);
        config.redirect_uri = optional(ENV_REDIRECT_URI);
        config.oauth_state = optional(ENV_OAUTH_STATE).map(Secret::new);
        if let Some(redirect_uri) = &config.redirect_uri {
            validate_url(redirect_uri, ENV_REDIRECT_URI)?;
        }
        Ok(config)
    }
}

/// A variable with no default. Empty and unset are the same thing, so a
/// blanked-out secret cannot start a server that serves without one.
fn required(key: &str) -> Result<String> {
    let value = std::env::var(key).unwrap_or_default();
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{key} must be set and non-empty");
    Ok(value.to_owned())
}

fn optional(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn resolve_metrics_bind_addr(
    explicit_addr: Option<&str>,
    pod_ip: Option<&str>,
) -> Result<SocketAddr> {
    let address = explicit_addr.map_or_else(
        || pod_ip.map_or_else(|| "127.0.0.1:9090".to_owned(), |ip| format!("{ip}:9090")),
        str::to_owned,
    );
    SocketAddr::from_str(&address)
        .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {address}"))
}

fn validate_url(url: &str, key: &str) -> Result<()> {
    anyhow::ensure!(
        is_absolute_http_uri(url),
        "{key} must be an absolute http(s) URL, got: {url}"
    );
    Ok(())
}

#[must_use]
pub fn is_absolute_http_uri(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && url.len() > "https://".len()
        && !url.chars().any(char::is_whitespace)
}

fn parse_rate_limit(key: &str, default: u32) -> Result<u32> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => {
            let value: u32 = raw
                .trim()
                .parse()
                .with_context(|| format!("{key} must be a positive integer, got: {raw}"))?;
            anyhow::ensure!(value > 0, "{key} must be > 0");
            Ok(value)
        }
    }
}

fn parse_allowed_hosts(raw: Option<String>) -> Result<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(default_allowed_hosts());
    };
    let hosts: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect();
    anyhow::ensure!(
        !hosts.is_empty(),
        "{ENV_ALLOWED_HOSTS} must contain at least one host"
    );
    anyhow::ensure!(
        !hosts
            .iter()
            .any(|host| host.chars().any(char::is_whitespace)),
        "{ENV_ALLOWED_HOSTS} entries must not contain whitespace"
    );
    Ok(hosts)
}

fn default_allowed_hosts() -> Vec<String> {
    DEFAULT_ALLOWED_HOSTS
        .iter()
        .map(|host| (*host).to_owned())
        .collect()
}

fn strip_trailing_slash(mut value: String) -> String {
    while value.ends_with('/') {
        value.pop();
    }
    value
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::new(
            "https://wbsapi.withings.net/",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
            Secret::new("inbound"),
            "client-id",
            Secret::new("client-secret"),
        )
        .unwrap()
    }

    /// Every value a deployment that sets nothing optional actually gets.
    ///
    /// `from_env` starts from this constructor, so a default changed here is
    /// a default changed in production. A test that passed each value in
    /// would stay green through any of these moving.
    #[test]
    fn the_defaults_a_deployment_gets_when_it_sets_nothing() {
        let config = config();
        assert_eq!(config.api_base_url, "https://wbsapi.withings.net");
        // Loopback and nothing else. This file is published, so a
        // deployment's public origin belongs in the environment.
        assert_eq!(config.allowed_hosts, ["localhost", "127.0.0.1", "::1"]);
        assert_eq!(config.rate_limit_reads_per_min, 60);
        assert_eq!(config.initialize_burst, 32);
        assert_eq!(config.initialize_replenish, Duration::from_mins(1));
        assert_eq!(config.metrics_bind_addr.port(), 9090);
        assert!(config.metrics_bind_addr.ip().is_loopback());
        // Nothing OAuth-shaped is on by default: no seed, no state file, no
        // callback. The callback in particular writes a credential, so it
        // stays off until a deployment names the state value.
        assert!(config.seed_refresh_token.is_none());
        assert!(config.token_state_path.is_none());
        assert!(config.redirect_uri.is_none());
        assert!(config.oauth_state.is_none());
    }

    #[test]
    fn parses_explicit_allowed_hosts() {
        assert_eq!(
            parse_allowed_hosts(Some("one.test, two.test".to_owned())).unwrap(),
            vec!["one.test", "two.test"]
        );
        assert!(parse_allowed_hosts(Some(" , ".to_owned())).is_err());
        assert!(parse_allowed_hosts(Some("has space".to_owned())).is_err());
        assert_eq!(parse_allowed_hosts(None).unwrap(), default_allowed_hosts());
    }

    #[test]
    fn rejects_non_absolute_urls() {
        assert!(!is_absolute_http_uri("wbsapi.withings.net"));
        assert!(!is_absolute_http_uri("https://has space.test"));
        assert!(is_absolute_http_uri("https://wbsapi.withings.net"));
        assert!(
            Config::new(
                "wbsapi.withings.net",
                SocketAddr::from(([0, 0, 0, 0], 3000)),
                Secret::new("inbound"),
                "id",
                Secret::new("secret"),
            )
            .is_err()
        );
    }

    #[test]
    fn a_secret_never_prints_itself() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(secret.expose(), "hunter2");
        // The whole config is the thing someone actually logs.
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("client-secret"), "{rendered}");
        assert!(!rendered.contains("inbound"), "{rendered}");
    }
}
