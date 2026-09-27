//! The refresh-token lifecycle.
//!
//! Withings rotates the refresh token on **every** refresh: the response to a
//! `grant_type=refresh_token` call carries a new one, and the token that
//! produced it dies 8 hours after issuance or as soon as the new access token
//! is used, whichever comes first. So the value a deployment injects is a
//! *seed* and not a standing credential, and a process that keeps reading the
//! environment variable authenticates exactly once after each restart and then
//! stops — with a Withings `status: 401` and nothing else to go on.
//!
//! [`TokenStore`] is where the rotated value goes. Two implementations ship
//! here: [`MemoryStore`], which loses it on exit, and [`FileStore`], which
//! writes it to a `0600` file. Which one a deployment uses is a deployment
//! decision, and both directions have a real cost, so the choice is made in
//! configuration rather than in this module.
//!
//! The ordering inside a refresh is load-bearing and is documented on
//! [`TokenManager::persist_before_use`]: the rotated refresh token is written
//! down and read back **before** the new access token is used for anything.
//! Withings' 8-hour grace on the previous refresh token ends the moment the
//! new access token is used, so the reverse order trades a window in which a
//! person can notice a broken store for no window at all, and the two orders
//! are indistinguishable while everything works.

use std::fmt;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::withings_client::{ClientCredentials, TokenResponse, WithingsClient, WithingsError};

/// How long before expiry an access token is treated as spent.
///
/// A Withings access token lives three hours, so five minutes of headroom is
/// generous against clock skew and still refreshes fewer than nine times a
/// day at steady state.
pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_mins(5);

/// One authorised Withings user's tokens, as persisted.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredTokens {
    pub userid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scope: String,
    /// Unix seconds at which `access_token` stops being accepted.
    pub expires_at: u64,
}

impl fmt::Debug for StoredTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredTokens")
            .field("userid", &self.userid)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl StoredTokens {
    /// A new authorisation. It replaces an account rather than continuing
    /// one, so nothing is inherited. Only reached through [`TokenManager::adopt`],
    /// which has already refused a response without `userid` and `scope`.
    fn from_authorization(response: &TokenResponse, now: u64) -> Self {
        Self {
            userid: response.userid.clone().unwrap_or_default(),
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            scope: response.scope.clone().unwrap_or_default(),
            expires_at: now.saturating_add(response.expires_in),
        }
    }

    /// The record a refresh of `previous` produces.
    ///
    /// Withings' documented refresh response carries only the token pair and
    /// `expires_in`, so `userid` and `scope` are this account's, carried
    /// forward. A refresh continues the same authorisation, so the stored
    /// values are still true; dropping them would turn `whoami` blank after
    /// the first refresh. A value the response does carry wins.
    fn from_refresh(response: &TokenResponse, previous: &Self, now: u64) -> Self {
        Self {
            userid: response
                .userid
                .clone()
                .unwrap_or_else(|| previous.userid.clone()),
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            scope: response
                .scope
                .clone()
                .unwrap_or_else(|| previous.scope.clone()),
            expires_at: now.saturating_add(response.expires_in),
        }
    }

    /// Whether the access token is still usable `skew` ahead of now.
    #[must_use]
    pub const fn is_fresh(&self, now: u64, skew: Duration) -> bool {
        self.expires_at > now.saturating_add(skew.as_secs())
    }

    /// Seconds until the access token expires, saturating at zero.
    #[must_use]
    pub const fn expires_in(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }
}

/// Which token-store operation failed on the way to an access token.
///
/// This, and [`store_cause`], is everything about a store failure that leaves
/// this module. A store's own error is free text: `FileStore`'s can carry a
/// path, and a custom store's can quote the file it failed to parse, which
/// holds the credential. So neither a log line nor an MCP error carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStep {
    /// Reading the stored tokens, before a refresh or under the gate.
    Load,
    /// Writing the rotated tokens.
    Persist,
    /// Reading the rotated tokens back after writing them.
    ReadBack,
    /// The read-back succeeded and returned something else.
    Mismatch,
}

impl StoreStep {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Persist => "persist",
            Self::ReadBack => "read_back",
            Self::Mismatch => "mismatch",
        }
    }
}

impl fmt::Display for StoreStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bounded description of a store error: a class and, for an I/O failure,
/// its [`std::io::ErrorKind`]. Both come from fixed sets, so they are safe to
/// log where the error's `Display` is not.
#[must_use]
pub fn store_cause(error: &anyhow::Error) -> (&'static str, Option<std::io::ErrorKind>) {
    if error
        .chain()
        .any(<dyn std::error::Error>::is::<WithingsError>)
    {
        return ("withings", None);
    }
    if error
        .chain()
        .any(<dyn std::error::Error>::is::<serde_json::Error>)
    {
        return ("parse", None);
    }
    let io_kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind);
    (if io_kind.is_some() { "io" } else { "other" }, io_kind)
}

/// Log a store failure by step and bounded cause, and turn it into the error
/// the caller sees. The only place a store error on the refresh path is
/// reported, so there is one thing to keep free of the error's text.
fn store_failure(step: StoreStep, error: &anyhow::Error) -> WithingsError {
    let (cause, io_kind) = store_cause(error);
    warn!(
        step = step.as_str(),
        cause,
        ?io_kind,
        "token store failed; not using a new access token"
    );
    WithingsError::TokenStore { step }
}

/// Where the rotated refresh token is kept between refreshes.
///
/// Implementations must be usable from many tasks at once. `save` is called
/// on every refresh and is expected to be atomic enough that a crash between
/// two calls leaves either the old value or the new one, never a truncated
/// file.
pub trait TokenStore: Send + Sync + fmt::Debug {
    fn load(&self) -> Result<Option<StoredTokens>>;
    fn save(&self, tokens: &StoredTokens) -> Result<()>;
}

/// Keeps the rotated token in process memory only.
///
/// A restart loses it and the server falls back to the configured seed, which
/// works exactly once per seed value. Correct for tests and for a local run;
/// for a long-lived deployment it means re-authorising by hand.
#[derive(Debug, Default)]
pub struct MemoryStore {
    tokens: RwLock<Option<StoredTokens>>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredTokens>> {
        Ok(self
            .tokens
            .read()
            .map_err(|_| anyhow::anyhow!("token store lock poisoned"))?
            .clone())
    }

    fn save(&self, tokens: &StoredTokens) -> Result<()> {
        let tokens = tokens.clone();
        let mut guard = self
            .tokens
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(tokens);
        drop(guard);
        Ok(())
    }
}

/// Persists the rotated token to a file, replaced atomically.
///
/// The file holds a live credential. It is written `0600` and is only ever an
/// appropriate destination on storage the deployment already treats as secret.
#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn temp_path(&self) -> PathBuf {
        let mut path = self.path.clone().into_os_string();
        path.push(".tmp");
        PathBuf::from(path)
    }
}

impl TokenStore for FileStore {
    fn load(&self) -> Result<Option<StoredTokens>> {
        match std::fs::read(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("read token state"),
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("parse token state")?,
            )),
        }
    }

    fn save(&self, tokens: &StoredTokens) -> Result<()> {
        let serialized = serde_json::to_vec(tokens).context("serialize token state")?;
        let temp_path = self.temp_path();
        // Create with 0600 and rename over the target, so a reader never sees
        // a half-written file and the credential is never briefly world
        // readable.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path).context("open token state")?;
        file.write_all(&serialized).context("write token state")?;
        file.sync_all().context("sync token state")?;
        drop(file);
        std::fs::rename(&temp_path, &self.path).context("replace token state")?;
        Ok(())
    }
}

/// Holds the current tokens and refreshes them when they go stale.
///
/// **One `Mutex` serialises every mutation reachable after construction**:
/// [`Self::adopt`] and the whole refresh-persist-read-back-return sequence both
/// take it. Serialising refreshes alone is not enough, and the gap is not
/// obvious: a callback adopting a new authorisation between a refresh's
/// read-back and its return leaves the store holding a token that does not
/// match the access token just handed out, so the guarantee
/// `persist_before_use` exists to make stops being atomic. Found in
/// cross-engine review of this file, 2026-08-29.
///
/// Seeding is the third mutation and it is **not** behind the gate, because it
/// happens in [`seed`] before the manager exists and therefore before anything
/// can share it. That is why it is a constructor argument rather than a
/// method: a gate whose necessity depends on an ordering nothing asserts is a
/// gate a reader cannot evaluate.
///
/// What the serialisation buys: N concurrent tool calls arriving on an expired
/// token produce one refresh rather than N. N concurrent refreshes would rotate
/// the token N times and persist only the last, leaving the store holding a
/// value Withings has already superseded — the same silent death as no
/// write-back at all, reachable without a restart.
///
/// **The gate is per manager, so one store must not be shared by two.** Two
/// managers over one store have two mutexes and none of this holds. There is
/// one manager per process here and nothing enforces that in the type.
pub struct TokenManager {
    client: WithingsClient,
    credentials: ClientCredentials,
    store: Box<dyn TokenStore>,
    refresh_skew: Duration,
    store_gate: Mutex<()>,
}

impl fmt::Debug for TokenManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenManager")
            .field("store", &self.store)
            .field("refresh_skew", &self.refresh_skew)
            .finish_non_exhaustive()
    }
}

/// Write the configured seed into an empty store.
///
/// Taken as a constructor argument rather than a method on purpose. The seed
/// is applied to a store that has not yet been handed to a [`TokenManager`],
/// so nothing else can hold a reference to it and there is no ordering for a
/// later edit to get wrong. The previous shape was a public `seed_refresh_token`
/// whose safety rested on `main` calling it before the listener bound —
/// unasserted, and removing its lock reddened no test. Cross-engine review of
/// the gate, 2026-08-29.
///
/// A seed never overwrites a stored value: the stored one is newer by
/// construction, and preferring the environment would hand Withings a refresh
/// token it retired at the previous rotation.
fn seed(store: &dyn TokenStore, refresh_token: Option<&str>) -> Result<()> {
    let Some(refresh_token) = refresh_token else {
        return Ok(());
    };
    if store.load()?.is_some() {
        info!("token store already holds tokens; configured seed not used");
        return Ok(());
    }
    store.save(&StoredTokens {
        userid: String::new(),
        access_token: String::new(),
        refresh_token: refresh_token.to_owned(),
        scope: String::new(),
        // Zero is in the past, so the first call refreshes. There is no
        // access token to go with a seed.
        expires_at: 0,
    })
}

impl TokenManager {
    /// Build a manager with [`DEFAULT_REFRESH_SKEW`], seeding the store if a
    /// seed was configured and the store holds nothing.
    ///
    /// This is the constructor `main` calls, so it is the one whose behaviour
    /// a deployment actually gets.
    pub fn new(
        client: WithingsClient,
        credentials: ClientCredentials,
        store: Box<dyn TokenStore>,
        seed_refresh_token: Option<&str>,
    ) -> Result<Self> {
        Self::with_refresh_skew(
            client,
            credentials,
            store,
            seed_refresh_token,
            DEFAULT_REFRESH_SKEW,
        )
    }

    pub fn with_refresh_skew(
        client: WithingsClient,
        credentials: ClientCredentials,
        store: Box<dyn TokenStore>,
        seed_refresh_token: Option<&str>,
        refresh_skew: Duration,
    ) -> Result<Self> {
        seed(store.as_ref(), seed_refresh_token)?;
        Ok(Self {
            client,
            credentials,
            store,
            refresh_skew,
            store_gate: Mutex::new(()),
        })
    }

    /// Replace whatever is stored with a freshly authorised pair.
    ///
    /// Used by the OAuth callback, which is the one path that legitimately
    /// discards an existing credential.
    ///
    /// Fails closed, before touching the store, on a response without a
    /// `userid` and `scope`. `exchange_code` already refuses one; this is
    /// checked again here because this is where the credential is replaced,
    /// and a record with no identity is one a later refresh would carry
    /// forward blank indefinitely.
    pub async fn adopt(&self, response: &TokenResponse) -> Result<StoredTokens> {
        response
            .require_identity()
            .context("refusing to adopt an authorisation that does not name its account")?;
        let _guard = self.store_gate.lock().await;
        let tokens = StoredTokens::from_authorization(response, now_unix());
        self.store.save(&tokens)?;
        Ok(tokens)
    }

    /// The tokens as stored, without refreshing.
    pub fn peek(&self) -> Result<Option<StoredTokens>> {
        self.store.load()
    }

    /// A usable access token, refreshing first if the stored one is spent.
    pub async fn access_token(&self) -> Result<StoredTokens, WithingsError> {
        let stored = self.load_or_unauthorized()?;
        if stored.is_fresh(now_unix(), self.refresh_skew) {
            return Ok(stored);
        }
        let _guard = self.store_gate.lock().await;
        // Re-read under the gate: another task may have refreshed while this
        // one waited, and refreshing again would rotate a token that is
        // already current.
        let stored = self.load_or_unauthorized()?;
        if stored.is_fresh(now_unix(), self.refresh_skew) {
            return Ok(stored);
        }
        let response = self
            .client
            .refresh(&self.credentials, &stored.refresh_token)
            .await?;
        let refreshed = StoredTokens::from_refresh(&response, &stored, now_unix());
        self.persist_before_use(&refreshed)?;
        // No userid: a Withings user id is account content, and this line is
        // on the path whose logs `a_refresh_failure_names_its_stage_...` in
        // `main.rs` holds to envelope fields only.
        info!(
            expires_in = response.expires_in,
            "refreshed the Withings access token"
        );
        Ok(refreshed)
    }

    /// Write the rotated refresh token down and read it back before the new
    /// access token is handed to anything that would use it.
    ///
    /// Withings retires the previous refresh token **8 hours after issuance or
    /// as soon as the new access token is used**, whichever comes first. Using
    /// first and persisting second therefore trades an eight-hour window in
    /// which a person can notice a broken store for no window at all: the
    /// credential is gone the instant the served call succeeds, and the only
    /// recovery is the user authorising again in a browser.
    ///
    /// So a failed write, or a read-back that disagrees, aborts the refresh.
    /// The caller sees an error, the tool call fails loudly, and the old
    /// refresh token is still alive.
    ///
    /// This and the store gate defend the same thing from two sides — the gate
    /// stops a concurrent mutation superseding the value being stored, this
    /// stops a stored value being skipped altogether. Neither makes the other
    /// redundant.
    ///
    /// Every failure here is reported through [`store_failure`], by step and
    /// never by the store's own text.
    fn persist_before_use(&self, refreshed: &StoredTokens) -> Result<(), WithingsError> {
        self.store
            .save(refreshed)
            .map_err(|error| store_failure(StoreStep::Persist, &error))?;
        let read_back = self
            .store
            .load()
            .map_err(|error| store_failure(StoreStep::ReadBack, &error))?;
        // The whole record, not only the refresh token: a store that kept the
        // token but lost the carried-forward identity is half a state, and
        // `whoami` would read it back blank.
        if read_back.as_ref() != Some(refreshed) {
            warn!(
                step = StoreStep::Mismatch.as_str(),
                "token store did not read back the refreshed token; not using the new access token"
            );
            return Err(WithingsError::TokenStore {
                step: StoreStep::Mismatch,
            });
        }
        Ok(())
    }

    fn load_or_unauthorized(&self) -> Result<StoredTokens, WithingsError> {
        self.store
            .load()
            .map_err(|error| store_failure(StoreStep::Load, &error))?
            .filter(|tokens| !tokens.refresh_token.is_empty())
            .ok_or(WithingsError::InvalidGrant)
    }
}

/// Seconds since the Unix epoch. A clock before 1970 reads as zero, which
/// makes every token stale rather than eternally fresh.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn credentials() -> ClientCredentials {
        ClientCredentials {
            client_id: "id".to_owned(),
            client_secret: "secret".to_owned(),
        }
    }

    fn token_response(access: &str, refresh: &str) -> serde_json::Value {
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

    /// The constructor `main` uses takes no skew argument, so this is the only
    /// test that can catch the default being changed. A test that always
    /// passes a skew would stay green with `DEFAULT_REFRESH_SKEW` set to zero.
    #[test]
    fn the_no_argument_constructor_uses_the_documented_skew() {
        let manager = TokenManager::new(
            WithingsClient::new("https://example.test").unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            None,
        )
        .unwrap();
        assert_eq!(manager.refresh_skew, DEFAULT_REFRESH_SKEW);
        assert_eq!(DEFAULT_REFRESH_SKEW, Duration::from_mins(5));
        // Non-zero is the property that matters: at zero, a token is fresh
        // until the instant it expires and every refresh races the clock.
        assert!(DEFAULT_REFRESH_SKEW > Duration::from_secs(0));
    }

    #[test]
    fn a_token_inside_the_skew_window_is_not_fresh() {
        let tokens = StoredTokens {
            userid: "u".to_owned(),
            access_token: "a".to_owned(),
            refresh_token: "r".to_owned(),
            scope: String::new(),
            expires_at: 1_000,
        };
        assert!(tokens.is_fresh(500, DEFAULT_REFRESH_SKEW));
        // 4 minutes left, skew is 5: spent.
        assert!(!tokens.is_fresh(760, DEFAULT_REFRESH_SKEW));
        assert!(!tokens.is_fresh(1_001, DEFAULT_REFRESH_SKEW));
        assert_eq!(tokens.expires_in(1_001), 0);
        assert_eq!(tokens.expires_in(400), 600);
    }

    #[tokio::test]
    async fn a_refresh_persists_the_rotated_token_and_the_next_refresh_uses_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("refresh_token=seed"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(token_response("acc-1", "rot-1")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            Some("seed"),
        )
        .unwrap();

        let tokens = manager.access_token().await.unwrap();
        assert_eq!(tokens.access_token, "acc-1");
        // The seed is gone from the store. If it were still there, the next
        // refresh after a restart would send a token Withings has retired.
        let stored = manager.peek().unwrap().unwrap();
        assert_eq!(stored.refresh_token, "rot-1");
        server.verify().await;
    }

    /// Withings' documented refresh response: the token pair and
    /// `expires_in`, and nothing else.
    fn documented_refresh_response(access: &str, refresh: &str) -> serde_json::Value {
        json!({
            "status": 0,
            "body": {
                "access_token": access,
                "refresh_token": refresh,
                "expires_in": 10800
            }
        })
    }

    /// A store holding an authorised account whose access token is spent, so
    /// the next call is a forced refresh. Invented id.
    fn expired_account() -> MemoryStore {
        let store = MemoryStore::new();
        store
            .save(&StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "acc-0".to_owned(),
                refresh_token: "rot-0".to_owned(),
                scope: "user.metrics".to_owned(),
                expires_at: 0,
            })
            .unwrap();
        store
    }

    /// Withings' documented refresh response has no `userid` and no `scope`.
    /// A refresh continues the same authorisation, so both are carried forward
    /// from the stored record; losing them would blank `whoami` after the
    /// first refresh, and requiring them failed every refresh outright.
    #[tokio::test]
    async fn a_refresh_that_omits_identity_keeps_the_stored_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("refresh_token=rot-0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(documented_refresh_response("acc-1", "rot-1")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(expired_account()),
            None,
        )
        .unwrap();

        let handed_out = manager.access_token().await.unwrap();
        let stored = manager.peek().unwrap().unwrap();
        assert_eq!(
            handed_out, stored,
            "handed-out tokens differ from the stored ones"
        );
        assert_eq!(stored.userid, "1234567");
        assert_eq!(stored.scope, "user.metrics");
        assert_eq!(stored.access_token, "acc-1");
        assert_eq!(stored.refresh_token, "rot-1");
        assert!(stored.expires_at > 0);
        server.verify().await;
    }

    /// A seed has no identity to carry forward, and a refresh that returns
    /// none must still succeed and persist the rotation rather than invent
    /// one. `whoami` then reports an empty userid until a consent names it.
    #[tokio::test]
    async fn a_seeded_refresh_that_omits_identity_persists_the_rotation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .and(body_string_contains("refresh_token=seed"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(documented_refresh_response("acc-1", "rot-1")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            Some("seed"),
        )
        .unwrap();
        assert_eq!(manager.peek().unwrap().unwrap().expires_at, 0);

        manager.access_token().await.unwrap();
        let stored = manager.peek().unwrap().unwrap();
        assert_eq!(stored.refresh_token, "rot-1");
        assert_eq!(stored.userid, "");
        assert_eq!(stored.scope, "");
        server.verify().await;
    }

    /// A value the refresh response does carry wins over the stored one, and
    /// a numeric `userid` is held as a string. Invented id.
    #[tokio::test]
    async fn a_forced_refresh_with_a_numeric_userid_persists_it_as_a_string() {
        let server = MockServer::start().await;
        let mut body = documented_refresh_response("acc-1", "rot-1");
        body["body"]["userid"] = json!(7_654_321);
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(expired_account()),
            None,
        )
        .unwrap();

        let handed_out = manager.access_token().await.unwrap();
        assert_eq!(handed_out.userid, "7654321");
        let stored = manager.peek().unwrap().unwrap();
        assert_eq!(stored.userid, "7654321");
        assert_eq!(stored.scope, "user.metrics");
        server.verify().await;
    }

    /// Keeps the refresh token of every write but drops the identity after
    /// the first: the half-state a lossy destination leaves.
    #[derive(Debug, Default)]
    struct IdentityDroppingStore {
        tokens: RwLock<Option<StoredTokens>>,
        writes: std::sync::atomic::AtomicUsize,
    }

    impl TokenStore for IdentityDroppingStore {
        fn load(&self) -> Result<Option<StoredTokens>> {
            Ok(self.tokens.read().unwrap().clone())
        }

        fn save(&self, tokens: &StoredTokens) -> Result<()> {
            let mut kept = tokens.clone();
            if self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                > 0
            {
                kept.userid.clear();
                kept.scope.clear();
            }
            *self.tokens.write().unwrap() = Some(kept);
            Ok(())
        }
    }

    /// The read-back checks the whole record. A store that kept the rotated
    /// token and lost the carried-forward identity must not yield the new
    /// access token, exactly as a store that lost the token does.
    #[tokio::test]
    async fn a_refresh_whose_identity_did_not_persist_never_yields_an_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(documented_refresh_response("acc-1", "rot-1")),
            )
            .mount(&server)
            .await;
        let store = IdentityDroppingStore::default();
        store
            .save(&StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "acc-0".to_owned(),
                refresh_token: "rot-0".to_owned(),
                scope: "user.metrics".to_owned(),
                expires_at: 0,
            })
            .unwrap();
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(store),
            None,
        )
        .unwrap();

        let error = manager.access_token().await.unwrap_err();
        assert!(
            matches!(
                error,
                WithingsError::TokenStore {
                    step: StoreStep::Mismatch
                }
            ),
            "{error}"
        );
    }

    /// A consent that does not name its account is refused before the store
    /// is touched: only a refresh may inherit identity, and an adopt is where
    /// a record's identity comes from.
    #[tokio::test]
    async fn an_adopt_without_userid_or_scope_fails_closed_and_stores_nothing() {
        let manager = TokenManager::new(
            WithingsClient::new("https://example.test").unwrap(),
            credentials(),
            Box::new(expired_account()),
            None,
        )
        .unwrap();
        let before = manager.peek().unwrap().unwrap();
        let complete = TokenResponse {
            userid: Some("7654321".to_owned()),
            access_token: "acc-new".to_owned(),
            refresh_token: "rot-new".to_owned(),
            scope: Some("user.metrics".to_owned()),
            expires_in: 10_800,
        };
        for incomplete in [
            TokenResponse {
                userid: None,
                ..complete.clone()
            },
            TokenResponse {
                scope: None,
                ..complete.clone()
            },
            TokenResponse {
                userid: Some(String::new()),
                ..complete.clone()
            },
        ] {
            let error = manager.adopt(&incomplete).await.unwrap_err();
            assert!(!format!("{error:#}").contains("rot-new"), "{error:#}");
            assert_eq!(manager.peek().unwrap().unwrap(), before);
        }
        manager.adopt(&complete).await.unwrap();
        assert_eq!(manager.peek().unwrap().unwrap().userid, "7654321");
    }

    /// A forced refresh Withings answers with a non-zero status must leave the
    /// store exactly as it was: the seed is still the only live credential.
    /// `503` is the documented "invalid params" status and is not specially
    /// mapped, so it arrives as `Api { status: 503 }` with the number intact.
    #[tokio::test]
    async fn a_refused_forced_refresh_keeps_the_status_and_persists_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"status": 503, "error": "invented detail"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            Some("seed"),
        )
        .unwrap();
        let before = manager.peek().unwrap().unwrap();

        let error = manager.access_token().await.unwrap_err();
        assert!(
            matches!(error, WithingsError::Api { status: 503 }),
            "{error:?}"
        );
        assert_eq!(manager.peek().unwrap().unwrap(), before);
        server.verify().await;
    }

    #[tokio::test]
    async fn a_fresh_token_is_served_without_calling_withings() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(token_response("acc-1", "rot-1")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            Some("seed"),
        )
        .unwrap();
        manager.access_token().await.unwrap();
        // Second call is inside the three-hour window: `expect(1)` above is
        // what fails if this one refreshes again.
        let second = manager.access_token().await.unwrap();
        assert_eq!(second.access_token, "acc-1");
        server.verify().await;
    }

    /// Accepts the first write and silently drops every later one.
    ///
    /// This is the shape a misconfigured destination actually has: no error,
    /// no log line, and a `save` that returns `Ok`. A store that errors is the
    /// easy case.
    #[derive(Debug, Default)]
    struct WriteOnceStore {
        tokens: RwLock<Option<StoredTokens>>,
        writes: std::sync::atomic::AtomicUsize,
    }

    impl TokenStore for WriteOnceStore {
        fn load(&self) -> Result<Option<StoredTokens>> {
            Ok(self.tokens.read().unwrap().clone())
        }

        fn save(&self, tokens: &StoredTokens) -> Result<()> {
            if self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                *self.tokens.write().unwrap() = Some(tokens.clone());
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FailingStore {
        tokens: RwLock<Option<StoredTokens>>,
        fail_after: std::sync::atomic::AtomicUsize,
    }

    impl TokenStore for FailingStore {
        fn load(&self) -> Result<Option<StoredTokens>> {
            Ok(self.tokens.read().unwrap().clone())
        }

        fn save(&self, tokens: &StoredTokens) -> Result<()> {
            if self
                .fail_after
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                *self.tokens.write().unwrap() = Some(tokens.clone());
                return Ok(());
            }
            anyhow::bail!("disk is full")
        }
    }

    async fn refresh_against(store: Box<dyn TokenStore>) -> Result<StoredTokens, WithingsError> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(token_response("acc-1", "rot-1")),
            )
            .mount(&server)
            .await;
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            store,
            Some("seed"),
        )
        .unwrap();
        manager.access_token().await
    }

    /// Withings retires the old refresh token as soon as the new access token
    /// is used, so a refresh whose write-back did not land must never hand
    /// that access token out. If it does, the credential is spent and the
    /// only recovery is a browser.
    ///
    /// The two stores are the two ways a destination breaks. The silent one
    /// is why the read-back exists: without it, `save` returning `Ok` is the
    /// whole check, and it passes.
    #[tokio::test]
    async fn a_refresh_that_cannot_be_persisted_never_yields_an_access_token() {
        let dropped = refresh_against(Box::new(WriteOnceStore::default())).await;
        let error = dropped
            .err()
            .ok_or("a dropped write must not yield an access token")
            .unwrap();
        assert!(
            matches!(
                error,
                WithingsError::TokenStore {
                    step: StoreStep::Mismatch
                }
            ),
            "expected the read-back to catch a silent drop: {error}"
        );

        let failed = refresh_against(Box::new(FailingStore::default())).await;
        let error = failed
            .err()
            .ok_or("a failed write must not yield an access token")
            .unwrap();
        assert!(
            matches!(
                error,
                WithingsError::TokenStore {
                    step: StoreStep::Persist
                }
            ),
            "{error}"
        );
        // The store said "disk is full"; the caller hears the step only.
        assert!(!format!("{error}").contains("disk"), "{error}");
    }

    /// A handle onto a shared [`RecordingStore`], so the test can read the
    /// write order after handing ownership to the manager.
    struct Shared(std::sync::Arc<RecordingStore>);

    impl fmt::Debug for Shared {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Shared")
        }
    }

    impl TokenStore for Shared {
        fn load(&self) -> Result<Option<StoredTokens>> {
            self.0.load()
        }

        fn save(&self, tokens: &StoredTokens) -> Result<()> {
            self.0.save(tokens)
        }
    }

    /// Records the refresh token of every write, in order.
    #[derive(Debug, Default)]
    struct RecordingStore {
        tokens: RwLock<Option<StoredTokens>>,
        writes: RwLock<Vec<String>>,
    }

    impl TokenStore for RecordingStore {
        fn load(&self) -> Result<Option<StoredTokens>> {
            Ok(self.tokens.read().unwrap().clone())
        }

        fn save(&self, tokens: &StoredTokens) -> Result<()> {
            self.writes
                .write()
                .unwrap()
                .push(tokens.refresh_token.clone());
            *self.tokens.write().unwrap() = Some(tokens.clone());
            Ok(())
        }
    }

    /// `adopt` must not mutate the store while a refresh is in flight.
    ///
    /// Serialising refreshes alone leaves this open: a callback adopting a new
    /// authorisation between a refresh's read-back and its return leaves the
    /// store holding a token that does not match the access token just handed
    /// out, so the atomicity `persist_before_use` exists to provide is gone.
    /// Found in cross-engine review, 2026-08-29.
    ///
    /// The refresh is delayed 300 ms and the adopt is issued 50 ms in. Under
    /// the gate the writes are ordered refresh-then-adopt; with `adopt` outside
    /// it, the adopt write lands first, in the middle of the refresh.
    #[tokio::test]
    async fn an_adopt_cannot_interleave_with_a_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/oauth2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(token_response("acc-1", "rot-1"))
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;

        let store = std::sync::Arc::new(RecordingStore::default());
        let manager = std::sync::Arc::new(
            TokenManager::new(
                WithingsClient::new(&server.uri()).unwrap(),
                credentials(),
                Box::new(Shared(std::sync::Arc::clone(&store))),
                Some("seed"),
            )
            .unwrap(),
        );

        let refreshing = tokio::spawn({
            let manager = std::sync::Arc::clone(&manager);
            async move { manager.access_token().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager
            .adopt(&TokenResponse {
                userid: Some("1234567".to_owned()),
                access_token: "acc-adopted".to_owned(),
                refresh_token: "rot-adopted".to_owned(),
                scope: Some("user.metrics".to_owned()),
                expires_in: 10_800,
            })
            .await
            .unwrap();
        refreshing.await.unwrap().unwrap();

        let writes = store.writes.read().unwrap().clone();
        assert_eq!(
            writes,
            vec![
                "seed".to_owned(),
                "rot-1".to_owned(),
                "rot-adopted".to_owned()
            ],
            "the adopt wrote while the refresh was in flight"
        );
    }

    #[tokio::test]
    async fn a_seed_never_overwrites_a_stored_rotation() {
        let store = MemoryStore::new();
        store
            .save(&StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "acc".to_owned(),
                refresh_token: "rotated".to_owned(),
                scope: String::new(),
                expires_at: now_unix() + 10_800,
            })
            .unwrap();
        let manager = TokenManager::new(
            WithingsClient::new("https://example.test").unwrap(),
            credentials(),
            Box::new(store),
            Some("stale-seed"),
        )
        .unwrap();
        assert_eq!(manager.peek().unwrap().unwrap().refresh_token, "rotated");
    }

    #[tokio::test]
    async fn an_empty_store_is_an_invalid_grant_rather_than_a_transport_error() {
        let manager = TokenManager::new(
            WithingsClient::new("https://example.test").unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
            None,
        )
        .unwrap();
        let error = manager.access_token().await.unwrap_err();
        assert_eq!(error.code(), "withings_invalid_grant");
    }

    #[test]
    fn the_file_store_round_trips_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("state.json"));
        assert!(store.load().unwrap().is_none());

        let first = StoredTokens {
            userid: "1234567".to_owned(),
            access_token: "acc-1".to_owned(),
            refresh_token: "rot-1".to_owned(),
            scope: "user.metrics".to_owned(),
            expires_at: 10_800,
        };
        store.save(&first).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), first);

        let second = StoredTokens {
            refresh_token: "rot-2".to_owned(),
            ..first
        };
        store.save(&second).unwrap();
        assert_eq!(store.load().unwrap().unwrap().refresh_token, "rot-2");
        assert!(!store.temp_path().exists(), "temp file left behind");
    }

    #[cfg(unix)]
    #[test]
    fn the_file_store_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("state.json"));
        store
            .save(&StoredTokens {
                userid: "u".to_owned(),
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
                scope: String::new(),
                expires_at: 0,
            })
            .unwrap();
        let mode = std::fs::metadata(dir.path().join("state.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "state file is {:o}", mode & 0o777);
    }

    #[test]
    fn stored_tokens_debug_redacts_both_tokens() {
        let rendered = format!(
            "{:?}",
            StoredTokens {
                userid: "1234567".to_owned(),
                access_token: "secret-access".to_owned(),
                refresh_token: "secret-refresh".to_owned(),
                scope: String::new(),
                expires_at: 0,
            }
        );
        assert!(!rendered.contains("secret-access"), "{rendered}");
        assert!(!rendered.contains("secret-refresh"), "{rendered}");
    }
}
