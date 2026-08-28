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
    fn from_response(response: &TokenResponse, now: u64) -> Self {
        Self {
            userid: response.userid.clone(),
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            scope: response.scope.clone(),
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
/// **One `Mutex` serialises every mutation of the store**, not only refreshes:
/// [`Self::seed_refresh_token`], [`Self::adopt`] and the whole
/// refresh-persist-read-back-return sequence all take it. Serialising refreshes
/// alone is not enough, and the gap is not obvious — a callback adopting a new
/// authorisation between a refresh's read-back and its return leaves the store
/// holding a token that does not match the access token just handed out, so the
/// guarantee `persist_before_use` exists to make stops being atomic. Found in
/// cross-engine review of this file, 2026-08-29.
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

impl TokenManager {
    /// Build a manager with [`DEFAULT_REFRESH_SKEW`].
    ///
    /// This is the constructor `main` calls, so it is the one whose behaviour
    /// a deployment actually gets.
    #[must_use]
    pub fn new(
        client: WithingsClient,
        credentials: ClientCredentials,
        store: Box<dyn TokenStore>,
    ) -> Self {
        Self::with_refresh_skew(client, credentials, store, DEFAULT_REFRESH_SKEW)
    }

    #[must_use]
    pub fn with_refresh_skew(
        client: WithingsClient,
        credentials: ClientCredentials,
        store: Box<dyn TokenStore>,
        refresh_skew: Duration,
    ) -> Self {
        Self {
            client,
            credentials,
            store,
            refresh_skew,
            store_gate: Mutex::new(()),
        }
    }

    /// Seed the store from configuration if it holds nothing yet.
    ///
    /// A seed never overwrites a stored value: the stored one is newer by
    /// construction, and preferring the environment would hand Withings a
    /// refresh token it retired at the previous rotation.
    pub async fn seed_refresh_token(&self, refresh_token: &str) -> Result<()> {
        let _guard = self.store_gate.lock().await;
        if self.store.load()?.is_some() {
            info!("token store already holds tokens; configured seed not used");
            return Ok(());
        }
        self.store.save(&StoredTokens {
            userid: String::new(),
            access_token: String::new(),
            refresh_token: refresh_token.to_owned(),
            scope: String::new(),
            // Zero is in the past, so the first call refreshes. There is no
            // access token to go with a seed.
            expires_at: 0,
        })
    }

    /// Replace whatever is stored with a freshly authorised pair.
    ///
    /// Used by the OAuth callback, which is the one path that legitimately
    /// discards an existing credential.
    pub async fn adopt(&self, response: &TokenResponse) -> Result<StoredTokens> {
        let _guard = self.store_gate.lock().await;
        let tokens = StoredTokens::from_response(response, now_unix());
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
        let refreshed = StoredTokens::from_response(&response, now_unix());
        self.persist_before_use(&refreshed)?;
        info!(
            userid = %refreshed.userid,
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
    fn persist_before_use(&self, refreshed: &StoredTokens) -> Result<(), WithingsError> {
        if let Err(error) = self.store.save(refreshed) {
            warn!(%error, "refreshed tokens could not be persisted; not using the new access token");
            return Err(WithingsError::InvalidInput(format!(
                "persist refreshed tokens: {error}"
            )));
        }
        let read_back = self.store.load().map_err(|error| {
            warn!(%error, "refreshed tokens could not be read back");
            WithingsError::InvalidInput(format!("read back refreshed tokens: {error}"))
        })?;
        if read_back
            .as_ref()
            .map(|tokens| tokens.refresh_token.as_str())
            != Some(refreshed.refresh_token.as_str())
        {
            warn!(
                "token store did not read back the refreshed token; not using the new access token"
            );
            return Err(WithingsError::InvalidInput(
                "token store did not read back the refreshed token".to_owned(),
            ));
        }
        Ok(())
    }

    fn load_or_unauthorized(&self) -> Result<StoredTokens, WithingsError> {
        self.store
            .load()
            .map_err(|error| WithingsError::InvalidInput(format!("read token store: {error}")))?
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
        );
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

        let store = Box::new(MemoryStore::new());
        let manager = TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            store,
        );
        manager.seed_refresh_token("seed").await.unwrap();

        let tokens = manager.access_token().await.unwrap();
        assert_eq!(tokens.access_token, "acc-1");
        // The seed is gone from the store. If it were still there, the next
        // refresh after a restart would send a token Withings has retired.
        let stored = manager.peek().unwrap().unwrap();
        assert_eq!(stored.refresh_token, "rot-1");
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
        );
        manager.seed_refresh_token("seed").await.unwrap();
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
        );
        manager.seed_refresh_token("seed").await.unwrap();
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
            format!("{error}").contains("read back"),
            "expected the read-back to catch a silent drop: {error}"
        );

        let failed = refresh_against(Box::new(FailingStore::default())).await;
        let error = failed
            .err()
            .ok_or("a failed write must not yield an access token")
            .unwrap();
        assert!(format!("{error}").contains("persist"), "{error}");
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
        let manager = std::sync::Arc::new(TokenManager::new(
            WithingsClient::new(&server.uri()).unwrap(),
            credentials(),
            Box::new(Shared(std::sync::Arc::clone(&store))),
        ));
        manager.seed_refresh_token("seed").await.unwrap();

        let refreshing = tokio::spawn({
            let manager = std::sync::Arc::clone(&manager);
            async move { manager.access_token().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager
            .adopt(&TokenResponse {
                userid: "1234567".to_owned(),
                access_token: "acc-adopted".to_owned(),
                refresh_token: "rot-adopted".to_owned(),
                scope: "user.metrics".to_owned(),
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
        );
        manager.seed_refresh_token("stale-seed").await.unwrap();
        assert_eq!(manager.peek().unwrap().unwrap().refresh_token, "rotated");
    }

    #[tokio::test]
    async fn an_empty_store_is_an_invalid_grant_rather_than_a_transport_error() {
        let manager = TokenManager::new(
            WithingsClient::new("https://example.test").unwrap(),
            credentials(),
            Box::new(MemoryStore::new()),
        );
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
