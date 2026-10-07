//! Session-management hardening.
//!
//! Wraps `rmcp`'s `LocalSessionManager` with two complementary defences
//! against authenticated denial-of-service via session flooding:
//!
//! * **Idle TTL** — `LocalSessionManager` is constructed with a
//!   [`SessionConfig`] whose `keep_alive` is set to 30 minutes. rmcp's default
//!   is 5 minutes; we lengthen it so claude.ai's variable tool-call cadence
//!   (sometimes >5 min between calls within a long conversation) doesn't
//!   silently evict sessions and leave the connector wedged in a "connected
//!   but un-handshaken" state. The global [`MAX_SESSIONS`] cap remains the
//!   real defence against session flooding.
//!
//! * **Global session cap** — [`CappedSessionManager`] wraps the inner
//!   manager and rejects `create_session` once the live session count hits
//!   [`MAX_SESSIONS`]. New `initialize` requests receive an HTTP 503 / JSON-RPC
//!   error instead of growing memory without bound.
//!
//! Both mitigations are applied together in `build_router`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
    local::{LocalSessionManager, LocalSessionManagerError, SessionTransport},
};
use tracing::{info, warn};

/// Maximum number of concurrent MCP sessions the server will hold.
///
/// Requests that would push the count beyond this limit receive an error
/// from `create_session`. Legitimate claude.ai usage peaks around one or
/// two sessions per user; 2048 comfortably covers all expected concurrent
/// users (and a reconnect storm after a rollout) while bounding the
/// worst-case memory from a flooded attacker. The count only means anything
/// because dead sessions are reclaimed; see [`CappedSessionManager`].
pub const MAX_SESSIONS: usize = 2048;

/// Idle timeout applied to each session.
///
/// 30 minutes — longer than rmcp's 5-minute default. claude.ai's MCP
/// connector doesn't always heartbeat within a tight window, and an
/// evicted-too-fast session leaves the connector in a wedged state
/// (UI shows "connected" but every subsequent tool call sends a
/// stale session id, 404s, and silently drops). The global
/// [`MAX_SESSIONS`] cap remains the real defence against an
/// authenticated session flood.
pub const SESSION_KEEP_ALIVE: Duration = Duration::from_mins(30);

/// How often the background sweeper reclaims sessions whose worker is gone.
///
/// `create_session` also reclaims before it counts, so the cap never refuses
/// on account of a dead session; the sweeper keeps the live count (and the
/// memory behind it) accurate between initializes.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Build a `LocalSessionManager` with the tightened idle TTL.
///
/// Mitigation A: a longer idle TTL than rmcp's default.
fn inner_manager() -> LocalSessionManager {
    // Both `LocalSessionManager` and `SessionConfig` are `#[non_exhaustive]`,
    // so struct literals are forbidden outside the crate.  We use
    // `Default::default()` to get a value, then mutate the public fields.
    let mut mgr = LocalSessionManager::default();
    mgr.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
    mgr
}

/// Error returned by [`CappedSessionManager`].
#[derive(Debug)]
pub enum CappedSessionError {
    Inner(LocalSessionManagerError),
    CapReached,
}

impl std::fmt::Display for CappedSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "inner session manager error: {e}"),
            Self::CapReached => write!(
                f,
                "session cap reached ({MAX_SESSIONS} sessions active); try again later"
            ),
        }
    }
}

impl std::error::Error for CappedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::CapReached => None,
        }
    }
}

impl From<LocalSessionManagerError> for CappedSessionError {
    fn from(e: LocalSessionManagerError) -> Self {
        Self::Inner(e)
    }
}

impl From<CappedSessionError> for std::io::Error {
    fn from(e: CappedSessionError) -> Self {
        Self::other(e.to_string())
    }
}

/// A thin wrapper around [`LocalSessionManager`] that rejects new sessions
/// once [`MAX_SESSIONS`] are already live (Mitigation B).
///
/// **Reclamation.** rmcp's `LocalSessionManager` removes a handle from its
/// map only in `close_session`. rmcp's streamable-HTTP service calls that
/// once a served session ends (idle timeout, client gone), but it calls
/// `create_session` for *every* POST that carries no session id and only
/// then checks that the body is `initialize` (and that the protocol header
/// matches). When it is not, the transport is dropped on the error path, the
/// worker exits, and the handle stays in the map for the life of the process.
/// Counted against the cap, those handles reached 256 after a few weeks of
/// uptime and every new `initialize` was refused while `/health` stayed
/// green. This wrapper keeps the worker transport's cancellation token for
/// every session it hands out; the token is cancelled exactly when that
/// transport is dropped, which is when nobody can serve the session any
/// more. Such sessions are closed before every cap check and by a periodic
/// sweeper ([`CappedSessionManager::start`]). A session whose transport is
/// still held — including one sitting idle on a standalone SSE stream for
/// up to [`SESSION_KEEP_ALIVE`] — is never reclaimed here; rmcp's own idle
/// timeout ends it, and only then does its token fire.
///
/// All other methods are pass-throughs.
///
/// The cap is enforced atomically: concurrent `create_session` calls
/// serialize on `create_gate`, so the check-then-insert sequence
/// cannot be interleaved by another task. Without the gate, N parallel
/// initialize requests could each read `count = MAX_SESSIONS - 1`,
/// each see room, and each create a session — overshooting the cap
/// by up to N. The gate adds zero contention on the read-heavy
/// session-lookup paths (`has_session`, `accept_message`, etc.) because
/// they do not take it.
pub struct CappedSessionManager {
    inner: LocalSessionManager,
    limit: usize,
    create_gate: tokio::sync::Mutex<()>,
    /// One probe per session handle in `inner`: true once that session's
    /// worker transport has been dropped.
    workers: Mutex<HashMap<SessionId, WorkerGone>>,
}

type WorkerGone = Box<dyn Fn() -> bool + Send + Sync>;

impl CappedSessionManager {
    /// Construct a new `CappedSessionManager` backed by a [`LocalSessionManager`]
    /// configured with the tightened idle TTL (Mitigation A + B combined).
    pub fn new() -> Self {
        Self::with_limit(MAX_SESSIONS)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            inner: inner_manager(),
            limit,
            create_gate: tokio::sync::Mutex::new(()),
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// The manager the server mounts: [`Self::new`] plus the background
    /// sweeper. The sweeper holds only a weak reference, so it stops once the
    /// service drops the manager.
    pub fn start() -> Arc<Self> {
        let manager = Arc::new(Self::new());
        Self::spawn_sweeper(&manager, SWEEP_INTERVAL);
        manager
    }

    fn spawn_sweeper(manager: &Arc<Self>, every: Duration) -> Option<tokio::task::JoinHandle<()>> {
        // Outside a runtime (a synchronous unit test building the router)
        // there is nothing to sweep on; `create_session` still reclaims.
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let manager = Arc::downgrade(manager);
        Some(runtime.spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(manager) = manager.upgrade() else {
                    break;
                };
                let reclaimed = manager.reap().await;
                if reclaimed > 0 {
                    let live = manager.session_count().await;
                    info!(
                        reclaimed,
                        live, "reclaimed sessions whose worker had exited"
                    );
                }
            }
        }))
    }

    /// A poisoned lock still holds a consistent map: every critical section is
    /// a single insert, remove or scan.
    fn workers(&self) -> MutexGuard<'_, HashMap<SessionId, WorkerGone>> {
        self.workers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn track(&self, id: &SessionId, transport: &SessionTransport) {
        let token = transport.cancel_token();
        self.workers()
            .insert(id.clone(), Box::new(move || token.is_cancelled()));
    }

    /// Closes every session whose worker transport has been dropped and
    /// returns how many it closed. The std lock is never held across an await.
    async fn reap(&self) -> usize {
        let dead = self
            .workers()
            .iter()
            .filter(|(_, gone)| gone())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in &dead {
            if let Err(error) = self.inner.close_session(id).await {
                warn!(%error, "failed to close a session whose worker had exited");
            }
            self.workers().remove(id);
        }
        dead.len()
    }

    async fn session_count(&self) -> usize {
        self.inner.sessions.read().await.len()
    }
}

// Compile-time check that `CappedSessionManager` satisfies the `Send + Sync`
// bounds required by `StreamableHttpService::new`, which wraps the manager in
// an `Arc<M>` shared across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    const fn _check() {
        assert_send_sync::<CappedSessionManager>();
    }
};

impl SessionManager for CappedSessionManager {
    type Error = CappedSessionError;
    type Transport = SessionTransport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Serialize check-and-create so concurrent initializes cannot
        // all observe `count < MAX_SESSIONS` and then each insert. The
        // gate is held only across the count + inner.create_session
        // call (both fast). Other manager operations don't take it.
        let _create_guard = self.create_gate.lock().await;
        self.reap().await;
        let count = self.session_count().await;
        if count >= self.limit {
            warn!(
                count,
                limit = self.limit,
                "session cap reached; rejecting new initialize"
            );
            return Err(CappedSessionError::CapReached);
        }
        let (id, transport) = self.inner.create_session().await?;
        self.track(&id, &transport);
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        Ok(self.inner.initialize_session(id, message).await?)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let closed = self.inner.close_session(id).await;
        self.workers().remove(id);
        Ok(closed?)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.inner.has_session(id).await?)
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_stream(id, message).await?)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        Ok(self.inner.accept_message(id, message).await?)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_standalone_stream(id).await?)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.resume(id, last_event_id).await?)
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self.inner.restore_session(id.clone()).await?;
        if let RestoreOutcome::Restored(transport) = &outcome {
            self.track(&id, transport);
        }
        Ok(outcome)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod reclaim_tests {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    use super::*;

    /// A server with no tools; the transport is what is under test.
    #[derive(Clone)]
    struct Bare;
    impl rmcp::ServerHandler for Bare {}

    fn transport(
        manager: Arc<CappedSessionManager>,
    ) -> StreamableHttpService<Bare, CappedSessionManager> {
        StreamableHttpService::new(|| Ok(Bare), manager, StreamableHttpServerConfig::default())
    }

    fn post(body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn initialize() -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        })
    }

    fn is_cap_reached(result: &Result<(SessionId, SessionTransport), CappedSessionError>) -> bool {
        matches!(result, Err(CappedSessionError::CapReached))
    }

    /// The production outage: a session-less POST that is not `initialize`
    /// makes rmcp create a session and then drop its transport. Before the
    /// fix each one held a slot forever; at the cap, `initialize` was refused.
    #[tokio::test]
    async fn session_less_non_initialize_posts_do_not_burn_slots() {
        let manager = Arc::new(CappedSessionManager::with_limit(2));
        let service = transport(Arc::clone(&manager));
        let tools_list = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        for _ in 0..8 {
            let response = service.handle(post(&tools_list)).await;
            assert!(!response.status().is_success());
        }
        let response = service.handle(post(&initialize())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(manager.session_count().await <= 2);
    }

    #[tokio::test]
    async fn dead_sessions_are_reclaimed_and_free_capacity() {
        let manager = CappedSessionManager::with_limit(2);
        let (first, first_worker) = manager.create_session().await.unwrap();
        let (_second, second_worker) = manager.create_session().await.unwrap();
        assert!(is_cap_reached(&manager.create_session().await));

        drop(first_worker);
        drop(second_worker);
        let (_third, _third_worker) = manager.create_session().await.unwrap();
        assert_eq!(manager.session_count().await, 1);
        assert!(!manager.has_session(&first).await.unwrap());
        assert_eq!(manager.workers().len(), 1);
    }

    #[tokio::test]
    async fn live_sessions_are_never_reclaimed() {
        let manager = CappedSessionManager::with_limit(2);
        let (first, _first_worker) = manager.create_session().await.unwrap();
        let (second, _second_worker) = manager.create_session().await.unwrap();

        assert_eq!(manager.reap().await, 0);
        assert!(manager.has_session(&first).await.unwrap());
        assert!(manager.has_session(&second).await.unwrap());
        assert!(
            is_cap_reached(&manager.create_session().await),
            "the cap must still hold against live sessions"
        );
        assert_eq!(manager.session_count().await, 2);
    }

    /// A served session that is idle (no client traffic, standalone stream or
    /// not) stays until rmcp's own keep-alive ends it.
    #[tokio::test]
    async fn an_initialized_idle_session_survives_sweeps() {
        let manager = Arc::new(CappedSessionManager::with_limit(4));
        let service = transport(Arc::clone(&manager));
        let response = service.handle(post(&initialize())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let id: SessionId = response
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
            .into();
        for _ in 0..3 {
            assert_eq!(manager.reap().await, 0);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(manager.has_session(&id).await.unwrap());
    }

    #[tokio::test]
    async fn the_sweeper_reclaims_without_a_new_initialize() {
        let manager = Arc::new(CappedSessionManager::with_limit(4));
        let (_id, worker) = manager.create_session().await.unwrap();
        let (_live, _live_worker) = manager.create_session().await.unwrap();
        drop(worker);
        let sweeper =
            CappedSessionManager::spawn_sweeper(&manager, Duration::from_millis(10)).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while manager.session_count().await != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the sweeper never reclaimed the dead session"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        sweeper.abort();
    }

    #[tokio::test]
    async fn the_sweeper_stops_when_the_manager_is_dropped() {
        let manager = Arc::new(CappedSessionManager::with_limit(4));
        let sweeper =
            CappedSessionManager::spawn_sweeper(&manager, Duration::from_millis(10)).unwrap();
        drop(manager);
        tokio::time::timeout(Duration::from_secs(5), sweeper)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_closed_session_is_forgotten() {
        let manager = CappedSessionManager::with_limit(4);
        let (id, _worker) = manager.create_session().await.unwrap();
        manager.close_session(&id).await.unwrap();
        assert_eq!(manager.session_count().await, 0);
        assert!(manager.workers().is_empty());
    }
}
