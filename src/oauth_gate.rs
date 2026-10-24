//! When `/oauth/callback` may act.
//!
//! The callback replaces the server's Withings credential and cannot carry the
//! MCP bearer, so the configured `state` is all that stands between the origin
//! and a stranger's account. That value is static: it is in the consent URL,
//! so it is in a browser history and in Withings' own logs. A static secret
//! that is accepted forever is accepted by anyone who has ever seen one
//! consent URL.
//!
//! So a configured state is necessary and no longer sufficient. The callback
//! is open only for a window after the process starts, it closes for good on
//! the first authorisation it adopts, and it closes after a handful of wrong
//! `state` values. Re-authorising means restarting the process and consenting
//! inside the window, which is the one moment someone is watching.
//!
//! Every closed answer is the same `404` the callback gives when no state is
//! configured, so a probe cannot tell "closed" from "never on".

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::warn;

/// How long the callback stays open after startup when nothing says otherwise.
pub const DEFAULT_WINDOW: Duration = Duration::from_mins(10);

/// The longest window a deployment may configure. Longer is a standing door
/// again, which is what the window exists to remove.
pub const MAX_WINDOW: Duration = Duration::from_hours(1);

/// Wrong `state` values tolerated before the callback closes.
pub const MAX_STATE_FAILURES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    /// A correct `state` is being exchanged. A second one waits its turn
    /// rather than racing to be the credential that is stored last.
    InFlight,
    Closed(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    Adopted,
    Expired,
    TooManyFailures,
}

impl Reason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Adopted => "adopted",
            Self::Expired => "window_elapsed",
            Self::TooManyFailures => "too_many_state_failures",
        }
    }
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    failures: u32,
}

#[derive(Debug)]
pub struct CallbackGate {
    closes_at: Instant,
    inner: Mutex<Inner>,
}

/// What the callback should do with one request.
#[derive(Debug)]
pub enum Admission {
    /// Closed, for whatever reason. Answer as if the callback were off.
    Closed,
    /// Open, and the `state` was wrong.
    WrongState,
    /// Another correct `state` is mid-exchange.
    Busy,
    /// The caller holds the single exchange slot until the ticket drops.
    Proceed(Ticket),
}

/// The exchange slot. Dropping it releases the slot whatever happened to the
/// request holding it — a browser that disconnects mid-exchange drops the
/// handler future, and a slot released only on the happy path would leave the
/// callback `InFlight`, answering `409` past its window, until a restart.
#[derive(Debug)]
pub struct Ticket {
    gate: Arc<CallbackGate>,
    adopted: bool,
}

impl Ticket {
    /// A new authorisation was stored: the callback closes for good when this
    /// ticket drops.
    pub const fn adopted(&mut self) {
        self.adopted = true;
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.gate.finish(self.adopted);
    }
}

impl CallbackGate {
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            closes_at: Instant::now() + window,
            inner: Mutex::new(Inner {
                phase: Phase::Open,
                failures: 0,
            }),
        }
    }

    /// Whether the callback is still open, closing it if the window elapsed.
    fn open(&self, inner: &mut Inner) -> bool {
        if matches!(inner.phase, Phase::Closed(_)) {
            return false;
        }
        if Instant::now() >= self.closes_at && inner.phase == Phase::Open {
            close(inner, Reason::Expired);
            return false;
        }
        true
    }

    /// Admit a request whose `state` has already been compared.
    ///
    /// The comparison happens outside the gate so that its timing does not
    /// depend on the gate's lock. A wrong `state` counts towards closing; a
    /// right one claims the single exchange slot. A request with no `state`
    /// at all is not a guess and the caller must not bring it here, or five
    /// scanner hits would close the callback on the operator.
    pub fn admit(self: &Arc<Self>, state_matches: bool) -> Admission {
        let mut inner = self.lock();
        if !self.open(&mut inner) {
            return Admission::Closed;
        }
        if !state_matches {
            inner.failures += 1;
            if inner.failures >= MAX_STATE_FAILURES {
                close(&mut inner, Reason::TooManyFailures);
            }
            return Admission::WrongState;
        }
        if inner.phase == Phase::InFlight {
            return Admission::Busy;
        }
        inner.phase = Phase::InFlight;
        drop(inner);
        Admission::Proceed(Ticket {
            gate: Arc::clone(self),
            adopted: false,
        })
    }

    /// Whether the callback would admit a correct `state` right now. Checked
    /// before the `state` comparison so a closed callback answers `404`
    /// without doing any work.
    pub fn is_open(&self) -> bool {
        let mut inner = self.lock();
        self.open(&mut inner)
    }

    /// Release the slot [`Self::admit`] handed out. An adopted authorisation
    /// closes the callback for good; a failed exchange reopens it, and the
    /// next request finds out whether the window elapsed meanwhile.
    fn finish(&self, adopted: bool) {
        let mut inner = self.lock();
        if adopted {
            close(&mut inner, Reason::Adopted);
        } else if inner.phase == Phase::InFlight {
            inner.phase = Phase::Open;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a panic mid-update. Failing closed is the
        // only safe reading of a gate whose state is unknown.
        self.inner.lock().unwrap_or_else(|poisoned| {
            let mut inner = poisoned.into_inner();
            inner.phase = Phase::Closed(Reason::TooManyFailures);
            inner
        })
    }
}

fn close(inner: &mut Inner, reason: Reason) {
    if inner.phase != Phase::Closed(reason) {
        warn!(reason = reason.as_str(), "oauth callback closed");
    }
    inner.phase = Phase::Closed(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(window: Duration) -> Arc<CallbackGate> {
        Arc::new(CallbackGate::new(window))
    }

    #[test]
    fn the_default_window_is_ten_minutes() {
        assert_eq!(DEFAULT_WINDOW, Duration::from_secs(600));
    }

    #[test]
    fn an_adopted_authorisation_closes_the_callback_for_good() {
        let gate = gate(DEFAULT_WINDOW);
        let admission = gate.admit(true);
        assert!(matches!(admission, Admission::Proceed(_)));
        if let Admission::Proceed(mut ticket) = admission {
            ticket.adopted();
        }
        assert!(!gate.is_open());
        assert!(matches!(gate.admit(true), Admission::Closed));
    }

    #[test]
    fn a_failed_exchange_leaves_the_callback_open() {
        let gate = gate(DEFAULT_WINDOW);
        drop(gate.admit(true));
        assert!(matches!(gate.admit(true), Admission::Proceed(_)));
    }

    #[test]
    fn a_second_correct_state_waits_for_the_first() {
        let gate = gate(DEFAULT_WINDOW);
        let first = gate.admit(true);
        assert!(matches!(first, Admission::Proceed(_)));
        assert!(matches!(gate.admit(true), Admission::Busy));
        // The slot is released by the ticket, not by a call someone must
        // remember to make.
        drop(first);
        assert!(matches!(gate.admit(true), Admission::Proceed(_)));
    }

    #[test]
    fn a_slot_released_in_flight_still_closes_after_the_window() {
        let gate = gate(Duration::ZERO);
        // Constructed open-at-zero: claim the slot by hand, as a request
        // admitted just before the window ended would hold it.
        gate.lock().phase = Phase::InFlight;
        drop(Ticket {
            gate: Arc::clone(&gate),
            adopted: false,
        });
        assert!(!gate.is_open());
    }

    #[test]
    fn repeated_wrong_states_close_the_callback() {
        let gate = gate(DEFAULT_WINDOW);
        for _ in 1..MAX_STATE_FAILURES {
            assert!(matches!(gate.admit(false), Admission::WrongState));
            assert!(gate.is_open());
        }
        assert!(matches!(gate.admit(false), Admission::WrongState));
        assert!(!gate.is_open());
        assert!(matches!(gate.admit(false), Admission::Closed));
        // Even the right value is refused now.
        assert!(matches!(gate.admit(true), Admission::Closed));
    }

    #[test]
    fn the_window_closes_the_callback() {
        let gate = gate(Duration::ZERO);
        assert!(!gate.is_open());
        assert!(matches!(gate.admit(true), Admission::Closed));
    }
}
