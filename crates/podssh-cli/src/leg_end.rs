//! How long the last leg of a session may take to end after the session:
//! its Close and the relay's answer. A road that answers more slowly (a
//! bucket, T-725) sets its own bound once for the process.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The bound of each road but a slower one's.
const LEG_END: Duration = Duration::from_secs(12);
/// The bound that a road set, in milliseconds; 0 for none.
static SET_MS: AtomicU64 = AtomicU64::new(0);

/// The last leg of each session of this process may take `wait` to end.
pub(crate) fn set(wait: Duration) {
    SET_MS.store(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX), Ordering::SeqCst);
}

/// The bound now.
pub(crate) fn now() -> Duration {
    match SET_MS.load(Ordering::SeqCst) {
        0 => LEG_END,
        ms => Duration::from_millis(ms),
    }
}
