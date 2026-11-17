//! The process's wall clock, in milliseconds since the epoch, that a node's
//! pairs and the relay role's pairs and tokens read alike (T-710). A test of
//! months cannot wait for them: on its own thread, it makes this clock
//! follow tokio's, which a paused runtime moves by days in a moment, so that
//! each sleep of a task and each read of the clock move together.
//!
//! Only a function of this library that the binary never calls does that,
//! for the thread that called it and until its guard drops: no variable, no
//! file and no flag changes the time of a released binary.

use std::cell::Cell;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    /// The time of this thread at tokio's instant, while a test follows it.
    static FOLLOW: Cell<Option<(i64, tokio::time::Instant)>> = const { Cell::new(None) };
}

/// Milliseconds since the Unix epoch, now: the system's clock, or the one
/// that a test of this thread follows.
pub fn now_ms() -> i64 {
    match FOLLOW.with(Cell::get) {
        Some((base, since)) => {
            let gone = tokio::time::Instant::now().saturating_duration_since(since);
            base.saturating_add(i64::try_from(gone.as_millis()).unwrap_or(i64::MAX))
        }
        None => wall_ms(),
    }
}

/// The system's clock, which no test moves.
pub fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).unwrap_or(0)
}

/// While it lives, [`now_ms`] on this thread is `base_ms` plus the time that
/// tokio's clock went on since; its drop gives the system's clock back.
/// Not `Send`: the thread that made it drops it.
#[doc(hidden)]
#[must_use = "the clock follows tokio's only while the guard lives"]
pub struct Following(PhantomData<*const ()>);

impl Drop for Following {
    fn drop(&mut self) {
        FOLLOW.with(|follow| follow.set(None));
    }
}

/// For a test alone: [`now_ms`] on this thread follows tokio's clock from
/// `base_ms` on, so that a paused runtime moves both (T-710). Call it inside
/// the runtime whose clock is followed, on the thread that runs its tasks: a
/// runtime of the current thread.
#[doc(hidden)]
pub fn follow_tokio(base_ms: i64) -> Following {
    FOLLOW.with(|follow| follow.set(Some((base_ms, tokio::time::Instant::now()))));
    Following(PhantomData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn a_followed_clock_moves_with_a_paused_runtime_and_ends_with_its_guard() {
        let guard = follow_tokio(1_000);
        assert_eq!(now_ms(), 1_000);
        tokio::time::sleep(Duration::from_secs(90 * 24 * 3600)).await;
        assert_eq!(now_ms(), 1_000 + 90 * 24 * 3_600_000, "90 days on, in a moment");
        drop(guard);
        let wall = wall_ms();
        assert!((now_ms() - wall).abs() < 60_000, "the system's clock again");
    }

    #[test]
    fn another_thread_keeps_the_systems_clock() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
        let _guard = runtime.block_on(async { follow_tokio(5) });
        let other = std::thread::spawn(|| (now_ms() - wall_ms()).abs()).join().unwrap();
        assert!(other < 60_000, "only the thread that follows");
        assert_eq!(runtime.block_on(async { now_ms() }), 5);
    }
}
