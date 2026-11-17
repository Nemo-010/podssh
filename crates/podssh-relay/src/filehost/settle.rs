//! The writes of a carrier that are under way, so that an end that leaves
//! (a client's Close) waits until its last note is on the board: the
//! process would otherwise end with the note in a pipe or a request.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// How often [`Sends::settled`] looks.
const LOOK: Duration = Duration::from_millis(50);

/// The writes under way, and when one last started or ended.
pub struct Sends {
    under_way: AtomicUsize,
    last: Mutex<Instant>,
}

impl Default for Sends {
    fn default() -> Sends {
        Sends { under_way: AtomicUsize::new(0), last: Mutex::new(Instant::now()) }
    }
}

/// One write under way, until it is dropped.
pub struct OnWay<'a>(&'a Sends);

impl Drop for OnWay<'_> {
    fn drop(&mut self) {
        self.0.stamp();
        self.0.under_way.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Sends {
    fn stamp(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    /// A write starts.
    pub fn start(&self) -> OnWay<'_> {
        self.under_way.fetch_add(1, Ordering::SeqCst);
        self.stamp();
        OnWay(self)
    }

    /// Until no write is under way and none started for `quiet`, within
    /// `limit`: true when it settled. It first waits `quiet`, so that bytes
    /// still on their way to a write (a link's pipe, its gather) start it.
    pub async fn settled(&self, quiet: Duration, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        tokio::time::sleep(quiet.min(limit)).await;
        loop {
            let still = self.last.lock().unwrap_or_else(|e| e.into_inner()).elapsed() < quiet;
            if self.under_way.load(Ordering::SeqCst) == 0 && !still {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            tokio::time::sleep(LOOK).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_write_under_way_holds_the_end_until_it_ends() {
        let sends = Arc::new(Sends::default());
        let held = sends.clone();
        let writer = tokio::spawn(async move {
            let _on = held.start();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let started = Instant::now();
        assert!(sends.settled(Duration::from_secs(1), Duration::from_secs(30)).await);
        assert!(started.elapsed() >= Duration::from_secs(6), "{:?}", started.elapsed());
        writer.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_never_ends_is_left_at_the_limit() {
        let sends = Sends::default();
        let _on = sends.start();
        assert!(!sends.settled(Duration::from_secs(1), Duration::from_secs(3)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_under_way_settles_after_the_quiet() {
        let sends = Sends::default();
        tokio::time::sleep(Duration::from_secs(10)).await;
        let started = Instant::now();
        assert!(sends.settled(Duration::from_secs(1), Duration::from_secs(30)).await);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
