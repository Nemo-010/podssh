//! The counts of each caller of a node's exit (T-721): its connects, its
//! refusals, and the bytes of its sessions through the exit, each way. The
//! bytes are counted at the channel's link, framing with them: the exit's
//! socket must stay a `TcpStream`, which the upgrade in place hands on to
//! the next binary, so no meter can sit on it. A session counts toward its
//! caller once the exit opened its target ([`Tally::attach`]); what its link
//! carried before is added then. At most [`CALLERS_MOST`] callers are
//! kept, the one seen least recently forgotten first, so that keys that
//! come once each hold no memory for ever.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::identity::PublicKey;

/// The callers that the counts keep.
pub const CALLERS_MOST: usize = 1024;

/// One caller's counts.
#[derive(Debug, Default)]
pub struct Caller {
    connects: AtomicU64,
    refusals: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    last_ms: AtomicU64,
}

/// A caller's counts as they read now, for `podssh status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    /// The caller's fingerprint, never more of its key.
    pub key: String,
    pub connects: u64,
    pub refusals: u64,
    /// The caller's bytes to the exit, and the exit's to the caller.
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// When it last connected, was refused, or carried a byte.
    pub last_ms: u64,
}

/// Each caller's counts at one node, shared by its roads.
#[derive(Default)]
pub struct Counts {
    callers: Mutex<HashMap<PublicKey, Arc<Caller>>>,
    /// Moves at each count, so that a writer of the counts writes only
    /// when one moved.
    moved: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Counts {
    /// The counts of `key`, made at its first call; past [`CALLERS_MOST`],
    /// the caller seen least recently is forgotten.
    pub fn caller(&self, key: &PublicKey) -> Arc<Caller> {
        let mut callers = self.callers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(caller) = callers.get(key) {
            return caller.clone();
        }
        if callers.len() >= CALLERS_MOST {
            let oldest = callers.iter().min_by_key(|(_, c)| c.last_ms.load(Ordering::Relaxed)).map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                callers.remove(&oldest);
            }
        }
        let caller = Arc::new(Caller { last_ms: AtomicU64::new(now_ms()), ..Caller::default() });
        callers.insert(*key, caller.clone());
        caller
    }

    /// The exit opened a target for `key`.
    pub fn connected(&self, key: &PublicKey) -> Arc<Caller> {
        let caller = self.caller(key);
        caller.connects.fetch_add(1, Ordering::Relaxed);
        self.touch(&caller);
        caller
    }

    /// The exit refused `key` a target, or could not reach it.
    pub fn refused(&self, key: &PublicKey) {
        let caller = self.caller(key);
        caller.refusals.fetch_add(1, Ordering::Relaxed);
        self.touch(&caller);
    }

    fn touch(&self, caller: &Caller) {
        caller.last_ms.store(now_ms(), Ordering::Relaxed);
        self.moved.fetch_add(1, Ordering::Relaxed);
    }

    /// A number that moves at each count.
    pub fn moved(&self) -> u64 {
        self.moved.load(Ordering::Relaxed)
    }

    /// Each caller's counts, by its fingerprint.
    pub fn rows(&self) -> Vec<Row> {
        let callers = self.callers.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows: Vec<Row> = callers
            .iter()
            .map(|(key, c)| Row {
                key: key.fingerprint(),
                connects: c.connects.load(Ordering::Relaxed),
                refusals: c.refusals.load(Ordering::Relaxed),
                bytes_up: c.up.load(Ordering::Relaxed),
                bytes_down: c.down.load(Ordering::Relaxed),
                last_ms: c.last_ms.load(Ordering::Relaxed),
            })
            .collect();
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        rows
    }
}

/// The bytes of one session's link, held until it is known whose they are.
#[derive(Default)]
pub struct Tally {
    up: AtomicU64,
    down: AtomicU64,
    caller: OnceLock<(Arc<Caller>, Arc<Counts>)>,
}

impl Tally {
    /// The session's bytes are `caller`'s from now, and those it carried
    /// before too.
    pub fn attach(&self, caller: Arc<Caller>, counts: Arc<Counts>) {
        if self.caller.set((caller, counts)).is_ok() {
            self.flush();
        }
    }

    fn add(&self, up: u64, down: u64) {
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
        // A bind between the two steps is caught here or by its own flush:
        // each takes what it swaps, so no byte counts twice.
        if self.caller.get().is_some() {
            self.flush();
        }
    }

    fn flush(&self) {
        let Some((caller, counts)) = self.caller.get() else { return };
        let (up, down) = (self.up.swap(0, Ordering::Relaxed), self.down.swap(0, Ordering::Relaxed));
        if up == 0 && down == 0 {
            return;
        }
        caller.up.fetch_add(up, Ordering::Relaxed);
        caller.down.fetch_add(down, Ordering::Relaxed);
        counts.touch(caller);
    }
}

/// A session's link that counts its bytes into a [`Tally`]: a read is the
/// caller's bytes (up), a write the exit's to it (down).
pub struct Metered<S> {
    inner: S,
    tally: Arc<Tally>,
}

impl<S> Metered<S> {
    pub fn new(inner: S, tally: Arc<Tally>) -> Metered<S> {
        Metered { inner, tally }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len().saturating_sub(before);
        if read > 0 {
            self.tally.add(read as u64, 0);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            self.tally.add(0, *n as u64);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key(b: u8) -> PublicKey {
        PublicKey([b; 32])
    }

    #[test]
    fn each_caller_has_its_own_connects_and_refusals() {
        let counts = Counts::default();
        counts.connected(&key(1));
        counts.refused(&key(1));
        counts.refused(&key(2));
        let rows = counts.rows();
        let one = rows.iter().find(|r| r.key == key(1).fingerprint()).unwrap();
        let two = rows.iter().find(|r| r.key == key(2).fingerprint()).unwrap();
        assert_eq!((one.connects, one.refusals, two.connects, two.refusals), (1, 1, 0, 1));
        assert!(counts.moved() >= 3);
    }

    #[test]
    fn past_the_bound_the_caller_seen_least_recently_goes() {
        let counts = Counts::default();
        for n in 0..CALLERS_MOST {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let caller = counts.caller(&PublicKey(bytes));
            caller.last_ms.store(n as u64 + 10, Ordering::Relaxed);
        }
        counts.refused(&key(0xff));
        let rows = counts.rows();
        assert_eq!(rows.len(), CALLERS_MOST);
        assert!(!rows.iter().any(|r| r.key == PublicKey([0; 32]).fingerprint()), "the oldest went");
    }

    #[tokio::test]
    async fn a_session_s_bytes_go_to_its_caller_once_bound_and_those_before_too() {
        let counts = Arc::new(Counts::default());
        let tally = Arc::new(Tally::default());
        let (ours, mut theirs) = tokio::io::duplex(1024);
        let mut link = Metered::new(ours, tally.clone());
        theirs.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        link.read_exact(&mut got).await.unwrap();
        tally.attach(counts.connected(&key(7)), counts.clone());
        link.write_all(b"back!!").await.unwrap();
        let row = counts.rows().into_iter().find(|r| r.key == key(7).fingerprint()).unwrap();
        assert_eq!((row.bytes_up, row.bytes_down, row.connects), (5, 6, 1));
    }

    #[test]
    fn an_unbound_session_counts_toward_nobody() {
        let counts = Counts::default();
        let tally = Tally::default();
        tally.add(10, 10);
        assert!(counts.rows().is_empty());
    }
}
