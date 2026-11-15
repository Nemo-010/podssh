//! A QUIC endpoint whose way fails each read must not spin a core (T-787).
//! noq's receive loop takes ECONNRESET and EMSGSIZE as noise and reads again
//! at once, before its own bound of work; a way whose reads keep failing so
//! would keep one thread of the runtime busy for ever, as osewa found of
//! quinn's. The stand-in way here fails each read with ECONNRESET; the
//! process's CPU over a few seconds tells whether the endpoint spins.

#![cfg(all(feature = "quic", unix))]

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use pod_core::{Datagrams, RecvMeta, Transmit};

/// A way that sends nothing and fails each read with ECONNRESET.
struct Failing {
    reads: AtomicU64,
}

impl fmt::Debug for Failing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Failing")
    }
}

impl Datagrams for Failing {
    fn poll_writable(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
        Ok(())
    }

    fn poll_recv(&self, _: &mut Context<'_>, _: &mut [IoSliceMut<'_>], _: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok((Ipv4Addr::LOCALHOST, 9).into())
    }
}

/// The process's CPU time, user and system.
fn cpu() -> Duration {
    // SAFETY: getrusage fills the struct that it is given.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
    let of = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    of(usage.ru_utime) + of(usage.ru_stime)
}

// It fails until podssh takes the tag of PodUtils/podcrates whose pod-quic
// bounds the failed reads (T-787, COORD-075): the socket is pod-quic's.
#[test]
#[ignore = "fails until pod-quic bounds a way's failed reads (T-787, COORD-075)"]
fn quic_socket_fails_each_read_and_the_endpoint_does_not_spin() {
    // A runtime of our own, shut down in the background at the end: a worker
    // that spins never yields, and a drop that waits for it would hang.
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let way = Arc::new(Failing { reads: AtomicU64::new(0) });
    let endpoint = runtime.block_on(async { pod_quic::over(way.clone(), None) }).expect("an endpoint");
    std::thread::sleep(Duration::from_millis(200));
    let (before, reads_before) = (cpu(), way.reads.load(Ordering::Relaxed));
    let window = Duration::from_secs(3);
    std::thread::sleep(window);
    let (spent, reads) = (cpu() - before, way.reads.load(Ordering::Relaxed) - reads_before);
    eprintln!("the failing way: {reads} reads and {spent:?} of CPU in {window:?}");
    // A quarter of one core: an endpoint that waits uses next to none, one
    // that spins uses each tick of a thread.
    if spent >= window / 4 {
        // A spinning driver holds the endpoint's lock for ever: a drop of the
        // endpoint, or of the runtime, would hang the test instead of failing it.
        std::mem::forget(endpoint);
        std::mem::forget(runtime);
        panic!("the endpoint spun: {spent:?} of CPU and {reads} failed reads in {window:?}");
    }
    drop(endpoint);
    runtime.shutdown_background();
}
