//! T-803: the rate of podssh's relay role on the loopback, in the shape of
//! the owner's dig study (podcrates' `docs/research/dig-study.md`): plain
//! `ws://`, 16 MiB in frames of 49,152 bytes, many runs, a new session for
//! each. The study saw two modes, near 75 and near 330 MiB/s. This run
//! prints each run's rate, the target's time to take the last byte, so that
//! a slow mode shows and can be told from a fast one. Ignored: a
//! measurement, run by hand in a release build:
//!
//!     cargo test --release -p podssh-relay --features serve,plain-ws --test relay_serve_rate -- --ignored --nocapture
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use role_harness::Role;
use tokio::io::AsyncReadExt;
use tokio::sync::Notify;
use tokio::time::Instant;

const MIB: usize = 1 << 20;
const SIZE: usize = 16 * MIB;
const CHUNK: usize = 49_152;
const RUNS: usize = 20;

/// A target on the loopback that reads its one client and counts the bytes,
/// and tells `done` when `size` came.
async fn sink(size: usize) -> (u16, Arc<AtomicUsize>, Arc<Notify>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (read, done) = (Arc::new(AtomicUsize::new(0)), Arc::new(Notify::new()));
    let (counted, told) = (read.clone(), done.clone());
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else { return };
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if counted.fetch_add(n, Ordering::SeqCst) + n >= size {
                        told.notify_one();
                    }
                }
            }
        }
    });
    (port, read, done)
}

/// One run: a session to a new sink, `SIZE` bytes sent in `CHUNK` frames,
/// and the time until the sink took the last of them, in MiB/s.
async fn run(role: &Role) -> f64 {
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let (port, read, done) = sink(SIZE).await;
    let session = role.socket(&format!("/connect/127.0.0.1/{port}"), &token).await.expect("a forward session");
    let chunk = vec![0xa5u8; CHUNK];
    let started = Instant::now();
    let sender = async {
        let mut sent = 0;
        while sent < SIZE {
            let n = CHUNK.min(SIZE - sent);
            session.send_binary(&chunk[..n]).await.expect("a frame sent");
            sent += n;
        }
    };
    let finished = async { tokio::time::timeout(Duration::from_secs(60), done.notified()).await };
    let ((), took) = tokio::join!(sender, finished);
    took.expect("the sink took each byte within 60 s");
    let secs = started.elapsed().as_secs_f64();
    assert_eq!(read.load(Ordering::SeqCst), SIZE);
    let _ = session.send_close(1000, "").await;
    SIZE as f64 / MIB as f64 / secs
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: run by hand in a release build"]
async fn the_rate_of_the_role_on_the_loopback_in_the_study_s_shape() {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let mut rates = Vec::new();
    for i in 1..=RUNS {
        let rate = run(&role).await;
        println!("run {i:2}: {rate:8.1} MiB/s");
        rates.push(rate);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = rates[RUNS / 2];
    println!("min {:.1}, median {median:.1}, max {:.1} MiB/s", rates[0], rates[RUNS - 1]);
    let slow: Vec<f64> = rates.iter().copied().filter(|r| *r < median / 2.0).collect();
    println!("runs under half the median: {}", slow.len());
}
