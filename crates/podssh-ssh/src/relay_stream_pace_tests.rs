//! The pace of the forward road's Pings (T-712): an idle session pings a
//! relay that offered 60 s once a minute, and podssh's 10 s six times, with
//! no frame else. On a paused clock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame::{decode, encode, Frame, Role, OPCODE_PING, OPCODE_PONG};
use podssh_ws::RelaySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::{spawn, spawn_paced, ASK};

/// What a stand-in relay saw of its client.
#[derive(Default)]
struct Seen {
    pings: AtomicUsize,
    others: AtomicUsize,
}

/// A relay that answers each Ping with its Pong and counts what came: the
/// Pings of liveness, and any frame else (a question of podssh's is no
/// liveness Ping, and an idle session asks none).
fn stand_in(relay: DuplexStream) -> Arc<Seen> {
    let seen = Arc::new(Seen::default());
    let counted = seen.clone();
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(relay);
        let mut wire = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            while let Some((frame, used)) = decode(&wire, Role::Client).expect("a client's frame") {
                wire.drain(..used);
                if frame.opcode == OPCODE_PING && frame.payload != ASK {
                    counted.pings.fetch_add(1, Ordering::SeqCst);
                } else {
                    counted.others.fetch_add(1, Ordering::SeqCst);
                }
                if frame.opcode == OPCODE_PING {
                    let pong = Frame { fin: true, opcode: OPCODE_PONG, payload: frame.payload };
                    if write.write_all(&encode(&pong, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
            }
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => wire.extend_from_slice(&buf[..n]),
            }
        }
    });
    seen
}

/// The frames that an idle session sends in a minute, at `pace` (`None`:
/// podssh's own).
async fn a_minute(pace: Option<Duration>) -> (usize, usize) {
    let (ours, relay) = tokio::io::duplex(1 << 16);
    let seen = stand_in(relay);
    let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(30));
    let (_ssh, _status) = match pace {
        Some(every) => spawn_paced(session, every, 3),
        None => spawn(session),
    };
    // A little past the minute, so that the Ping at 60 s is in.
    tokio::time::sleep(Duration::from_millis(60_500)).await;
    (seen.pings.load(Ordering::SeqCst), seen.others.load(Ordering::SeqCst))
}

#[tokio::test(start_paused = true)]
async fn a_relay_that_offers_a_minute_sees_one_ping() {
    assert_eq!(a_minute(Some(Duration::from_secs(60))).await, (1, 0));
}

#[tokio::test(start_paused = true)]
async fn a_relay_that_offers_nothing_sees_six() {
    assert_eq!(a_minute(None).await, (6, 0));
}
