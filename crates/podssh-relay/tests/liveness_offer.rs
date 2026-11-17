//! The pace of an idle node's and an idle operator leg's Pings (T-712), on a
//! paused clock: a stand-in relay that offers `liveness` of 60 s sees one
//! Ping in a minute and no frame else; one that offers nothing sees six.
//!
//! The sockets are `pod-relay`'s: the tests of an offer wait, ignored, until
//! its port reads the offer (the ask of T-712 to PodUtils/podcrates); the
//! tests of no offer hold now, and must hold after the port.
#![cfg(feature = "pair")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::reverse::{self, operator, Handler, Opening, OperatorLimits, SessionId};
use podssh_ws::frame::{decode, encode, Frame, Role, OPCODE_PING, OPCODE_PONG, OPCODE_TEXT};
use podssh_ws::RelaySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// The offer of a relay that hibernates.
const OFFER: &str = r#""liveness":{"pingMs":60000,"frame":"ws-ping"}"#;
/// A session's id, as the relay names it.
const ID: &str = "0123456789abcdef0123456789abcdef";
/// A little past a minute, so that a Ping at 60 s is in.
const MINUTE: Duration = Duration::from_millis(60_500);

/// No session opens on this node: the test's node is idle.
struct Idle;

impl Handler for Idle {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async { Err("no session in this test".to_string()) })
    }
}

/// What the stand-in relay saw of its client.
#[derive(Default)]
struct Seen {
    pings: AtomicUsize,
    others: AtomicUsize,
}

/// A relay that sends `first` as its first text frame, answers each Ping
/// with its Pong, and counts the Pings and any frame else.
fn stand_in(relay: DuplexStream, first: String) -> Arc<Seen> {
    let seen = Arc::new(Seen::default());
    let counted = seen.clone();
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(relay);
        let text = Frame { fin: true, opcode: OPCODE_TEXT, payload: first.into_bytes() };
        if write.write_all(&encode(&text, Role::Server, [0; 4])).await.is_err() {
            return;
        }
        let (mut wire, mut buf) = (Vec::new(), vec![0u8; 4096]);
        loop {
            while let Some((frame, used)) = decode(&wire, Role::Client).expect("a client's frame") {
                wire.drain(..used);
                if frame.opcode != OPCODE_PING {
                    counted.others.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                counted.pings.fetch_add(1, Ordering::SeqCst);
                let pong = Frame { fin: true, opcode: OPCODE_PONG, payload: frame.payload };
                if write.write_all(&encode(&pong, Role::Server, [0; 4])).await.is_err() {
                    return;
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

fn client(ours: DuplexStream) -> RelaySession<DuplexStream> {
    RelaySession::new(ours, Vec::new(), None, Duration::from_secs(30))
}

/// The Pings, and the frames else, of an idle node in a minute, whose
/// relay's `hello` is `hello`.
async fn node_minute(hello: String) -> (usize, usize) {
    let (ours, relay) = tokio::io::duplex(1 << 16);
    let seen = stand_in(relay, hello);
    let node = tokio::spawn(async move {
        let mut stop = std::future::pending::<()>();
        reverse::serve(client(ours), Arc::new(Idle), reverse::settings(), &mut stop).await
    });
    tokio::time::sleep(MINUTE).await;
    assert!(!node.is_finished(), "the idle node stays on its socket");
    node.abort();
    (seen.pings.load(Ordering::SeqCst), seen.others.load(Ordering::SeqCst))
}

/// The same of an operator's leg that is ready, with no input, whose
/// relay's `ready` is `ready`.
async fn operator_minute(ready: String) -> (usize, usize) {
    let (ours, relay) = tokio::io::duplex(1 << 16);
    let seen = stand_in(relay, ready);
    // The input stays open and says nothing: `_input` is held to the end.
    let (io, _input) = tokio::io::duplex(1 << 16);
    let leg = tokio::spawn(operator::exchange(client(ours), io, OperatorLimits::default()));
    tokio::time::sleep(MINUTE).await;
    assert!(!leg.is_finished(), "the idle leg stays on its socket");
    leg.abort();
    (seen.pings.load(Ordering::SeqCst), seen.others.load(Ordering::SeqCst))
}

#[tokio::test(start_paused = true)]
async fn a_node_pings_once_a_minute_where_its_relay_offers_it() {
    let hello = format!(r#"{{"type":"hello","version":1,"maxSessions":64,"maxFrameBytes":65536,{OFFER}}}"#);
    assert_eq!(node_minute(hello).await, (1, 0));
}

#[tokio::test(start_paused = true)]
async fn a_node_pings_each_ten_seconds_with_no_offer() {
    let hello = r#"{"type":"hello","version":1,"maxSessions":64,"maxFrameBytes":65536}"#.to_string();
    assert_eq!(node_minute(hello).await, (6, 0));
}

#[tokio::test(start_paused = true)]
async fn a_node_keeps_ten_seconds_for_an_offer_it_cannot_take() {
    let hello = r#"{"type":"hello","maxSessions":64,"liveness":{"pingMs":5000,"frame":"ws-ping"}}"#.to_string();
    assert_eq!(node_minute(hello).await, (6, 0));
}

#[tokio::test(start_paused = true)]
async fn an_operator_leg_pings_once_a_minute_where_its_relay_offers_it() {
    let ready = format!(r#"{{"type":"ready","id":"{ID}",{OFFER}}}"#);
    assert_eq!(operator_minute(ready).await, (1, 0));
}

#[tokio::test(start_paused = true)]
async fn an_operator_leg_pings_each_ten_seconds_with_no_offer() {
    let ready = format!(r#"{{"type":"ready","id":"{ID}"}}"#);
    assert_eq!(operator_minute(ready).await, (6, 0));
}
