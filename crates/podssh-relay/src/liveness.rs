//! The pace of the Pings that a relay asks of its clients (T-712). A relay
//! that runs as a Durable Object with WebSocket hibernation sleeps while its
//! sockets are quiet, and the runtime answers a protocol Ping without waking
//! it; a Ping each 10 s still costs it six wakes a minute where a data frame
//! or a text frame would wake it. So such a relay offers a slower pace:
//!
//! ```json
//! "liveness": {"pingMs": 60000, "frame": "ws-ping"}
//! ```
//!
//! in a node's `hello`, in the `ready` of an operator's leg, and as
//! `forward.liveness` of its `/relays.json` for the forward road. A client
//! that reads it pings at that pace with WebSocket Ping frames alone, and
//! allows [`ALLOWED`] silent checks. The member is a hint
//! (`pod_session::answer`): absent, or null, keeps podssh's 10 s; one of a
//! wrong type, a frame of another kind, or a pace under [`FLOOR`] is ignored
//! and keeps 10 s too, as 10 s works with each relay; a pace over [`MOST`] is
//! held to [`MOST`], as a Pong must come within the forward road's 90 s
//! idle read limit. A line of each offer that was not taken as it stood goes
//! out once for the process ([`say_once`]).
//!
//! `docs/relay.md` ("A relay that sleeps between frames") states the words
//! and the vectors of [`VECTORS`]. The node's and the operator's sockets are
//! `pod-relay`'s, which takes this reading in its port; the forward road of
//! `podssh ssh` takes a pace by `podssh_ssh::relay_stream::spawn_paced`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

/// The member of a `hello`, a `ready` and `forward` of `/relays.json`.
pub const FIELD: &str = "liveness";
/// The pace in milliseconds, a whole number.
pub const PING_MS: &str = "pingMs";
/// The kind of frame that the client sends.
pub const FRAME: &str = "frame";
/// The one kind: a WebSocket Ping, which a hibernating relay's runtime
/// answers without waking the relay.
pub const WS_PING: &str = "ws-ping";
/// The slowest pace that a client takes; a slower offer is held to it.
pub const MOST: Duration = Duration::from_secs(60);
/// The fastest offered pace that a client takes; a faster one is ignored,
/// as it would only be a pace of a relay's mistake.
pub const FLOOR: Duration = Duration::from_secs(30);
/// The silent checks in a row that end a socket at an offered pace.
pub const ALLOWED: u32 = 3;

/// How often a client pings, and how many silent checks in a row end it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pace {
    pub every: Duration,
    pub allowed: u32,
}

impl Pace {
    /// podssh's pace where no relay offered one: 10 s, 3 silent checks.
    pub const DEFAULT: Pace = Pace { every: podssh_ws::LIVENESS_EVERY, allowed: podssh_ws::LIVENESS_ALLOWED };
}

impl Default for Pace {
    fn default() -> Pace {
        Pace::DEFAULT
    }
}

/// What a client took of a relay's member: the pace, and a line where the
/// offer was not taken as it stood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    pub pace: Pace,
    /// Whether the relay's pace is the one taken, or held to [`MOST`].
    pub offered: bool,
    pub line: Option<String>,
}

impl Heard {
    fn none() -> Heard {
        Heard { pace: Pace::DEFAULT, offered: false, line: None }
    }

    fn ignored(why: String) -> Heard {
        let every = Pace::DEFAULT.every.as_secs();
        let line = format!("the relay's liveness offer is ignored: {why}; podssh pings each {every} s");
        Heard { pace: Pace::DEFAULT, offered: false, line: Some(line) }
    }
}

/// The pace that `value`, a relay's member [`FIELD`], offers.
pub fn of(value: Option<&Value>) -> Heard {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Heard::none() };
    let Some(offer) = value.as_object() else { return Heard::ignored("it is not an object".into()) };
    match offer.get(FRAME) {
        Some(Value::String(kind)) if kind == WS_PING => {}
        Some(other) => return Heard::ignored(format!("its frame {} is not {WS_PING:?}", shown(other))),
        None => return Heard::ignored(format!("it names no frame, and podssh sends {WS_PING:?} alone")),
    }
    let Some(ms) = offer.get(PING_MS).and_then(Value::as_u64) else {
        let given = offer.get(PING_MS).map_or_else(|| "none".to_string(), shown);
        return Heard::ignored(format!("its {PING_MS} {given} is not a whole number of milliseconds"));
    };
    let every = Duration::from_millis(ms);
    if every < FLOOR {
        return Heard::ignored(format!("its {PING_MS} {ms} is under {} s", FLOOR.as_secs()));
    }
    if every > MOST {
        let line = format!(
            "the relay offers a ping each {} s; podssh pings each {} s, so that a dead link is found in time",
            ms / 1000,
            MOST.as_secs()
        );
        return Heard { pace: Pace { every: MOST, allowed: ALLOWED }, offered: false, line: Some(line) };
    }
    Heard { pace: Pace { every, allowed: ALLOWED }, offered: true, line: None }
}

/// The pace of a relay's text frame: a node's `hello`, or an operator's
/// `ready`, as JSON's object.
pub fn of_frame(frame: &serde_json::Map<String, Value>) -> Heard {
    of(frame.get(FIELD))
}

/// The pace that the body of a host's `/relays.json` offers its forward
/// road: `forward.liveness`. A body that is no JSON offers none.
pub fn of_relays(body: &[u8]) -> Heard {
    let doc: Value = serde_json::from_slice(body).unwrap_or_default();
    of(doc.get("forward").and_then(|forward| forward.get(FIELD)))
}

/// The pace that a node's `hello` offers.
#[cfg(feature = "pair")]
pub fn of_hello(hello: &crate::reverse::control::Hello) -> Heard {
    of_frame(&hello.extra)
}

/// Whether the line of an offer was said in this process.
static SAID: AtomicBool = AtomicBool::new(false);

/// Give `heard`'s line to `say`, the first time that a line came in this
/// process: a relay says the same at each socket, and its line once is
/// enough. Returns the pace.
pub fn say_once(heard: &Heard, say: impl FnOnce(&str)) -> Pace {
    if let Some(line) = &heard.line
        && !SAID.swap(true, Ordering::SeqCst)
    {
        say(line);
    }
    heard.pace
}

/// A relay's value as a line shows it: JSON, on one line, cut short.
fn shown(value: &Value) -> String {
    let text = pod_core::text::one_line(&value.to_string());
    text.chars().take(40).collect()
}

/// The test vectors of `docs/relay.md`: a member, as a relay writes it, and
/// the pace in milliseconds that a client takes (`None`: podssh's 10 s).
pub const VECTORS: &[(&str, Option<u64>)] = &[
    (r#"{"pingMs":60000,"frame":"ws-ping"}"#, Some(60_000)),
    (r#"{"pingMs":30000,"frame":"ws-ping"}"#, Some(30_000)),
    (r#"{"pingMs":45000,"frame":"ws-ping","later":1}"#, Some(45_000)),
    (r#"{"pingMs":120000,"frame":"ws-ping"}"#, Some(60_000)),
    (r#"{"pingMs":29999,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":"60000","frame":"ws-ping"}"#, None),
    (r#"{"pingMs":60000.5,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":-60000,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":60000,"frame":"text"}"#, None),
    (r#"{"pingMs":60000}"#, None),
    (r#"60000"#, None),
    (r#"null"#, None),
];

#[cfg(test)]
#[path = "liveness_tests.rs"]
mod tests;
