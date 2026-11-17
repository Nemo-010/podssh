use std::time::Duration;

use serde_json::{json, Value};

use super::*;

fn member(text: &str) -> Value {
    serde_json::from_str(text).expect("a vector is JSON")
}

/// Each vector of `docs/relay.md` gives its pace, and one that is not
/// taken as it stood gives a line.
#[test]
fn the_vectors_give_their_pace() {
    for (text, want) in VECTORS {
        let heard = of(Some(&member(text)));
        let want = want.map_or(Pace::DEFAULT.every, Duration::from_millis);
        assert_eq!(heard.pace.every, want, "{text}");
        let taken = heard.offered;
        assert_eq!(heard.line.is_none(), taken || *text == "null", "{text}: {heard:?}");
    }
}

/// An offered pace allows three silent checks, as podssh's own.
#[test]
fn an_offer_keeps_three_silent_checks() {
    let heard = of(Some(&json!({"pingMs": 60000, "frame": "ws-ping"})));
    assert_eq!(heard.pace, Pace { every: Duration::from_secs(60), allowed: 3 });
    assert!(heard.offered);
}

/// No member, and null, are a relay of before: 10 s, and nothing said.
#[test]
fn no_member_keeps_ten_seconds() {
    for value in [None, Some(Value::Null)] {
        let heard = of(value.as_ref());
        assert_eq!(heard.pace, Pace::DEFAULT);
        assert_eq!(heard.pace.every, Duration::from_secs(10));
        assert!(!heard.offered && heard.line.is_none());
    }
}

/// A line names what was wrong, and a relay's value cannot make it long
/// nor break it.
#[test]
fn a_line_names_the_fault_on_one_line() {
    let heard = of(Some(&json!({"pingMs": 5000, "frame": "ws-ping"})));
    assert!(heard.line.as_deref().unwrap().contains("under 30 s"), "{heard:?}");
    let long = "x\n".repeat(500);
    let heard = of(Some(&json!({"pingMs": 60000, "frame": long})));
    let line = heard.line.unwrap();
    assert!(!line.contains('\n') && line.len() < 200, "{line}");
}

/// `forward.liveness` of `/relays.json`, and nothing from a body that is
/// no JSON or has no `forward`.
#[test]
fn the_forward_road_reads_relays_json() {
    let body = br#"{"forward":{"layer":true,"liveness":{"pingMs":60000,"frame":"ws-ping"}}}"#;
    assert_eq!(of_relays(body).pace.every, Duration::from_secs(60));
    let bodies: [&[u8]; 3] = [b"not json", br#"{"forward":{"layer":true}}"#, br#"{"liveness":{"pingMs":60000}}"#];
    for body in bodies {
        assert_eq!(of_relays(body), of(None));
    }
}

/// A `hello` keeps the member among the fields that podssh does not model.
#[cfg(feature = "pair")]
#[test]
fn a_hello_carries_the_offer() {
    let hello: crate::reverse::control::Hello =
        serde_json::from_str(r#"{"maxSessions":64,"liveness":{"pingMs":60000,"frame":"ws-ping"}}"#).unwrap();
    assert_eq!(of_hello(&hello).pace.every, Duration::from_secs(60));
    let hello: crate::reverse::control::Hello = serde_json::from_str(r#"{"maxSessions":64}"#).unwrap();
    assert_eq!(of_hello(&hello).pace, Pace::DEFAULT);
}

/// A line goes once for the process, whatever offers come after.
#[test]
fn a_line_is_said_once() {
    let bad = of(Some(&json!({"pingMs": "soon", "frame": "ws-ping"})));
    let mut said = Vec::new();
    for _ in 0..3 {
        let pace = say_once(&bad, |line| said.push(line.to_string()));
        assert_eq!(pace, Pace::DEFAULT);
    }
    assert!(say_once(&of(None), |_| panic!("no line to say")) == Pace::DEFAULT);
    // No other test of this process says a line.
    assert_eq!(said.len(), 1, "{said:?}");
}
