//! The probes of the meeting routes (T-720), as iroh's and Tailscale's
//! reports of the network read them. The relay protocol itself, with two
//! clients of n0's own code, is `tests/relay_meet.rs`'s.

use podssh_ws::http::request::parse_request;

use super::*;

fn head(extra: &str) -> Request {
    parse_request(format!("GET /generate_204 HTTP/1.1\r\nHost: relay.test\r\n{extra}\r\n").as_bytes()).unwrap()
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

#[test]
fn the_204_answers_each_challenge_in_its_own_header() {
    let answer = text(no_content(&head("X-Tailscale-Challenge: ts:abc-1\r\nX-Iroh-Challenge: iroh.Z_9\r\n")));
    assert!(answer.starts_with("HTTP/1.1 204 No Content\r\n"), "{answer}");
    assert!(answer.contains("\r\nX-Tailscale-Response: response ts:abc-1\r\n"), "{answer}");
    assert!(answer.contains("\r\nX-Iroh-Response: response iroh.Z_9\r\n"), "{answer}");
    assert!(answer.contains("Cache-Control: no-cache, no-store"), "{answer}");
    assert!(answer.ends_with("\r\n\r\n"), "{answer}");
}

#[test]
fn a_challenge_of_a_wrong_character_or_length_gets_no_answer() {
    // iroh takes no `:` and fewer than 64 characters; Tailscale takes 64.
    let long = "a".repeat(64);
    let asked = format!("X-Iroh-Challenge: a:b\r\nX-Tailscale-Challenge: {long}\r\n");
    let answer = text(no_content(&head(&asked)));
    assert!(!answer.contains("X-Iroh-Response"), "{answer}");
    assert!(answer.contains(&format!("X-Tailscale-Response: response {long}\r\n")), "{answer}");
    let answer = text(no_content(&head(&format!("X-Iroh-Challenge: {long}\r\nX-Tailscale-Challenge: a b\r\n"))));
    assert!(!answer.contains("Response"), "{answer}");
    // None asked: the bare 204.
    assert!(!text(no_content(&head(""))).contains("Response"));
}

#[test]
fn the_ping_is_an_empty_200_that_a_page_may_read() {
    let answer = text(ping());
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains("\r\nAccess-Control-Allow-Origin: *\r\n"), "{answer}");
    assert!(answer.contains("\r\nContent-Length: 0\r\n"), "{answer}");
}

#[test]
fn with_iroh_off_its_routes_are_not_served() {
    // No test of this binary turns iroh on: the relay protocol's own tests
    // run in a binary of their own.
    assert!(!iroh());
    assert!(!serves(RELAY_PATH));
    assert!(!serves(PING_PATH));
    assert_eq!(doc("relay.test:443")["iroh"], Value::Null);
}
