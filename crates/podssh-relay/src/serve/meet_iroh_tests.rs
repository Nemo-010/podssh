//! The parts of iroh's relay route that need no client: the version of the
//! protocol, the head that the hook of access reads, and whom the role
//! admits. Two clients of n0's own code meet in `tests/relay_meet.rs`.

use podssh_ws::http::request::parse_request;

use super::*;
use crate::identity::Identity;
use crate::serve::keys::List;

fn head(extra: &str) -> Request {
    let text = format!(
        "GET /relay HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    );
    parse_request(text.as_bytes()).unwrap()
}

#[test]
fn the_newest_version_that_the_client_offers_is_chosen() {
    // iroh's client offers each, the newest first.
    let both = head("Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1\r\n");
    assert_eq!(version_of(&both), Some(ProtocolVersion::V2));
    let old = head("Sec-WebSocket-Protocol: iroh-relay-v1\r\n");
    assert_eq!(version_of(&old), Some(ProtocolVersion::V1));
    let reversed = head("Sec-WebSocket-Protocol: iroh-relay-v1\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n");
    assert_eq!(version_of(&reversed), Some(ProtocolVersion::V2));
}

#[test]
fn a_client_that_offers_no_version_of_the_protocol_has_none() {
    assert_eq!(version_of(&head("")), None);
    assert_eq!(version_of(&head("Sec-WebSocket-Protocol: derp\r\n")), None);
    assert_eq!(version_of(&head("Sec-WebSocket-Protocol: iroh-relay-v9\r\n")), None);
}

#[test]
fn the_hook_reads_the_request_s_path_and_headers() {
    let parts = parts_of(&head("Authorization: Bearer abc\r\n"));
    assert_eq!(parts.method, http::Method::GET);
    assert_eq!(parts.uri.path(), "/relay");
    assert_eq!(parts.headers.get("authorization").and_then(|v| v.to_str().ok()), Some("Bearer abc"));
}

#[test]
fn whom_it_admits_follows_the_mint() {
    let (listed, other) = (Identity::from_seed(&[1; 32]).public(), Identity::from_seed(&[2; 32]).public());
    assert_eq!(admits(&Mint::Anyone, &other), Ok(()));
    let why = admits(&Mint::Nobody, &listed).expect_err("nobody");
    assert!(why.contains("mints for nobody"), "{why}");
    let dir = std::env::temp_dir().join(format!("podssh-meet-iroh-{}", std::process::id()));
    crate::cache::private_dir(&dir).unwrap();
    let path = dir.join("allow");
    std::fs::write(&path, format!("{} the listed key\n", listed.fingerprint())).unwrap();
    let mint = Mint::Keys(List::File(path));
    assert_eq!(admits(&mint, &listed), Ok(()));
    let why = admits(&mint, &other).expect_err("a key off the list");
    assert!(why.contains(&other.fingerprint()), "{why}");
    let _ = std::fs::remove_dir_all(&dir);
}
