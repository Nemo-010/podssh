//! The PROXY header of T-807 against haproxy's own bytes; its rule of whom
//! it trusts, on real sockets, is `tests/serve_proxy_header.rs`'s.

use std::net::IpAddr;

use super::*;

/// haproxy 2.8.30's `send-proxy` for a client at 127.0.0.2:38265 of its
/// frontend at 127.0.0.1:18401, captured once, then the client's `HELLO`.
const HAPROXY_V1: &str =
    "50524f58592054435034203132372e302e302e32203132372e302e302e312033383236352031383430310d0a48454c4c4f";
/// Its `send-proxy-v2` for a client at 127.0.0.2, then `HELLO`.
const HAPROXY_V2: &str = "0d0a0d0a000d0a515549540a2111000c7f0000027f000001d3c947e348454c4c4f";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[tokio::test]
async fn haproxy_s_headers_name_the_client_and_leave_its_bytes() {
    for captured in [HAPROXY_V1, HAPROXY_V2] {
        let bytes = hex(captured);
        let mut from = bytes.as_slice();
        assert_eq!(read(&mut from).await, Ok(Said::Client(ip("127.0.0.2"))), "{captured}");
        assert_eq!(from, b"HELLO", "read to the header's end, no further");
    }
}

#[test]
fn each_form_of_the_header() {
    let v1 = |line: &str| parse_v1(line.as_bytes());
    assert_eq!(v1("PROXY TCP6 2001:db8::1 2001:db8::2 4000 443"), Ok(Said::Client(ip("2001:db8::1"))));
    assert_eq!(v1("PROXY UNKNOWN"), Ok(Said::Own));
    assert_eq!(v1("PROXY UNKNOWN ffff::1 ffff::2 1 2"), Ok(Said::Own));
    for bad in [
        "PROXY TCP4 2001:db8::1 192.0.2.2 1 2",
        "PROXY TCP4 192.0.2.1 192.0.2.2 1",
        "PROXY TCP4 192.0.2.1 192.0.2.2 1 70000",
        "PROXY TCP4 192.0.2.1 192.0.2.2 +1 2",
        "PROXY UDP4 192.0.2.1 192.0.2.2 1 2",
        "GET / HTTP/1.1",
    ] {
        assert!(v1(bad).is_err(), "{bad}");
    }
    // LOCAL: the balancer's own check, its peer the address.
    assert_eq!(parse_v2(0x20, 0x00, &[]), Ok(Said::Own));
    let mut six = vec![0u8; 36];
    six[..16].copy_from_slice(&"2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
    assert_eq!(parse_v2(0x21, 0x21, &six), Ok(Said::Client(ip("2001:db8::7"))));
    assert_eq!(parse_v2(0x21, 0x31, &[0; 216]), Ok(Said::Own), "a UNIX socket names no client");
    assert!(parse_v2(0x21, 0x11, &[0; 8]).is_err(), "too short");
    assert!(parse_v2(0x11, 0x11, &[0; 12]).is_err(), "version 1 in a binary header");
    assert!(parse_v2(0x22, 0x11, &[0; 12]).is_err(), "no such command");
}

#[tokio::test]
async fn a_line_or_a_block_past_its_bound_is_refused() {
    let long = format!("PROXY TCP4 {}\r\n", "1".repeat(V1_MAX));
    assert!(read(&mut long.as_bytes()).await.unwrap_err().contains("longer than"));
    let mut big = V2_SIGNATURE.to_vec();
    big.extend([0x21, 0x11, 0xff, 0xff]);
    assert!(read(&mut big.as_slice()).await.unwrap_err().contains("past"));
    assert!(read(&mut b"\x16\x03\x01".as_slice()).await.is_err(), "no header at all");
}
