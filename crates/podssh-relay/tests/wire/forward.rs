//! `forward.json`: the WebSocket frames that carry the forward road, as
//! `pod-ws`'s framing writes and reads them (RFC 6455).

use podssh_ws::frame::{self, Frame, Role};
use serde_json::Value;

use crate::common::{array, bytes, hex, name, of_kind, small, text};

fn writer(v: &Value) -> Role {
    match text(v, "writer") {
        "server" => Role::Server,
        _ => Role::Client,
    }
}

#[test]
fn each_frame_encodes_to_its_bytes_and_decodes_to_its_fields() {
    for v in of_kind("forward", "frame") {
        let fin = v["fin"].as_bool().expect("fin");
        let f = Frame { fin, opcode: small(&v, "opcode"), payload: bytes(&v, "payload") };
        let mask: [u8; 4] = if v.get("mask").is_some() { array(&v, "mask") } else { [0; 4] };
        assert_eq!(hex(&frame::encode(&f, writer(&v), mask)), text(&v, "hex"), "{}", name(&v));
        let wire = bytes(&v, "hex");
        match frame::decode(&wire, writer(&v)) {
            Ok(Some((read, used))) => {
                assert_eq!(read, f, "{}", name(&v));
                assert_eq!(used, wire.len(), "{}", name(&v));
            }
            Ok(None) => panic!("{}: it waits for more", name(&v)),
            Err(e) => panic!("{}: {e}", name(&v)),
        }
    }
}

#[test]
fn each_refused_frame_is_refused() {
    for v in of_kind("forward", "frame-refused") {
        let read = frame::decode(&bytes(&v, "hex"), writer(&v));
        assert!(read.is_err(), "{}: read as {read:?}", name(&v));
    }
}
