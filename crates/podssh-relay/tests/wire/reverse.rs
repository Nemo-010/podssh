//! `reverse.json`: the frames of the reverse road's two legs and the node's
//! control messages (`pod-relay`'s `reverse::framing` and `reverse::control`).

use podssh_relay::reverse::control::{self, NodeInbound, NodeOutbound};
use podssh_relay::reverse::framing::{legs, CodecError, SessionId};
use serde_json::Value;

use crate::common::{bytes, hex, name, number, of_kind, text};

/// The page's name of a codec's fault.
fn fault(e: &CodecError) -> &'static str {
    match e {
        CodecError::FrameTooShort { .. } => "frame-too-short",
        CodecError::FrameTooLong { .. } => "frame-too-long",
        CodecError::SessionIdNotLowercaseHex { .. } => "id-not-lowercase-hex",
        CodecError::SessionIdLength { .. } => "id-length",
        CodecError::OperatorPayloadTooLong { .. } => "operator-payload-too-long",
        CodecError::ControlFrameTooLong { .. } => "control-frame-too-long",
        CodecError::ControlNotUtf8 { .. } => "control-not-utf8",
    }
}

fn id_of(v: &Value) -> SessionId {
    SessionId::parse(text(v, "id").as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", name(v)))
}

#[test]
fn each_frame_of_each_leg_is_the_page_s() {
    for v in of_kind("reverse", "node-frame") {
        let (id, payload) = (id_of(&v), bytes(&v, "payload"));
        let wire = legs::encode_node_frame(&id, &payload).expect("a node frame");
        assert_eq!(hex(&wire), text(&v, "hex"), "{}", name(&v));
        let framed = bytes(&v, "hex");
        let (read, rest) = legs::decode_node_frame(&framed).expect("a node frame");
        assert_eq!((read.as_str(), rest), (text(&v, "id"), &payload[..]), "{}", name(&v));
    }
    for v in of_kind("reverse", "operator-frame") {
        let wire = legs::encode_operator_frame(&bytes(&v, "payload")).expect("an operator frame");
        assert_eq!(hex(&wire), text(&v, "hex"), "{}", name(&v));
    }
    for v in of_kind("reverse", "chunks") {
        let n = usize::try_from(number(&v, "bytes_len")).expect("a length");
        let frames = legs::chunk_for_node(&id_of(&v), &vec![0; n]).expect("chunks");
        let lens: Vec<u64> = frames.iter().map(|f| f.len() as u64).collect();
        let want: Vec<u64> = v["frame_lens"].as_array().expect("lens").iter().filter_map(Value::as_u64).collect();
        assert_eq!(lens, want, "{}", name(&v));
    }
}

#[test]
fn each_refused_frame_is_refused_with_the_relay_s_close() {
    for v in of_kind("reverse", "node-frame-refused") {
        let e = legs::decode_node_frame(&bytes(&v, "hex")).err().unwrap_or_else(|| panic!("{}: read", name(&v)));
        assert_eq!(fault(&e), text(&v, "error"), "{}", name(&v));
        assert_eq!(e.relay_close_code().map(u64::from), Some(number(&v, "close")), "{}", name(&v));
    }
    let id = SessionId::parse(b"0123456789abcdef0123456789abcdef").expect("an id");
    for v in of_kind("reverse", "too-long") {
        let payload = vec![0; usize::try_from(number(&v, "payload_len")).expect("a length")];
        let e = match text(&v, "leg") {
            "node" => legs::encode_node_frame(&id, &payload).err(),
            _ => legs::encode_operator_frame(&payload).err(),
        };
        let e = e.unwrap_or_else(|| panic!("{}: made", name(&v)));
        assert_eq!(fault(&e), text(&v, "error"), "{}", name(&v));
        assert_eq!(e.relay_close_code().map(u64::from), Some(number(&v, "close")), "{}", name(&v));
    }
}

/// What the operator reads of a control text, as the page's members.
fn members(read: NodeOutbound) -> Value {
    match read {
        NodeOutbound::Ready { id } => serde_json::json!({ "type": "ready", "id": id }),
        NodeOutbound::Reject { id, reason } => serde_json::json!({ "type": "reject", "id": id, "reason": reason }),
        NodeOutbound::Close { id, reason: None } => serde_json::json!({ "type": "close", "id": id }),
        NodeOutbound::Close { id, reason: Some(r) } => serde_json::json!({ "type": "close", "id": id, "reason": r }),
    }
}

#[test]
fn each_control_message_of_the_node_is_its_exact_text() {
    for v in of_kind("reverse", "control-out") {
        let m = &v["message"];
        let id = id_of(m);
        let made = match text(m, "type") {
            "ready" => control::ready(&id),
            "reject" => control::reject(&id, text(m, "reason")),
            _ => control::close(&id, m["reason"].as_str()),
        };
        let made = made.unwrap_or_else(|e| panic!("{}: {e}", name(&v)));
        assert_eq!(String::from_utf8_lossy(&made), text(&v, "text"), "{}", name(&v));
        let read = control::parse_operator_control(text(&v, "text").as_bytes()).expect("the operator reads it");
        assert_eq!(&members(read), m, "{}", name(&v));
    }
    for v in of_kind("reverse", "control-cut") {
        let long = "x".repeat(usize::try_from(number(&v, "reason_len")).expect("a length"));
        let made = control::reject(&id_of(&v), &long).expect("a reject");
        assert!(made.len() <= control::CONTROL_MAX, "{}: {} bytes", name(&v), made.len());
        match control::parse_operator_control(&made).expect("the operator reads it") {
            NodeOutbound::Reject { reason, .. } => {
                assert_eq!(reason.len() as u64, number(&v, "cut_len"), "{}", name(&v));
            }
            other => panic!("{}: {other:?}", name(&v)),
        }
    }
}

#[test]
fn each_control_message_to_the_node_reads_as_the_page_says() {
    for v in of_kind("reverse", "control-in") {
        let m = &v["message"];
        let read = control::parse_inbound(text(&v, "text").as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", name(&v)));
        match read {
            NodeInbound::Hello(hello) => {
                assert_eq!(text(m, "type"), "hello", "{}", name(&v));
                assert_eq!(hello.version.as_ref(), m.get("version"), "{}", name(&v));
                assert_eq!(hello.max_frame_bytes, m["maxFrameBytes"].as_u64(), "{}", name(&v));
                assert_eq!(hello.max_sessions.map(u64::from), m["maxSessions"].as_u64(), "{}", name(&v));
                // A member that the node does not model is kept, never refused.
                for (key, value) in m.as_object().expect("members") {
                    if !["type", "version", "maxFrameBytes", "maxSessions"].contains(&key.as_str()) {
                        assert_eq!(hello.extra.get(key), Some(value), "{}: {key}", name(&v));
                    }
                }
            }
            NodeInbound::Open { id } => {
                assert_eq!(serde_json::json!({ "type": "open", "id": id }), *m, "{}", name(&v));
            }
            NodeInbound::Close { id, reason } => {
                let mut want = serde_json::json!({ "type": "close", "id": id });
                if let Some(r) = reason {
                    want["reason"] = Value::from(r);
                }
                assert_eq!(want, *m, "{}", name(&v));
            }
            NodeInbound::Spent { digest } => {
                assert_eq!(serde_json::json!({ "type": "spent", "digest": digest }), *m, "{}", name(&v));
            }
            NodeInbound::Unknown => assert_eq!(text(m, "type"), "unknown", "{}", name(&v)),
        }
    }
}
