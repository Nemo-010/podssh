//! `layer.json`: the records of the resumable layer, its decoder's
//! refusals, and the secret and proofs of its handshake (`pod-session`).

use podssh_relay::session::decode::{DecodeError, Decoder};
use podssh_relay::session::record::{Acceptance, Hello, Opening, Record, RefuseCode, Role};
use podssh_relay::session::secret::{self, Claim, Exchange, Nonce, Proof, Prover, SessionId};
use serde_json::Value;

use crate::common::{array, bytes, hex, name, number, of_kind, small, strings, text, unhex};

/// The record that a vector's fields name.
fn record_of(v: &Value) -> Record {
    let f = &v["fields"];
    let hello = || Hello {
        version: small(f, "version"),
        role: Role(small(f, "role")),
        nonce: Nonce(array(f, "nonce")),
        features: strings(f, "features"),
    };
    match text(v, "record") {
        "GREETING" => Record::Greeting(hello()),
        "OPEN" => Record::Open {
            hello: hello(),
            opening: match text(f, "opening") {
                "new" => Opening::New { public: array(f, "public") },
                _ => Opening::Resume { id: SessionId(array(f, "id")) },
            },
        },
        "ACCEPT" => Record::Accept(match text(f, "acceptance") {
            "new" => Acceptance::New { id: SessionId(array(f, "id")), public: array(f, "public") },
            _ => Acceptance::Resume { offset: number(f, "offset"), proof: Proof(array(f, "proof")) },
        }),
        "PROOF" => Record::Proof { offset: number(f, "offset"), proof: Proof(array(f, "proof")) },
        "REFUSE" => Record::Refuse { code: RefuseCode(small(f, "code")), reason: text(f, "reason").into() },
        "DATA" => Record::Data { offset: number(f, "offset"), bytes: bytes(f, "bytes") },
        "ACK" => Record::Ack { offset: number(f, "offset") },
        "PING" => Record::Ping { value: number(f, "value") },
        "PONG" => Record::Pong { value: number(f, "value"), offset: number(f, "offset") },
        "CLOSE" => Record::Close { reason: text(f, "reason").into() },
        "RETIRE" => Record::Retire,
        "END" => Record::End { offset: number(f, "offset") },
        other => panic!("{}: no record {other}", name(v)),
    }
}

#[test]
fn each_record_encodes_to_its_bytes_and_decodes_to_its_fields() {
    for v in of_kind("layer", "record") {
        let record = record_of(&v);
        let wire = bytes(&v, "hex");
        assert_eq!(record.name(), text(&v, "record"), "{}", name(&v));
        assert_eq!(hex(&record.to_bytes().expect("a record of the table")), text(&v, "hex"), "{}", name(&v));
        let mut whole = Decoder::new();
        whole.push(&wire);
        assert_eq!(whole.next(), Ok(Some(record.clone())), "{}", name(&v));
        assert_eq!(whole.next(), Ok(None), "{}: nothing after it", name(&v));
        // Byte by byte: no record before its last byte, as a relay splits frames.
        let mut slow = Decoder::new();
        for (i, b) in wire.iter().enumerate() {
            slow.push(&[*b]);
            let got = slow.next();
            if i + 1 < wire.len() {
                assert_eq!(got, Ok(None), "{}: a record at byte {i}", name(&v));
            } else {
                assert_eq!(got, Ok(Some(record.clone())), "{}", name(&v));
            }
        }
    }
}

#[test]
fn each_refused_record_is_refused_as_the_page_says() {
    for v in of_kind("layer", "refused") {
        let mut decoder = Decoder::new();
        decoder.push(&bytes(&v, "hex"));
        let kind = match decoder.next() {
            Err(DecodeError::UnknownType(_)) => "unknown-type",
            Err(DecodeError::TooLong(_)) => "too-long",
            Err(DecodeError::Malformed { .. }) => "malformed",
            Ok(got) => panic!("{}: read {got:?}", name(&v)),
        };
        assert_eq!(kind, text(&v, "error"), "{}", name(&v));
    }
    for v in of_kind("layer", "partial") {
        let mut decoder = Decoder::new();
        decoder.push(&unhex(text(&v, "hex")));
        assert_eq!(decoder.next(), Ok(None), "{}: it waits for more", name(&v));
    }
}

#[test]
fn the_secret_and_each_proof_are_the_page_s() {
    for v in of_kind("layer", "secret") {
        let f = &v["fields"];
        let shared = array(f, "shared");
        let (client_public, far_public) = (array(f, "client_public"), array(f, "far_public"));
        let (far_nonce, client_nonce) = (Nonce(array(f, "far_nonce")), Nonce(array(f, "client_nonce")));
        let id = SessionId(array(f, "id"));
        let exchange = Exchange {
            shared: &shared,
            far_nonce: &far_nonce,
            client_nonce: &client_nonce,
            id: &id,
            client_public: &client_public,
            far_public: &far_public,
        };
        let made = secret::derive(&exchange);
        assert_eq!(hex(made.bytes()), text(&v, "secret"), "{}", name(&v));
        for p in v["proofs"].as_array().expect("proofs") {
            let offset = number(p, "offset");
            for (prover, side) in [(Prover::Client, "client"), (Prover::Far, "far")] {
                let claim = Claim { prover, id: &id, far_nonce: &far_nonce, client_nonce: &client_nonce, offset };
                let proof = secret::prove(&made, &claim);
                assert_eq!(hex(&proof.0), text(p, side), "{}: {side} at {offset}", name(&v));
                assert!(secret::verify(&made, &claim, &Proof(array(p, side))), "{}: {side}", name(&v));
            }
        }
    }
}
