//! `grants.json`: grants used once, OpenSSH user certificates of Ed25519
//! keys, as `pod-relay`'s `grant::Mint` signs them and `grant::Cert` reads
//! them. Ed25519 signs deterministically, so a seed and the fields give the
//! bytes.

use podssh_relay::grant::{self, Cert, Mint, USER};
use podssh_relay::identity::Identity;

use crate::common::{array, bytes, hex, name, number, of_kind, strings, text, unhex};

#[test]
fn each_grant_signs_to_its_bytes_and_reads_back_whole() {
    for v in of_kind("grants", "grant") {
        let issuer = Identity::from_seed(&array(&v, "issuer_seed"));
        let key = Identity::from_seed(&array(&v, "key_seed")).public();
        let node = Identity::from_seed(&array(&v, "node_seed")).public();
        assert_eq!(issuer.public().hex(), text(&v, "issuer"), "{}", name(&v));
        assert_eq!(key.hex(), text(&v, "key"), "{}", name(&v));
        let principals = strings(&v, "principals");
        assert_eq!(principals, [grant::principal(&node, v["route"].as_str())], "{}", name(&v));
        let owned: Vec<(String, Vec<u8>)> = v["critical"]
            .as_array()
            .expect("critical")
            .iter()
            .map(|o| (o[0].as_str().expect("a name").to_string(), unhex(o[1].as_str().expect("data"))))
            .collect();
        let critical: Vec<(&str, &[u8])> = owned.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
        let cert = Mint {
            nonce: array(&v, "nonce"),
            key,
            serial: number(&v, "serial"),
            key_id: text(&v, "key_id"),
            principals: &principals,
            valid_after: number(&v, "valid_after"),
            valid_before: number(&v, "valid_before"),
            critical: &critical,
        }
        .sign(&issuer);
        assert_eq!(hex(&cert.blob()), text(&v, "hex"), "{}", name(&v));
        assert_eq!(hex(&cert.digest()), text(&v, "digest"), "{}", name(&v));
        let read = Cert::from_blob(&bytes(&v, "hex")).unwrap_or_else(|e| panic!("{}: {e}", name(&v)));
        assert_eq!(read, cert, "{}", name(&v));
        assert!(read.signed_by_issuer(), "{}: its signature", name(&v));
        assert_eq!(read.kind, USER, "{}", name(&v));
        assert!(read.critical.iter().any(|(n, d)| n == grant::ONCE && d.is_empty()), "{}", name(&v));
        assert!(read.extensions.is_empty(), "{}", name(&v));
    }
}

#[test]
fn a_changed_grant_fails_its_signature_and_a_cut_one_its_form() {
    for v in of_kind("grants", "grant-forged") {
        let read = Cert::from_blob(&bytes(&v, "hex")).unwrap_or_else(|e| panic!("{}: {e}", name(&v)));
        assert_eq!(read.serial, number(&v, "serial"), "{}", name(&v));
        assert!(!read.signed_by_issuer(), "{}: a forged grant verified", name(&v));
    }
    for v in of_kind("grants", "grant-refused") {
        assert!(Cert::from_blob(&bytes(&v, "hex")).is_err(), "{}: read", name(&v));
    }
}
