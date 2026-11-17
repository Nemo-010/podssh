//! `tokens.json`: the forward tokens that podssh's relay role mints and takes
//! (`serve::tokens`). A file holds a token's parts alone, so that no whole
//! token stands in the repository for a scan of secrets to read as live.

use podssh_relay::serve::tokens::Tokens;

use crate::common::{array, name, number, of_kind, text};

fn token(expiry: u64, mac: &str) -> String {
    format!("ephm1.{expiry}.forward.{mac}")
}

#[test]
fn each_minted_token_is_the_page_s() {
    for v in of_kind("tokens", "mint") {
        let tokens = Tokens::new(array(&v, "secret"));
        let (made, expiry) = tokens.mint(number(&v, "now_ms"), number(&v, "lifetime_ms"));
        assert_eq!(expiry, number(&v, "expiry"), "{}", name(&v));
        // Compared, never printed: a message names the vector alone.
        assert!(made == token(expiry, text(&v, "mac")), "{}: another token", name(&v));
    }
}

#[test]
fn each_token_is_taken_or_refused_as_the_page_says() {
    for v in of_kind("tokens", "check") {
        let tokens = Tokens::new(array(&v, "secret"));
        let given = token(number(&v, "expiry"), text(&v, "mac"));
        let taken = tokens.check(&given, number(&v, "now_ms"));
        assert_eq!(taken, v["valid"].as_bool().expect("valid"), "{}", name(&v));
    }
}
