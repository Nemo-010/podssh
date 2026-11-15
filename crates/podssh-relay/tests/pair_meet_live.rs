//! The live runs of the places of the pairing by code after the mailboxes
//! (T-496, T-545, T-695; short, by the operator's rulings Q65, Q77 and Q78):
//! two podssh ends whose one mailbox is dead pair through the public ntfy
//! servers, the public Nostr relays or the public WebTorrent trackers of
//! `pod-services`, each place alone, and the line of its third party comes
//! first. `PODSSH_TEST_MEET_LIVE` names the places of a run, by commas
//! (`pair-code.yml`'s input `live`); with none, each test says so and passes.
//! The protocols are `pod-wormhole`'s, tested in PodUtils/podcrates against
//! each software's own server.

#![cfg(all(feature = "pair", feature = "code"))]

mod cleanup;
mod mailbox_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailbox_harness::nobody_there;
use podssh_relay::code::exchange::{Done, Offer};
use podssh_relay::code::run::{self, Ends, Waits};
use podssh_relay::code::{self, Code};
use podssh_relay::identity::PublicKey;
use podssh_relay::pair::OperatorPart;
use podssh_ws::{ProxyChoice, Trust};
use zeroize::Zeroizing;

const NAME: &str = "0123456789abcdef0123456789abcdef";
// A token of the tests alone, of the form of a pair's.
const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const NODE: PublicKey = PublicKey([0x22; 32]);
const OPERATOR: PublicKey = PublicKey([0x11; 32]);
const LIMIT: Duration = Duration::from_secs(120);

/// Whether the run asked for the place `name`.
fn asked(name: &str) -> bool {
    let value = std::env::var("PODSSH_TEST_MEET_LIVE").unwrap_or_default();
    let asked = value.split(',').any(|v| v.trim() == name);
    if !asked {
        eprintln!("PODSSH_TEST_MEET_LIVE names no {name}: no live run through it");
    }
    asked
}

fn offer() -> Offer {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let token = Zeroizing::new(TOKEN.to_string());
    let part = OperatorPart::checked("relay.example.org", NAME.into(), token, now + 3_600_000, now).unwrap();
    Offer { label: "lab".into(), node: NODE, part: Some(part) }
}

/// Two ends of one code meet at the place that `fill` gives, the mailbox
/// dead; the third party's line, `words`, comes before the pairing ends.
async fn pair_through(fill: fn(&mut Ends), words: &str) {
    let said: Arc<Mutex<Vec<String>>> = Default::default();
    let say_to = said.clone();
    let say: code::Say = Arc::new(move |line: String| say_to.lock().unwrap().push(line));
    let mut ends = Ends::new(vec![nobody_there()], code::config(&Trust::Default, &ProxyChoice::FromEnvironment, say));
    fill(&mut ends);
    let offer = offer();
    let (shown_tx, shown_rx) = tokio::sync::oneshot::channel::<String>();
    let mut shown_tx = Some(shown_tx);
    let mut show = move |made: &Code, _: &str| {
        if let Some(tx) = shown_tx.take() {
            let _ = tx.send(made.for_terminal().to_string());
        }
    };
    let mut admit = |key: &PublicKey| Done { admitted: *key == OPERATOR, said: "the operator of the test".into() };
    // podssh's own waits, as `podssh relay pair --code` and `join` take them.
    let waits = Waits::default();
    let giving = run::give(&ends, &waits, &offer, &mut show, &mut admit);
    let taking = async {
        let code = Code::parse(&shown_rx.await.expect("a code")).expect("a code");
        let mut check = |offer: &Offer| if offer.node == NODE { Ok(()) } else { Err("another node".to_string()) };
        run::take(&ends, &waits, &code, &OPERATOR, &mut check).await
    };
    let (given, taken) =
        tokio::time::timeout(LIMIT, async { tokio::join!(giving, taking) }).await.expect("within the limit");
    let lines = said.lock().unwrap().clone();
    let given = given.unwrap_or_else(|f| panic!("the giver: {f}; {lines:?}"));
    let taken = taken.unwrap_or_else(|f| panic!("the taker: {f}; {lines:?}"));
    assert!(given.done.admitted && taken.done.admitted);
    assert!(lines.iter().any(|l| l.contains(words)), "the third party's line: {lines:?}");
    eprintln!("paired through {}", given.mailbox);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_two_ends_pair_through_a_public_ntfy_server() {
    if !asked("ntfy") {
        return;
    }
    let fill = |ends: &mut Ends| ends.ntfy = code::ntfy_servers(None, None).expect("the catalog's servers");
    pair_through(fill, run::NTFY_WORDS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_two_ends_pair_through_a_public_nostr_relay() {
    if !asked("nostr") {
        return;
    }
    pair_through(|ends| ends.relays = code::nostr_relays(None, None), run::NOSTR_WORDS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_two_ends_pair_through_a_public_webtorrent_tracker() {
    if !asked("tracker") {
        return;
    }
    pair_through(|ends| ends.trackers = code::trackers(None, None), run::TRACKER_WORDS).await;
}
