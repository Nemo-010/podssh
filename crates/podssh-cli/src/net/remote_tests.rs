//! A node's net at a URL (T-715), on a paused clock, with a stand-in server
//! of the test's: the door follows a new document within the TTL; past the
//! TTL and the stale window it is closed, and a fetch that works opens it;
//! a document of another owner, one that another key signed, an older
//! serial and an answer past 64 KiB are refused, the copy held kept. The
//! node's own fetch over TLS is `tests/node_net_url.rs`'s.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::identity::{Identity, KeyName};
use podssh_relay::serve::keys::list::{Fetch, Fetching};
use podssh_ssh::russh::keys::{Algorithm, PrivateKey};

use super::super::doc::{self, Doc, Member};
use super::super::sign;
use super::*;
use crate::keygen_sign::Signing;

/// The epoch of the test's clock, in ms: 2026-11-02.
const BASE_MS: i64 = 1_793_577_600_000;
const TTL_S: u64 = 60;
const STALE_S: u64 = 600;

/// The server: its answer now, and how many fetches came.
#[derive(Clone)]
struct Served {
    answer: Arc<Mutex<Result<Vec<u8>, String>>>,
    asked: Arc<AtomicUsize>,
}

impl Served {
    fn new() -> Served {
        Served { answer: Arc::new(Mutex::new(Err("HTTP 503 Test".into()))), asked: Arc::new(AtomicUsize::new(0)) }
    }

    fn serve(&self, answer: Result<Vec<u8>, String>) {
        *self.answer.lock().unwrap() = answer;
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Fetch for Served {
    fn fetch(&self) -> Fetching<'_> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let answer = self.answer.lock().unwrap().clone();
        Box::pin(async move { answer })
    }

    fn shown(&self) -> String {
        "https://net.test/...".into()
    }
}

/// An owner's key, and its public line.
fn owner_key() -> (Signing, String) {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let line = key.public_key().to_openssh().unwrap().trim().to_string();
    (Signing::Key(Box::new(key)), line)
}

/// The fingerprint of an owner's line, as `--net-owner` names it.
fn named(line: &str) -> KeyName {
    owner_of(&sign::owner_fingerprint(line)).unwrap()
}

/// The key of the member of `seed`.
fn member_key(seed: u8) -> podssh_relay::identity::PublicKey {
    Identity::from_seed(&[seed; 32]).public()
}

/// A document of the serial `changes + 1`, with a member for each seed,
/// signed by `by` for the owner `owner`: its signed form, as a server serves
/// it.
fn document(owner: &str, by: &Signing, changes: u64, seeds: &[u8]) -> Vec<u8> {
    let mut doc = Doc::new("fleet", owner, 1_793_577_600, 4_102_444_800).unwrap();
    let values = seeds.iter().map(|seed| {
        doc::member_value(&Member {
            name: format!("m{seed:02x}"),
            key: KeyName::parse(&member_key(*seed).hex()).unwrap(),
            roles: vec!["node".into()],
            tickets: Default::default(),
            routes: Vec::new(),
            relay: None,
            shares: Vec::new(),
        })
    });
    let values: Vec<_> = values.collect();
    for _ in 1..changes {
        doc = doc.next(1_793_577_600, 4_102_444_800, |_| {}).unwrap();
    }
    doc = doc.next(1_793_577_600, 4_102_444_800, |list| list.extend(values)).unwrap();
    assert_eq!(doc.serial, changes + 1);
    let bytes = doc.to_bytes();
    let signature = sign::sign_bytes(by, &bytes).unwrap();
    [bytes, signature.into_bytes()].concat()
}

/// A private directory of the test, gone at its end.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let name = format!("podssh-net-url-{tag}-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let dir = std::env::temp_dir().join(name);
    podssh_relay::cache::private_dir(&dir).unwrap();
    Scratch(dir)
}

/// The net of the stand-in server, held in `dir`, owned by `owner`, on the
/// paused clock of tokio.
fn remote(served: &Served, owner: KeyName, dir: &Scratch) -> Arc<Remote> {
    let start = tokio::time::Instant::now();
    let clock: Clock = Arc::new(move || BASE_MS + start.elapsed().as_millis() as i64);
    let place = Place::File(dir.0.join("net.doc"));
    let id = id_of("https://net.test/fleet");
    Arc::new(Remote::new(Box::new(served.clone()), owner, TTL_S, STALE_S, place, clock, id, None))
}

/// Whether the net held at `dir` names the member of `seed`.
fn names(dir: &Scratch, seed: u8) -> bool {
    let held = store::held_at(&Place::File(dir.0.join("net.doc"))).unwrap().expect("a net held");
    held.signed.doc.member_of_key(&member_key(seed)).is_some()
}

/// The lines that the keeper says.
fn lines() -> (Say, Arc<Mutex<Vec<String>>>) {
    let said = Arc::new(Mutex::new(Vec::new()));
    let kept = said.clone();
    let say: Say = Arc::new(move |line: String| kept.lock().unwrap().push(line));
    (say, said)
}

#[tokio::test(start_paused = true)]
async fn the_door_follows_a_new_document_within_the_ttl() {
    let dir = scratch("follow");
    let (owner, line) = owner_key();
    let served = Served::new();
    served.serve(Ok(document(&line, &owner, 1, &[0x31, 0x32])));
    let net = remote(&served, named(&line), &dir);
    assert!(net.closed().is_some(), "no copy yet: the door is closed");
    assert_eq!(net.refresh().await, Ok(Got::New { serial: 2, before: None }));
    assert!(names(&dir, 0x31) && names(&dir, 0x32) && net.closed().is_none());
    let (say, said) = lines();
    tokio::spawn(Arc::clone(&net).keep(say));
    // The owner drops 0x32: no fetch before the TTL, then one.
    served.serve(Ok(document(&line, &owner, 2, &[0x31])));
    tokio::time::sleep(Duration::from_secs(TTL_S - 1)).await;
    assert!(names(&dir, 0x32) && served.asked() == 1, "a fetch before the TTL");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!names(&dir, 0x32) && names(&dir, 0x31), "the door follows within the TTL");
    assert_eq!(served.asked(), 2, "one fetch each TTL");
    let said = said.lock().unwrap().join("\n");
    assert!(said.contains("serial 3, in place of 2"), "{said}");
}

#[tokio::test(start_paused = true)]
async fn past_the_ttl_and_the_stale_window_the_door_is_closed_until_a_fetch_works() {
    let dir = scratch("stale");
    let (owner, line) = owner_key();
    let served = Served::new();
    let body = document(&line, &owner, 1, &[0x31]);
    served.serve(Ok(body.clone()));
    let net = remote(&served, named(&line), &dir);
    net.refresh().await.unwrap();
    let (say, said) = lines();
    tokio::spawn(Arc::clone(&net).keep(say));
    // The server stops: the copy is read through its stale window.
    served.serve(Err("HTTP 503 Test".into()));
    tokio::time::sleep(Duration::from_secs(TTL_S + 1)).await;
    assert_eq!(net.closed(), None, "a copy of a TTL ago is read");
    tokio::time::sleep(Duration::from_secs(STALE_S)).await;
    let why = net.closed().expect("past the TTL and the stale window, the door is closed");
    assert!(why.contains("lets nobody in"), "{why}");
    let closing = said.lock().unwrap().iter().filter(|l| l.contains("past --net-ttl and --net-stale")).count();
    assert_eq!(closing, 1, "the line of a door that closed comes once: {:?}", said.lock().unwrap());
    // A fetch that works opens it again, the same serial.
    served.serve(Ok(body));
    tokio::time::sleep(Duration::from_secs(TTL_S)).await;
    assert_eq!(net.closed(), None);
    assert!(said.lock().unwrap().iter().any(|l| l.contains("fetched again, serial 2, the one held")));
}

#[tokio::test(start_paused = true)]
async fn a_document_of_another_owner_or_key_an_older_serial_or_a_large_answer_is_refused() {
    let dir = scratch("refused");
    let (owner, line) = owner_key();
    let (other, other_line) = owner_key();
    let served = Served::new();
    let net = remote(&served, named(&line), &dir);
    // The first document, its owner another key: refused by --net-owner.
    served.serve(Ok(document(&other_line, &other, 1, &[0x31])));
    let why = net.refresh().await.unwrap_err();
    assert!(why.contains("--net-owner"), "{why}");
    assert!(store::held_at(&Place::File(dir.0.join("net.doc"))).unwrap().is_none(), "nothing is kept");
    assert!(net.closed().is_some(), "a refused document opens no door");
    // The owner's field, and another key's signature.
    served.serve(Ok(document(&line, &other, 1, &[0x31])));
    let why = net.refresh().await.unwrap_err();
    assert!(why.contains("not by its owner"), "{why}");
    // The owner's serial 3, then its serial 2: the older is refused.
    served.serve(Ok(document(&line, &owner, 2, &[0x31])));
    net.refresh().await.unwrap();
    served.serve(Ok(document(&line, &owner, 1, &[0x32])));
    let why = net.refresh().await.unwrap_err();
    assert!(why.contains("not higher than 3"), "{why}");
    assert!(names(&dir, 0x31) && !names(&dir, 0x32), "the copy held stays");
    let large = vec![b' '; DOC_MOST + 1];
    assert!(net.accept(&large).unwrap_err().contains("64 KiB"));
}

#[test]
fn the_flags_are_checked_before_anything_connects() {
    let file = Defaults::default();
    let owner = format!("SHA256:{}", "A".repeat(43));
    let args = |url: Option<&str>, owner: Option<&str>, ttl: Option<&str>| NodeArgs {
        name: Some("lab".into()),
        net_url: url.map(String::from),
        net_owner: owner.map(String::from),
        net_ttl: ttl.map(String::from),
        ..NodeArgs::default()
    };
    assert!(plan_with(&args(None, None, None), &file).unwrap().is_none(), "no URL, no fetch");
    let usage = |a: NodeArgs| plan_with(&a, &file).err().map(|r| (r.code, r.message)).expect("refused");
    let (code, why) = usage(args(None, Some(&owner), None));
    assert!(code == crate::exit_codes::EXIT_USAGE && why.contains("go with --net-url"), "{why}");
    assert!(usage(args(Some("https://net.example/doc"), None, None)).1.contains("--net-owner"));
    assert!(usage(args(Some("http://net.example/doc"), Some(&owner), None)).1.contains("TLS alone"));
    let user = ["https://u", ":pw", "@net.example/doc"].concat();
    assert!(usage(args(Some(&user), Some(&owner), None)).1.contains("no user"));
    // Never under 60 s (Q105).
    assert!(usage(args(Some("https://net.example/doc"), Some(&owner), Some("59"))).1.contains("from 60"));
    let plan = plan_with(&args(Some("https://net.example/SECRET"), Some(&owner), Some("60")), &file).unwrap().unwrap();
    assert_eq!((plan.ttl, plan.stale), (60, STALE));
    let asked = args(Some("https://net.example/d"), Some(&owner), None);
    let temporary = NodeArgs { temporary: Some(owner.clone()), ..asked };
    assert!(usage(temporary).1.contains("--temporary"));
    // The settings file stands in for the flags.
    let value = |text: &str| Some(crate::settings::Value { text: text.into(), at: "f:1".into() });
    let file = Defaults { net_url: value("https://net.example/doc"), net_owner: value(&owner), ..Defaults::default() };
    assert!(plan_with(&args(None, None, None), &file).unwrap().is_some());
}

#[test]
fn status_shows_the_url_by_its_host_the_serial_the_age_and_whether_it_is_stale() {
    let record = serde_json::json!({
        "url": "https://net.example/...", "id": "x", "owner": "SHA256:x", "serial": 4,
        "fetched_ms": BASE_MS, "ttl_s": 300, "stale_s": 3600, "error": null, "checked_ms": BASE_MS,
    })
    .to_string();
    let fresh = status_of(&record, BASE_MS + 10_000);
    assert_eq!((fresh["age_s"].as_i64(), &fresh["stale"], &fresh["closed"]), (Some(10), &json!(false), &json!(false)));
    assert_eq!((&fresh["url"], &fresh["serial"]), (&json!("https://net.example/..."), &json!(4)));
    let stale = status_of(&record, BASE_MS + 301_000);
    assert_eq!((&stale["stale"], &stale["closed"]), (&json!(true), &json!(false)));
    let closed = status_of(&record, BASE_MS + 3_901_000);
    assert_eq!(closed["closed"], json!(true));
}
