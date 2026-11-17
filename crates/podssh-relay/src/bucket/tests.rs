//! The bucket's road against the stand-in of `standin.rs`, which checks
//! each request's SigV4 and each key's rights on each prefix: the signer
//! against AWS's own example; a signature over another request refused (the
//! plant); one way at each end, two key pairs or an unsigned read; two ends
//! that carry 1 MiB each way through a link; a hello of a run long gone;
//! and a note played back under another number, which opens nothing.

use std::sync::Arc;
use std::time::Duration;

use pod_link::s3::sign::{self, Credentials, Signing, EMPTY_HASH};
use pod_link::s3::{Endpoint, Style};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::standin::{self, Right, StandIn, BUCKET};
use super::*;
use crate::filehost::board::Board;
use crate::filehost::keys::{Kind, LinkId, Way};

const SECRET: &[u8] = b"a secret of the test, 32 bytes!!";

/// AWS's example of Signature Version 4 for S3, "Example: GET Object", in
/// "Signature Calculations for the Authorization Header: Transferring
/// Payload in a Single Chunk (AWS Signature Version 4)" of the Amazon S3
/// API Reference (sig-v4-header-based-auth.html). Its key is the
/// documentation's, which no account has; its id is in two parts, as
/// pod-link's test has it, so that a scanner of secrets does not try it.
#[test]
fn the_signer_gives_aws_s_own_example_signature() {
    let key = Credentials::new(concat!("AKIA", "IOSFODNN7EXAMPLE"), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    let headers = [
        ("Host", "examplebucket.s3.amazonaws.com"),
        ("Range", "bytes=0-9"),
        ("x-amz-content-sha256", EMPTY_HASH),
        ("x-amz-date", "20130524T000000Z"),
    ];
    let signing = Signing {
        method: "GET",
        path: "/test.txt",
        query: &[],
        headers: &headers,
        payload_hash: EMPTY_HASH,
        date: "20130524T000000Z",
        region: "us-east-1",
    };
    let auth = sign::authorization(&key, &signing);
    assert!(auth.ends_with("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"), "{auth}");
    assert!(auth.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"), "{auth}");
}

#[test]
fn an_http_date_reads_as_seconds_and_another_form_does_not() {
    assert_eq!(s3::http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
    assert_eq!(standin::imf(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(s3::http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
    assert_eq!(s3::http_date("Sun, 06 Nov 1994 08:49:37 PST"), None);
}

/// The client writes `up/` and reads `down/`; the node the other way; and
/// the node may delete what it read, the client not.
fn rights() -> Vec<(Credentials, Vec<(String, Right)>)> {
    let write = Right { write: true, ..Right::default() };
    let read = Right { read: true, ..Right::default() };
    let read_delete = Right { read: true, delete: true, ..Right::default() };
    vec![
        (standin::client_key(), vec![("up/".into(), write), ("down/".into(), read)]),
        (standin::node_key(), vec![("down/".into(), write), ("up/".into(), read_delete)]),
    ]
}

fn place(standin: &StandIn) -> Place {
    let endpoint = Endpoint::parse(&standin.url()).expect("the stand-in's endpoint");
    let (region, bucket) = ("us-east-1".to_string(), BUCKET.to_string());
    Place { endpoint, style: Style::Path, region, bucket, up: "up".into(), down: "down".into() }
}

fn dial_out() -> crate::piping::dial::Dial {
    let endpoint = Endpoint::parse("http://127.0.0.1:1").unwrap();
    dial_of(&endpoint, podssh_ws::Trust::Default, podssh_ws::ProxyChoice::Direct)
}

fn quiet() -> crate::filehost::Say {
    Arc::new(|_| {})
}

fn end(standin: &StandIn, side: Side, read: Option<Credentials>) -> Arc<Carrier> {
    let write = match side {
        Side::Client => standin::client_key(),
        Side::Node => standin::node_key(),
    };
    carrier(&place(standin), side, KeyPairs { write, read }, SECRET, dial_out(), quiet()).expect("a carrier")
}

#[tokio::test]
async fn a_signature_over_another_request_is_refused() {
    let standin = StandIn::start(rights(), &[]).await;
    let bucket = s3::Bucket::new(place(&standin).endpoint, Style::Path, "us-east-1", BUCKET, dial_out());
    let key = standin::client_key();
    let good = bucket.request("PUT", "up/a", Some(&key), b"x", 0).await.unwrap();
    assert_eq!(good.status, 200, "a right signature");
    // The plant: the fields of a PUT of up/a, sent as a PUT of up/b, so
    // that the canonical request that was signed is not the one that came.
    let fields = s3::headers(&bucket, "PUT", "up/a", Some(&key), b"x", &sign::amz_date(1_700_000_000));
    let fields: Vec<(&str, &str)> = fields.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", standin.port)).await.unwrap();
    let host = format!("127.0.0.1:{}", standin.port);
    let path = format!("/{BUCKET}/up/b");
    let answer = pod_proxy::http::exchange(&mut tcp, "t", "PUT", &host, &path, &fields, b"x", 4096).await.unwrap();
    assert_eq!(answer.status, 403);
    assert!(String::from_utf8_lossy(&answer.body).contains("SignatureDoesNotMatch"));
    assert!(standin.keys("up/b").is_empty(), "nothing stored");
    // Another secret for the same id is refused too.
    let wrong = Credentials::new(key.access_key.clone(), "not the secret");
    assert_eq!(bucket.request("PUT", "up/c", Some(&wrong), b"x", 0).await.unwrap().status, 403);
    assert_eq!(standin.state.refused.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn each_end_writes_one_way_and_reads_the_other() {
    let standin = StandIn::start(rights(), &[]).await;
    let bucket = s3::Bucket::new(place(&standin).endpoint, Style::Path, "us-east-1", BUCKET, dial_out());
    let (client, node) = (standin::client_key(), standin::node_key());
    let denied = |status: u16| assert_eq!(status, 403);
    denied(bucket.request("GET", "up/x", Some(&client), &[], 64).await.unwrap().status);
    denied(bucket.request("PUT", "down/x", Some(&client), b"x", 0).await.unwrap().status);
    denied(bucket.request("PUT", "up/x", Some(&node), b"x", 0).await.unwrap().status);
    denied(bucket.request("GET", "up/x", None, &[], 64).await.unwrap().status);
    // The board of each end, over those rights.
    let keys = keys_of(SECRET, &place(&standin)).unwrap();
    let up = Arc::new(s3::Bucket::new(place(&standin).endpoint, Style::Path, "us-east-1", BUCKET, dial_out()));
    let client_board = board::BucketBoard::new(up.clone(), "up", "down", client.clone(), Some(client), keys.door());
    let node_board = board::BucketBoard::new(up, "down", "up", node.clone(), Some(node), keys.door());
    client_board.put("t1", b"hello".to_vec()).await.unwrap();
    assert_eq!(standin.keys("up/"), vec!["up/t1".to_string()]);
    assert_eq!(node_board.take("t1").await.unwrap().as_deref(), Some(&b"hello"[..]));
    assert_eq!(client_board.take("t1").await.unwrap(), None, "the client reads down/, where t1 is not");
    node_board.clear("t1").await.unwrap();
    assert!(standin.keys("up/").is_empty(), "the node may delete what it read");
    node_board.put("t2", b"back".to_vec()).await.unwrap();
    assert_eq!(client_board.take("t2").await.unwrap().as_deref(), Some(&b"back"[..]));
    assert!(client_board.clear("t2").await.is_err(), "the client may not delete");
}

/// A pattern of `len` bytes, so that a byte out of place shows.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_carry_a_mebibyte_each_way() {
    let standin = StandIn::start(rights(), &[]).await;
    let client = end(&standin, Side::Client, Some(standin::client_key()));
    let node = end(&standin, Side::Node, Some(standin::node_key()));
    let (up, down) = (pattern(1 << 20, 7), pattern(1 << 20, 11));
    let (want_up, want_down) = (Sha256::digest(&up), Sha256::digest(&down));
    let (tell, told) = tokio::sync::oneshot::channel();
    let node_task = tokio::spawn(async move {
        let mut link = accept(&node).await.expect("the node's link");
        let mut got = vec![0u8; 1 << 20];
        link.read_exact(&mut got).await.expect("the node's read");
        let _ = tell.send(got);
        link.write_all(&down).await.expect("the node's write");
        // The link lives until the client has read its way: a dropped link
        // ends its task.
        std::future::pending::<()>().await;
    });
    let carried = tokio::time::timeout(Duration::from_secs(240), async {
        let mut link = dial(&client).await.expect("the client's link");
        link.write_all(&up).await.expect("the client's write");
        let got_up = told.await.expect("the node read the up way");
        let mut back = vec![0u8; 1 << 20];
        link.read_exact(&mut back).await.expect("the client's read");
        (got_up, back)
    })
    .await;
    node_task.abort();
    let (got_up, back) = carried.expect("1 MiB each way within 240 s");
    assert_eq!(Sha256::digest(got_up), want_up, "up whole");
    assert_eq!(Sha256::digest(back), want_down, "down whole");
    assert_eq!(standin.state.refused.load(std::sync::atomic::Ordering::SeqCst), 0, "each request signed rightly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsigned_reader_of_a_public_prefix_takes_the_client_s_way() {
    let standin = StandIn::start(rights(), &["up/"]).await;
    let client = end(&standin, Side::Client, Some(standin::client_key()));
    let node = end(&standin, Side::Node, None);
    let done = tokio::time::timeout(Duration::from_secs(120), async {
        let node_task = tokio::spawn(async move {
            let mut link = accept(&node).await.expect("the node's link, read with no key");
            let mut got = vec![0u8; 5];
            link.read_exact(&mut got).await.expect("the node's read");
            got
        });
        let mut link = dial(&client).await.expect("the client's link");
        link.write_all(b"hello").await.expect("the client's write");
        node_task.await.expect("the node's task")
    })
    .await
    .expect("within 120 s");
    assert_eq!(done, b"hello");
}

#[tokio::test]
async fn a_hello_of_a_run_long_gone_opens_no_link() {
    let standin = StandIn::start(rights(), &[]).await;
    let client = end(&standin, Side::Client, Some(standin::client_key()));
    let node = end(&standin, Side::Node, Some(standin::node_key()));
    let link = LinkId([3; 16]);
    client.knock(&link).await.expect("the hello");
    let door = format!("up/{}", client.keys().door());
    assert_eq!(standin.keys("up/"), vec![door.clone()]);
    standin.age(&door, (board::DOOR_FRESH + Duration::from_secs(60)).as_secs() as i64);
    let answered = node.answer(Duration::from_secs(3)).await;
    assert!(answered.is_err(), "an old hello opens nothing: {answered:?}");
}

#[tokio::test]
async fn a_note_played_back_under_another_number_opens_nothing() {
    let standin = StandIn::start(rights(), &[]).await;
    let client = end(&standin, Side::Client, Some(standin::client_key()));
    let node = end(&standin, Side::Node, Some(standin::node_key()));
    let link = LinkId([5; 16]);
    client.send(Way::Up, &link, 0, b"piece zero").await.unwrap();
    // The plant: note 0's object again under note 1's name, as a bucket
    // that serves a repeated chunk would.
    let (zero, one) = (client.keys().topic(Way::Up, &link, 0), client.keys().topic(Way::Up, &link, 1));
    let body = standin.state.objects.lock().unwrap().get(&format!("up/{zero}")).unwrap().0.clone();
    standin.state.objects.lock().unwrap().insert(format!("up/{one}"), (body.clone(), 0));
    assert_eq!(node.receive(Way::Up, &link, 0, Duration::from_secs(5)).await.unwrap(), b"piece zero");
    let again = node.receive(Way::Up, &link, 1, Duration::from_secs(3)).await;
    assert!(again.is_err(), "a repeated chunk is not taken as piece 1: {again:?}");
    assert!(client.keys().open(Kind::Inline, Way::Up, &link, 1, &body).is_none());
}
