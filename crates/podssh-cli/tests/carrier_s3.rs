//! The bucket carrier (T-725), through the binary: `podssh node box TARGET
//! --carrier s3:FILE` and `podssh operator --carrier s3:FILE box`, with no
//! relay and no pair, through pod-link's stand-in of the S3 API on the
//! loopback (PodUtils/podcrates, software that podssh did not write), which
//! checks each request's Signature Version 4. 1 MiB comes back whole from an
//! echo server behind the node, and both ends exit 0; the bucket holds no
//! byte of it in clear. A wrong key (the plant: a signature that the
//! stand-in recomputes and refuses) is said, with 69, in time; and a file
//! with a key in it is refused with 78, showing no word of the key.

mod live_harness;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use live_harness::{echo_server, scratch};
use pod_link::s3::standin::{self, StandIn};

/// The bucket's road polls each 2 to 3 s, and the node's door 10 s apart
/// at most: a run takes a minute, not seconds.
const LIMIT: Duration = Duration::from_secs(300);
const BUCKET: &str = "links";

/// Removes the scratch directory, with its keys, however the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ends a node that a failed test left running.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// `name.conf` in `dir` for the stand-in at `url`, with `secret` (the
/// stand-in's own made-up key unless another is given).
fn bucket_file(dir: &Path, name: &str, url: &str, key_secret: Option<&str>) -> String {
    let key = standin::key();
    let secret_key = key_secret.unwrap_or(&key.secret_key);
    let keys = format!("[default]\naws_access_key_id = {}\naws_secret_access_key = {secret_key}\n", key.access_key);
    std::fs::write(dir.join(format!("{name}.keys")), keys).unwrap();
    std::fs::write(dir.join("pair.secret"), "the pair's secret of this test, not a real one\n").unwrap();
    let settings = format!(
        "endpoint = {url}\nbucket = {BUCKET}\nup = box/up\ndown = box/down\n\
         credentials = {name}.keys\nsecret-file = pair.secret\n"
    );
    let file = dir.join(format!("{name}.conf"));
    std::fs::write(&file, settings).unwrap();
    format!("s3:{}", file.display())
}

/// `cmd` with `input` on stdin, within `limit`: its code, stdout, stderr.
fn run_with(mut cmd: Command, input: Vec<u8>, limit: Duration) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut stdin = child.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = tx.send(bytes);
        });
        rx
    };
    let out = reader(Box::new(child.stdout.take().expect("stdout")));
    let err = reader(Box::new(child.stderr.take().expect("stderr")));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (out, err) = (out.recv_timeout(LIMIT).unwrap_or_default(), err.recv_timeout(LIMIT).unwrap_or_default());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
}

/// The node's exit code within `limit`, and its stderr.
fn node_end(mut node: Running, limit: Duration) -> (Option<i32>, String) {
    let deadline = Instant::now() + limit;
    let code = loop {
        if let Some(status) = node.0.try_wait().expect("wait") {
            break status.code();
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut err = String::new();
    if let Some(mut pipe) = node.0.stderr.take() {
        if code.is_some() {
            let _ = pipe.read_to_string(&mut err);
        }
    }
    (code, err)
}

#[test]
fn an_operator_reaches_a_node_through_a_bucket_and_both_end_with_0() {
    let home = scratch("bucket-echo");
    let _scratch = Scratch(home.clone());
    let standin = StandIn::start_thread(&[BUCKET]).expect("the stand-in");
    let target = format!("127.0.0.1:{}", echo_server());
    let node_carrier = bucket_file(&home, "node", &standin.url(), None);
    let client_carrier = bucket_file(&home, "client", &standin.url(), None);
    let node = live_harness::command(&home, &["node", "box", &target, "--carrier", &node_carrier])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let node = Running(node);
    let sent = pattern(1 << 20);
    let operator = live_harness::command(&home, &["operator", "--carrier", &client_carrier, "box"]);
    let (code, out, err) = run_with(operator, sent.clone(), LIMIT);
    let (node_code, node_err) = node_end(node, Duration::from_secs(120));
    let both = format!("{err}\nthe node: {node_err}");
    assert_eq!(code, Some(0), "{both}");
    assert!(out == sent, "{} bytes came back, changed or short: {both}", out.len());
    assert_eq!(node_code, Some(0), "the client's Close ends the node: {both}");
    assert!(node_err.contains("over the carrier s3:"), "{both}");
    // Each object is sealed: no run of the pattern is in the bucket.
    let probe = &sent[1000..1064];
    for (name, object) in standin.buckets().get(BUCKET).into_iter().flatten() {
        assert!(!object.body.windows(probe.len()).any(|w| w == probe), "{name} holds the bytes in clear");
    }
    assert_eq!(standin.counts().refused, 0, "each request was signed rightly");
}

#[test]
fn a_wrong_key_is_refused_by_the_bucket_and_said_with_69() {
    let home = scratch("bucket-wrong");
    let _scratch = Scratch(home.clone());
    let standin = StandIn::start_thread(&[BUCKET]).expect("the stand-in");
    // The plant: the right id with another secret, so the stand-in's own
    // signature of the canonical request differs from the one that came.
    let carrier = bucket_file(&home, "client", &standin.url(), Some("not-the-stand-in-s-secret"));
    let operator = live_harness::command(&home, &["operator", "--carrier", &carrier, "box"]);
    let (code, out, err) = run_with(operator, Vec::new(), Duration::from_secs(60));
    assert_eq!(code, Some(69), "{err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("SignatureDoesNotMatch"), "{err}");
    assert!(!err.contains("not-the-stand-in-s-secret"), "no word of the key: {err}");
    assert!(standin.counts().refused >= 1);
}

#[test]
fn a_bucket_s_file_with_a_key_in_it_is_refused_with_78() {
    let home = scratch("bucket-file");
    let _scratch = Scratch(home.clone());
    let file = home.join("bad.conf");
    let secret = "a-made-up-secret-that-must-not-show";
    let settings = format!(
        "endpoint = https://s3.example.test\nbucket = links\nup = u\ndown = d\naws_secret_access_key = {secret}\n"
    );
    std::fs::write(&file, settings).unwrap();
    let carrier = format!("s3:{}", file.display());
    for args in [
        vec!["operator", "--carrier", carrier.as_str(), "box"],
        vec!["node", "box", "127.0.0.1:1", "--carrier", carrier.as_str()],
    ] {
        let (code, out, err) = run_with(live_harness::command(&home, &args), Vec::new(), Duration::from_secs(30));
        assert_eq!(code, Some(78), "{args:?}: {err}");
        assert!(out.is_empty() && !err.contains(secret), "{args:?}: {err}");
        assert!(err.contains("a key goes in its own file"), "{args:?}: {err}");
    }
}
