//! The credentials of Cloudflare Access on a WebSocket road that podssh
//! builds (T-718), against a stand-in edge on the loopback that demands the
//! two headers of a service token, as Access does (no account): `podssh
//! pipe` reaches it with the id and the secret read from their files, and
//! the edge sees them; a host that was not named gets no header (a road
//! that sent them to each host fails here); a missing file is refused before
//! anything connects, naming its variable; and an edge that quotes the
//! secret in its refusal does not get it onto stderr. The relay's road, a
//! pair's road and `operator` are `pod-relay`'s, and wait for its headers.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::frame::{self, Frame, Role};

const LIMIT: Duration = Duration::from_secs(30);
const ID: &str = "id-of-this-test.access";
const SECRET: &str = "secret-of-this-test-0f3a9c";
const ID_FILE: &str = "PODSSH_CF_ACCESS_CLIENT_ID_FILE";
const SECRET_FILE: &str = "PODSSH_CF_ACCESS_CLIENT_SECRET_FILE";

/// The heads of the upgrades that the edge read, header names in lower case.
type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

/// An edge of Access on a free port of the loopback: an upgrade with the id
/// and the secret of `want` gets 101 and an echo of each binary message;
/// another gets 403, whose body quotes the secret that came when `quote`.
fn edge(want: (&'static str, &'static str), quote: bool) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let kept = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let _ = stream.set_read_timeout(Some(LIMIT));
            let headers = read_head(&mut stream);
            kept.lock().unwrap().push(headers.clone());
            let get = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
            let (id, secret) = (get("cf-access-client-id"), get("cf-access-client-secret"));
            if id.as_deref() == Some(want.0) && secret.as_deref() == Some(want.1) {
                let accept = podssh_ws::handshake::accept_key(&get("sec-websocket-key").unwrap_or_default());
                let head = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if stream.write_all(head.as_bytes()).is_ok() {
                    echo(&mut stream);
                }
            } else {
                let body = match (quote, secret) {
                    (true, Some(secret)) => format!("forbidden: Cf-Access-Client-Secret {secret} is not ours"),
                    _ => "forbidden".to_string(),
                };
                let length = body.len();
                let head = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {length}\r\n\
                     Connection: close\r\n\r\n"
                );
                let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body.as_bytes()));
            }
        }
    });
    (port, seen)
}

/// The head of a request, its headers as (lower-case name, value).
fn read_head(stream: &mut TcpStream) -> Vec<(String, String)> {
    let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
    while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    text.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// Each binary message back, until the client's Close, which is answered.
fn echo(stream: &mut TcpStream) {
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    loop {
        while let Ok(Some((f, used))) = frame::decode(&buf, Role::Client) {
            buf.drain(..used);
            let (opcode, payload) = match f.opcode {
                frame::OPCODE_BINARY => (frame::OPCODE_BINARY, f.payload),
                frame::OPCODE_CLOSE => (frame::OPCODE_CLOSE, 1000u16.to_be_bytes().to_vec()),
                _ => continue,
            };
            let answer = Frame { fin: true, opcode, payload };
            let closing = answer.opcode == frame::OPCODE_CLOSE;
            if stream.write_all(&frame::encode(&answer, Role::Server, [0; 4])).is_err() || closing {
                return;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A file of this test that holds `text`, removed when the test ends.
struct Temp(std::path::PathBuf);

impl Temp {
    fn new(name: &str, text: &str) -> Temp {
        // A number of its own for each file: the tests run at once in one
        // process, and one's end must not take another's file.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("podssh-access-headers-{}-{n}-{name}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        Temp(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `podssh pipe ARGS` with `set` and none of the machine's settings, its
/// stdin `input`: its code, stdout and stderr, within the limit.
fn pipe(args: &[&str], set: &[(&str, &str)], input: &[u8]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("pipe").args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "PODSSH_OFFLINE",
        "PODSSH_CF_ACCESS_CLIENT_ID",
        "PODSSH_CF_ACCESS_CLIENT_SECRET",
        "PODSSH_CF_ACCESS_TOKEN",
        "PODSSH_CF_ACCESS_TOKEN_FILE",
        ID_FILE,
        SECRET_FILE,
    ] {
        cmd.env_remove(name);
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    let code = ended(&mut child);
    let (mut out, mut err) = (String::new(), String::new());
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    (code, out, err)
}

fn ended(child: &mut Child) -> i32 {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh pipe did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn files() -> (Temp, Temp) {
    (Temp::new("id", &format!("{ID}\n")), Temp::new("secret", &format!("  {SECRET}\n")))
}

fn has_access_header(head: &[(String, String)]) -> bool {
    head.iter().any(|(n, _)| n.starts_with("cf-access-"))
}

#[test]
fn a_named_host_gets_the_service_token_of_the_files() {
    let (port, seen) = edge((ID, SECRET), false);
    let (id, secret) = files();
    let url = format!("ws://127.0.0.1:{port}/");
    let set = [(ID_FILE, id.path()), (SECRET_FILE, secret.path())];
    let (code, out, err) = pipe(&["--access-host", "127.0.0.1", "-", &url], &set, b"there and back\n");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "there and back\n", "{err}");
    let heads = seen.lock().unwrap();
    assert_eq!(heads.len(), 1, "one upgrade");
    assert!(heads[0].contains(&("cf-access-client-id".into(), ID.into())), "{:?}", heads[0]);
    assert!(!err.contains(SECRET), "{err}");
}

/// The planted defect of a road that sends the headers to each host: the
/// edge would take the session, and this test would see a header.
#[test]
fn a_host_that_was_not_named_gets_no_header() {
    let (port, seen) = edge((ID, SECRET), false);
    let (id, secret) = files();
    let url = format!("ws://127.0.0.1:{port}/");
    let set = [(ID_FILE, id.path()), (SECRET_FILE, secret.path())];
    let (code, _, err) = pipe(&["-", &url], &set, b"x");
    assert_eq!(code, 77, "Access refused the bare upgrade: {err}");
    let heads = seen.lock().unwrap();
    assert_eq!(heads.len(), 1, "one upgrade");
    assert!(!has_access_header(&heads[0]), "a header went to a host that was not named: {:?}", heads[0]);
}

#[test]
fn a_flag_or_a_file_that_cannot_serve_is_refused_before_anything_connects() {
    let (port, seen) = edge((ID, SECRET), false);
    let (id, secret) = files();
    let url = format!("ws://127.0.0.1:{port}/");
    let named = ["--access-host", "127.0.0.1", "-", &url];
    // A missing file: its variable, and no connection.
    let (code, _, err) = pipe(&named, &[(ID_FILE, id.path()), (SECRET_FILE, "/no/such/file/of/this/test")], b"");
    assert_eq!(code, 78, "{err}");
    assert!(err.contains(SECRET_FILE) && !err.contains(ID), "{err}");
    // Half a service token, and none at all: the variables by name.
    let (code, _, err) = pipe(&named, &[(ID_FILE, id.path())], b"");
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("PODSSH_CF_ACCESS_CLIENT_SECRET") && !err.contains(ID), "{err}");
    let (code, _, err) = pipe(&named, &[], b"");
    assert_eq!(code, 78, "{err}");
    assert!(err.contains(ID_FILE) && err.contains(SECRET_FILE), "{err}");
    // A flag that names no side, and ws: off the loopback.
    let set = [(ID_FILE, id.path()), (SECRET_FILE, secret.path())];
    let (code, _, err) = pipe(&["--access-host", "edge.example", "-", &url], &set, b"");
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("--access-host"), "{err}");
    let (code, _, err) = pipe(&["--access-host", "edge.example", "-", "ws://edge.example/"], &set, b"");
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("wss://"), "{err}");
    assert!(seen.lock().unwrap().is_empty(), "something connected");
}

/// An edge that quotes the secret it got: the planted leak of a value into
/// the line of a refusal, which podssh masks.
#[test]
fn a_refusal_that_quotes_the_secret_does_not_show_it() {
    let (port, seen) = edge((ID, "another-secret"), true);
    let (id, secret) = files();
    let url = format!("ws://127.0.0.1:{port}/");
    let set = [(ID_FILE, id.path()), (SECRET_FILE, secret.path())];
    let (code, _, err) = pipe(&["--access-host", "127.0.0.1", "-", &url], &set, b"x");
    assert_eq!(code, 77, "{err}");
    assert_eq!(seen.lock().unwrap().len(), 1, "the edge read the upgrade");
    assert!(err.contains("forbidden"), "the edge's words: {err}");
    assert!(!err.contains(SECRET), "the secret was shown: {err}");
    assert!(err.contains("PODSSH_CF_ACCESS_CLIENT_SECRET"), "the variable by name: {err}");
}
