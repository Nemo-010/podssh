//! A node's route to a Unix socket (T-714) from end to end, through the
//! stand-in relay's reverse road on the loopback: a stand-in service on a
//! socket in a temporary directory reads the caller's line and echoes it.
//! Two keys give two lines; a key that the door refuses gives the socket no
//! connection; a route with no `--caller-line` gets no line; a socket that
//! is gone is named. On Windows the socket is AF_UNIX. Each check says that
//! it did not run when this host has no Python or no openssl for the
//! stand-in.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// How long the stand-in service waits for a line.
const WAIT: Duration = Duration::from_secs(5);

#[cfg(unix)]
mod sock {
    use std::os::unix::net::{UnixListener, UnixStream};

    pub struct Listener(UnixListener);

    impl Listener {
        pub fn bind(path: &str) -> Listener {
            Listener(UnixListener::bind(path).expect("a socket in the test's directory"))
        }

        pub fn accept(&self) -> Option<UnixStream> {
            self.0.accept().ok().map(|(stream, _)| stream)
        }
    }
}

/// An AF_UNIX listener by WinSock, as the standard library has none on
/// Windows; a connected socket of any family carries bytes as a TCP one.
#[cfg(windows)]
mod sock {
    use std::net::TcpStream;
    use std::os::windows::io::FromRawSocket;

    use windows_sys::Win32::Networking::WinSock as ws;

    pub struct Listener(ws::SOCKET);

    impl Listener {
        pub fn bind(path: &str) -> Listener {
            // SAFETY: an all-zero SOCKADDR_UN is valid.
            let mut addr: ws::SOCKADDR_UN = unsafe { std::mem::zeroed() };
            addr.sun_family = ws::AF_UNIX;
            for (slot, b) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
                *slot = *b as _;
            }
            let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
            // SAFETY: WinSock calls on a socket of this test.
            unsafe {
                let mut data: ws::WSADATA = std::mem::zeroed();
                assert_eq!(ws::WSAStartup(0x0202, &mut data), 0);
                let s = ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0);
                assert_ne!(s, ws::INVALID_SOCKET, "AF_UNIX on this Windows");
                assert_eq!(ws::bind(s, (&addr as *const ws::SOCKADDR_UN).cast(), len), 0, "bind");
                assert_eq!(ws::listen(s, 8), 0, "listen");
                Listener(s)
            }
        }

        pub fn accept(&self) -> Option<TcpStream> {
            // SAFETY: an accept on the listener above; the socket is owned by the stream.
            unsafe {
                let s = ws::accept(self.0, std::ptr::null_mut(), std::ptr::null_mut());
                (s != ws::INVALID_SOCKET).then(|| TcpStream::from_raw_socket(s as u64))
            }
        }
    }
}

/// A service at `path` that reads one line of each connection and answers
/// `got LINE`, and counts the connections.
fn echo_line(path: &str) -> Arc<AtomicUsize> {
    let listener = sock::Listener::bind(path);
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        while let Some(mut stream) = listener.accept() {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(WAIT));
            let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
            while let Ok(1) = stream.read(&mut byte) {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            let _ = stream.write_all(b"got ");
            let _ = stream.write_all(&line);
        }
    });
    count
}

/// A service at `path` that writes `raw` first, and keeps what came to it.
fn raw(path: &str) -> Arc<Mutex<Vec<u8>>> {
    let listener = sock::Listener::bind(path);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = seen.clone();
    std::thread::spawn(move || {
        while let Some(mut stream) = listener.accept() {
            let _ = stream.write_all(b"raw\n");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut came = Vec::new();
            let _ = stream.read_to_end(&mut came);
            kept.lock().unwrap().extend(came);
        }
    });
    seen
}

/// What an operator got: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// A short directory of its own: a socket's address holds about 100 bytes.
fn socket_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pt714-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_unix_route_gets_the_line_of_each_key_that_the_door_let_in() {
    let session = Session::start("unix-route");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&mut command(&words(&["relay", "pair", "lab", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let dir = socket_dir();
    let path = |name: &str| dir.join(name).display().to_string();
    let (api, plain, gone) = (path("api.sock"), path("raw.sock"), path("missing.sock"));
    let api_seen = echo_line(&api);
    let raw_seen = raw(&plain);
    // In a directory of its own: the node refuses an allowlist that others
    // can change, as this host's temporary directory lets them.
    let private = session.home.join("private");
    podssh_relay::cache::private_dir(&private).unwrap();
    let allow = private.join("allow");
    std::fs::write(&allow, "# no key yet\n").unwrap();
    let node_args = words(&[
        "node",
        "lab",
        &format!("api=unix-connect:{api}"),
        &format!("raw=unix-connect:{plain}"),
        &format!("gone=unix-connect:{gone}"),
        "--caller-line",
        "api",
        "--allow",
        &allow.display().to_string(),
    ]);
    let mut node = command(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let first = wait_for(&lines, "serving").expect("the node starts");
    assert!(first.contains(&format!("api=unix-connect:{api} (caller line)")), "the first line names it: {first}");
    wait_for(&lines, "online").expect("the node is online");
    let key = |name: &str| session.home.join(name).display().to_string();
    let (key_a, key_b) = (key("a.key"), key("b.key"));
    let operator = |route: &str, client: &str| ran(&mut command(&words(&["operator", "--client-key", client, route])));
    // No key in the allowlist: each key is refused, and the socket sees
    // no connection.
    let fingerprint = |client: &str| {
        let (rc, _, err) = operator("lab/api", client);
        assert_ne!(rc, 0, "{err}");
        let refused = err.lines().find(|l| l.contains("refused this client's key")).expect("the key is named");
        let found = refused.split_whitespace().find(|w| w.starts_with("SHA256:")).expect("the client's key");
        found.trim_end_matches([':', ';']).to_string()
    };
    let (fp_a, fp_b) = (fingerprint(key_a.as_str()), fingerprint(key_b.as_str()));
    assert_ne!(fp_a, fp_b);
    assert_eq!(api_seen.load(Ordering::SeqCst), 0, "a key that the door refused reached the socket");
    std::fs::write(&allow, format!("{fp_a} routes=api,raw,gone a\n{fp_b} routes=api b\n")).unwrap();
    // Each key let in: its own line, which the service reads before the stream.
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    for (client, fp) in [(key_a.as_str(), &fp_a), (key_b.as_str(), &fp_b)] {
        let (rc, out, err) = operator("lab/api", client);
        assert_eq!(rc, 0, "{err}\nthe node:\n{}", said());
        assert_eq!(out, format!("got podssh-caller v1 {fp} api\n"), "{err}");
    }
    assert_eq!(api_seen.load(Ordering::SeqCst), 2);
    // A route that the key may not use is refused before the socket.
    let (rc, out, err) = operator("lab/raw", key_b.as_str());
    assert!(rc != 0 && out.is_empty() && err.contains("may not use the route raw"), "{err}");
    // With no --caller-line, the node writes nothing of its own.
    let (rc, out, err) = operator("lab/raw", key_a.as_str());
    assert_eq!((rc, out.as_str()), (0, "raw\n"), "{err}");
    assert!(raw_seen.lock().unwrap().is_empty(), "a plain route got bytes of the node");
    // A socket that is gone: its path is named.
    let (rc, _, err) = operator("lab/gone", key_a.as_str());
    assert!(rc != 0 && err.contains("missing.sock"), "{err}\nthe node:\n{}", said());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_node_refuses_a_unix_route_that_it_cannot_serve() {
    let home = throughput_harness::scratch("unix-route-refused");
    for (extra, says) in [
        (vec!["--sshd"], "--sshd"),
        (vec!["--exit"], "--exit"),
        (vec!["--no-e2e"], "--no-e2e"),
        (vec!["--caller-line", "web"], "no route web"),
    ] {
        let mut args = vec!["node".to_string(), "lab".into(), "api=unix-connect:/tmp/pt714.sock".into()];
        args.extend(extra.iter().map(|w| w.to_string()));
        let (rc, _, err) = ran(&mut throughput_harness::command_in(&home, &args));
        assert_eq!(rc, 64, "{extra:?}: {err}");
        assert!(err.contains(says), "{extra:?}: {err}");
    }
    let args = ["node", "lab", "unix-connect:/tmp/pt714.sock"].map(String::from);
    let (rc, _, err) = ran(&mut throughput_harness::command_in(&home, &args));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("has a route"), "{err}");
}
