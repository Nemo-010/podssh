//! `-J node://NAME` (T-724): a node of `podssh relay serve`'s pair as the
//! first hop of a chain, on the loopback. The node serves OpenSSH's sshd,
//! and the destination behind the hop is that sshd again, by its address:
//! the hop's key is checked under `node://lab`, the destination's under its
//! own name, and a wrong key of the node is refused (255) before anything
//! runs. A node as a later hop is refused with the words of the rule.
#![cfg(unix)]

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, without_proxy, Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// The roads of a node beside the pair's, which a run on the loopback
/// keeps off: each would look for a service on the internet.
const OFF: &[&str] = &[
    "PODSSH_TRANSIT",
    "PODSSH_CROC",
    "PODSSH_LOCALHOST_RUN",
    "PODSSH_SANDHOLE",
    "PODSSH_SRV_US",
    "PODSSH_TUNNL_GG",
    "PODSSH_LOCALTUNNEL",
    "PODSSH_HOSTC",
    "PODSSH_SMEE",
    "PODSSH_BORE",
];

/// `podssh ARGS` against the role at `ca`, within `LIMIT`.
fn podssh(s: &Session, ca: &str, args: &[String]) -> Output {
    let mut cmd = without_proxy(s.command(args));
    cmd.env("SSL_CERT_FILE", ca).env("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1").env("PODSSH_SSH_CONFIG", "none");
    for name in OFF {
        cmd.env(name, "no");
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

/// This user's name, for the login to the loopback's sshd.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

#[test]
fn a_node_is_the_first_hop_of_a_chain_and_its_key_is_checked_under_its_name() {
    let s = Session::start("node-jump");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => return eprintln!("did not run: {why}"),
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    let Some(user) = this_user() else { return eprintln!("did not run: no user name here") };
    let dir = s.home.join("jump");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let made = podssh(&s, &ca, &words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key.display().to_string()]));
    assert!(made.status.success(), "{}", said(&made));
    let sshd = match live_harness::sshd::start(&dir, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let out = podssh(&s, &ca, &words(&["relay", "pair", "lab", "--relay-host", &host]));
    assert!(out.status.success(), "podssh relay pair: {}", said(&out));
    let node_args = words(&["node", "lab", &format!("127.0.0.1:{}", sshd.port)]);
    let mut node = without_proxy(s.command(&node_args))
        .env("SSL_CERT_FILE", &ca)
        .env("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    wait_for(&lines, "online").expect("the node is online on the role");

    let known = dir.join("known_hosts");
    let ssh = |strict: &str, hops: &str| {
        let port = sshd.port.to_string();
        let kh = format!("UserKnownHostsFile={}", known.display());
        let strict = format!("StrictHostKeyChecking={strict}");
        let dest = format!("{user}@127.0.0.1");
        let key = key.display().to_string();
        podssh(
            &s,
            &ca,
            &words(&[
                "ssh",
                "-J",
                hops,
                "-p",
                &port,
                "-i",
                &key,
                "-o",
                &kh,
                "-o",
                &strict,
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                &dest,
                "echo",
                "behind-the-node",
            ]),
        )
    };
    let hop = format!("node://{user}@lab");
    let out = ssh("accept-new", &hop);
    assert!(out.status.success(), "-J node://lab: {}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("behind-the-node"), "{}", said(&out));
    let recorded = std::fs::read_to_string(&known).unwrap();
    assert!(recorded.lines().any(|l| l.starts_with("node://lab ")), "the hop's key under its name: {recorded}");
    assert!(recorded.lines().any(|l| l.contains("127.0.0.1")), "the destination's under its own: {recorded}");

    // The node's key changed: refused before the destination is reached.
    let other = dir.join("other");
    let made =
        podssh(&s, &ca, &words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &other.display().to_string()]));
    assert!(made.status.success(), "{}", said(&made));
    let wrong = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    let wrong: Vec<&str> = wrong.split_whitespace().take(2).collect();
    let swapped: String = recorded
        .lines()
        .map(|l| {
            if l.starts_with("node://lab ") {
                format!("node://lab {} {}\n", wrong[0], wrong[1])
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    std::fs::write(&known, swapped).unwrap();
    let out = ssh("yes", &hop);
    assert_eq!(out.status.code(), Some(255), "a wrong key of the node: {}", said(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("behind-the-node"), "{}", said(&out));

    // A node is the first hop alone.
    let out = ssh("yes", &format!("{user}@127.0.0.1:{},node://lab", sshd.port));
    assert_eq!(out.status.code(), Some(64), "{}", said(&out));
    assert!(said(&out).contains("a node can only be the first hop"), "{}", said(&out));
}
