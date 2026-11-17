//! `podssh relay conform` (T-713): each check passes against podssh's own
//! relay role on the loopback (`podssh relay serve`, with a short idle cut
//! and keepalive so that the run waits seconds), with a target that echoes
//! and the reverse road; a stand-in relay (`scripts/fake-relay.py`) with a
//! planted fault fails that check and exits 1, where the stand-in that
//! behaves does not; and the command line's refusals.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(240);

/// A target that echoes each byte, and closes once its client did.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// The relay flags of a cell: its host, its CA and the pinned address.
fn relay_flags(cell: &Cell) -> Vec<String> {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    vec![
        "--relay-host".into(),
        at("--relay-host"),
        "--ca-file".into(),
        at("--ca-file"),
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
    ]
}

/// `podssh relay conform ARGS`, with no proxy and no token of this host.
fn conform(s: &Session, args: &[String]) -> Output {
    let mut all = vec!["relay".to_string(), "conform".into()];
    all.extend(args.iter().cloned());
    let mut cmd = s.command(&all);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    ran(cmd)
}

fn ran(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// The report of a run with --json, and each check's verdict by its id.
fn verdicts(out: &Output) -> Vec<(String, String)> {
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("not JSON: {}", said(out)));
    let checks = doc["checks"].as_array().unwrap_or_else(|| panic!("no checks: {doc}"));
    checks.iter().map(|c| (c["id"].as_str().unwrap().to_string(), c["verdict"].as_str().unwrap().to_string())).collect()
}

fn verdict_of(all: &[(String, String)], id: &str) -> String {
    all.iter().find(|(i, _)| i == id).map(|(_, v)| v.clone()).unwrap_or_else(|| panic!("no check {id}: {all:?}"))
}

#[test]
fn each_check_passes_against_podsshs_own_relay_role() {
    let s = Session::start("conform-role");
    let extra = ["--routes", "127.0.0.1", "--idle", "4", "--keepalive", "1"];
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &extra) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let target = format!("127.0.0.1:{}", echo_target());
    let mut args = relay_flags(&cell);
    args.extend(["--target".to_string(), target, "--reverse".into(), "--json".into()]);
    let out = conform(&s, &args);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let all = verdicts(&out);
    assert!(all.iter().all(|(_, v)| v != "fail"), "{all:?}");
    for id in [
        "health",
        "relays-json",
        "mint",
        "upgrade-no-token",
        "upgrade-wrong-token",
        "token-in-query",
        "dial-lazy",
        "ping",
        "close-before-dial",
        "private-target",
        "target-bytes",
        "close-after-bytes",
        "keepalive",
        "idle-cut",
        "pair",
        "node-hello",
        "open",
        "bytes",
        "leg-close",
        "status",
        "stop-wrong-token",
        "ext.renew",
        "ext.halt",
        "stop",
        "stopped",
    ] {
        assert_eq!(verdict_of(&all, id), "pass", "{id}: {}", said(&out));
    }
    // No credential in the output: no token of the role's forms, whose
    // expiry in ms begins with 1 until 2286.
    let text = said(&out);
    assert!(!text.contains("ephm1.1") && !text.contains("once1.1"), "{text}");
}

/// The stand-in in `mode`, run with no target: the verdicts of a run.
fn stand_in(s: &Session, mode: &str) -> Option<(Output, Vec<(String, String)>)> {
    let cell = match Cell::fake_relay_mode(s, mode, "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let mut args = relay_flags(&cell);
    args.push("--json".into());
    let out = conform(s, &args);
    let all = verdicts(&out);
    Some((out, all))
}

#[test]
fn a_planted_close_code_fails_its_check_and_exits_1() {
    let s = Session::start("conform-close");
    let Some((_, behaves)) = stand_in(&s, "normal") else { return };
    assert_eq!(verdict_of(&behaves, "close-before-dial"), "pass", "{behaves:?}");
    let Some((out, planted)) = stand_in(&s, "wrongclose") else { return };
    assert_eq!(verdict_of(&planted, "close-before-dial"), "fail", "{}", said(&out));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
}

#[test]
fn a_planted_token_in_the_query_string_fails_its_check_and_exits_1() {
    let s = Session::start("conform-query");
    // The stand-in that behaves mints no token of one session: no URL holds one.
    let Some((_, behaves)) = stand_in(&s, "normal") else { return };
    assert_eq!(verdict_of(&behaves, "token-in-query"), "skip", "{behaves:?}");
    let Some((out, planted)) = stand_in(&s, "querytoken") else { return };
    assert_eq!(verdict_of(&planted, "token-in-query"), "fail", "{}", said(&out));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
}

#[test]
fn conform_refuses_no_host_several_hosts_and_its_flags_elsewhere() {
    let s = Session::start("conform-usage");
    let cases: [(&[&str], &str); 5] = [
        (&["relay", "conform"], "needs --relay-host"),
        (&["relay", "conform", "--relay-host", "a.test,b.test"], "one host"),
        (&["relay", "conform", "word", "--relay-host", "a.test"], "takes no NAME"),
        (&["relay", "status", "--reverse"], "goes with `podssh relay conform` only"),
        (&["relay", "status", "--target", "a.test:22"], "goes with `podssh relay rank` and"),
    ];
    for (args, says) in cases {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let out = ran(s.command(&args));
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", said(&out));
        assert!(said(&out).contains(says), "{args:?}: {}", said(&out));
    }
}

#[test]
fn a_host_that_does_not_answer_is_69() {
    let s = Session::start("conform-gone");
    // A port that nothing holds, for a moment.
    let gone = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let args = [
        "--relay-host".to_string(),
        format!("relay-a.test:{gone}"),
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
    ];
    let out = conform(&s, &args);
    assert_eq!(out.status.code(), Some(69), "{}", said(&out));
    assert!(said(&out).contains("did not answer"), "{}", said(&out));
}
