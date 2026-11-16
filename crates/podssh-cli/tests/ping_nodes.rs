//! `podssh ping --nodes` from end to end, on the loopback against podssh's
//! own relay role: three pairs of the role, `one` and `two` with their nodes
//! online in front of the test's SSH server, and `gone`, whose node never
//! runs, as a node that stopped. `two` also has a DERP ticket kept under its
//! name, whose server takes each connection and drops it, so that its race
//! has two roads where `one` has the pair's alone. One object names the three
//! in the order given, with the pair's road as the winner of `one` and `two`
//! and a code for `gone`; the exit is 1, and `gone` does not hold the run past
//! its `--timeout`. The refusals before anything connects close the file. It
//! says that it did not run when this host cannot make the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::net::TcpListener;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use pod_derp::{Key, Server, Ticket};
use podssh_relay::identity::Identity;
use serde_json::{json, Value};
use throughput_harness::{lines_of, wait_for, without_proxy, Cell, Session};

/// The bound on each run here.
const LIMIT: Duration = Duration::from_secs(120);
/// Each node's bound in the list's run.
const NODE_BOUND: Duration = Duration::from_secs(20);

/// The role, its host (`relay-a.test:PORT`) and its CA, or `None` when this
/// host cannot make its certificate.
fn role(s: &Session) -> Option<(Cell, String, String)> {
    let cell = match Cell::podssh_relay(s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    Some((cell, host, ca))
}

/// The variables of each run against the role: its CA, and its name pinned
/// to the loopback.
fn role_env(ca: &str) -> Vec<(String, String)> {
    vec![("SSL_CERT_FILE".into(), ca.to_string()), ("PODSSH_RELAY_ADDR".into(), "relay-a.test=127.0.0.1".into())]
}

/// `podssh ARGS` against the role, within `LIMIT`, and how long it took.
fn podssh(s: &Session, ca: &str, args: &[&str]) -> (Output, Duration) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let mut cmd = without_proxy(s.command(&args));
    cmd.envs(role_env(ca)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let deadline = started + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {args:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    (child.wait_with_output().unwrap(), took)
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// A pair of the role's under `label`.
fn pair(s: &Session, host: &str, ca: &str, label: &str) {
    let (out, _) = podssh(s, ca, &["relay", "pair", label, "--relay-host", host]);
    assert!(out.status.success(), "podssh relay pair {label} against the role: {}", said(&out));
}

/// The node of the pair under `label`, online in front of the test's server.
fn node(s: &Session, ca: &str, label: &str) {
    let args = vec!["node".to_string(), label.to_string(), format!("127.0.0.1:{}", s.port)];
    let mut node = without_proxy(s.command(&args))
        .envs(role_env(ca))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    wait_for(&lines, "online").expect("the node is online on the role");
}

/// A server of DERP in name only: it takes each connection and drops it, so
/// that the road to it starts and fails at once, on the loopback.
fn dropping_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            drop(conn);
        }
    });
    port
}

/// A DERP ticket kept under `label`, as a run that was given one keeps it:
/// its node's key from one byte, its server the one that drops.
fn keep_derp_ticket(s: &Session, label: &str, port: u16) {
    let ticket = Ticket {
        node: Identity::from_seed(&[0x22; 32]).public(),
        derp: Key([0x5a; 32]),
        server: Server::new("127.0.0.1", port).unwrap(),
    };
    let dir = s.home.join("cache").join("podssh");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let file = dir.join(format!("derp-{}.ticket", podssh_relay::cache::safe_name(label)));
    podssh_relay::cache::create_private(&file, format!("{ticket}\n").as_bytes()).unwrap();
}

/// The object of the node named `name` in the list's JSON.
fn node_of<'a>(doc: &'a Value, name: &str) -> &'a Value {
    let nodes = doc["nodes"].as_array().unwrap_or_else(|| panic!("no nodes: {doc}"));
    nodes.iter().find(|n| n["name"] == name).unwrap_or_else(|| panic!("no {name}: {doc}"))
}

/// The tokens of the pairs under `labels`, as this host keeps them.
fn pair_tokens(s: &Session, labels: &[&str]) -> Vec<String> {
    let dir = s.home.join("cache").join("podssh");
    let mut tokens = Vec::new();
    for label in labels {
        let file = dir.join(podssh_relay::pair::file_name(label).unwrap());
        let doc: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        for field in ["node_token", "connect_token", "stop_token"] {
            tokens.extend(doc[field].as_str().filter(|t| t.len() >= 8).map(str::to_string));
        }
    }
    assert!(!tokens.is_empty(), "the pairs keep their tokens here");
    tokens
}

fn roads_of(node: &Value) -> Vec<String> {
    let roads = node["roads"].as_array().cloned().unwrap_or_default();
    roads.iter().filter_map(|road| road["road"].as_str().map(str::to_string)).collect()
}

#[test]
fn ping_nodes_measures_each_node_of_the_list_in_one_object() {
    let s = Session::start("ping-nodes");
    let Some((_, host, ca)) = role(&s) else { return };
    for label in ["one", "two", "gone"] {
        pair(&s, &host, &ca, label);
    }
    node(&s, &ca, "one");
    node(&s, &ca, "two");
    keep_derp_ticket(&s, "two", dropping_server());

    let bound = format!("{}s", NODE_BOUND.as_secs());
    let list = ["ping", "--nodes", "one,node://two,gone", "--parallel", "3", "--timeout", &bound];
    let mut json_list = list.to_vec();
    json_list.push("--json");
    let (out, took) = podssh(&s, &ca, &json_list);
    assert_eq!(out.status.code(), Some(1), "one node of three is not reached: {}", said(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one object: {e}: {}", said(&out)));
    assert_eq!((&doc["schema"], &doc["exit"]), (&json!(1), &json!(1)), "{doc}");
    let nodes = doc["nodes"].as_array().cloned().unwrap_or_default();
    let names: Vec<&Value> = nodes.iter().map(|n| &n["name"]).collect();
    assert_eq!(names, [&json!("node://one"), &json!("node://two"), &json!("node://gone")], "in the order given: {doc}");

    // one: the pair's road answered, and no ticket gave it another road.
    let one = node_of(&doc, "node://one");
    assert_eq!((&one["won"], &one["code"], &one["error"]), (&json!("the pair's road"), &json!(0), &Value::Null));
    assert_eq!(roads_of(one).first().map(String::as_str), Some("the pair's road"), "{one}");
    assert!(!roads_of(one).iter().any(|road| road == "the DERP road"), "{one}");
    assert!(one["won_ms"].as_f64().is_some_and(|ms| ms > 0.0), "{one}");

    // two: two roads, the DERP road's server drops it, the pair's answers.
    let two = node_of(&doc, "node://two");
    assert_eq!((&two["won"], &two["code"]), (&json!("the pair's road"), &json!(0)), "{two}");
    let roads = roads_of(two);
    assert!(roads.len() >= 2 && roads.iter().any(|road| road == "the DERP road"), "two roads: {two}");
    let derp = two["roads"].as_array().unwrap().iter().find(|r| r["road"] == "the DERP road").unwrap();
    assert_eq!(derp["answered"], false, "a server that drops each connection answers nothing: {two}");

    // gone: no road answered, and it says why with its code.
    let gone = node_of(&doc, "node://gone");
    assert_eq!(gone["won"], Value::Null, "{gone}");
    let code = gone["code"].as_i64().unwrap_or_default();
    assert!(code == 69 || code == 75, "not reached, or past its bound: {gone}");
    assert!(gone["error"].as_str().is_some_and(|why| !why.is_empty()), "{gone}");

    // The node that stopped holds no one past its bound: the three run at
    // once, so the run ends within one bound and the time to start.
    assert!(took < NODE_BOUND + Duration::from_secs(15), "the run took {took:?}: {}", said(&out));
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    for token in pair_tokens(&s, &["one", "two", "gone"]) {
        assert!(!shown.contains(&token), "a token of a pair is in the output");
    }

    // The lines: each node's, in the order given, then the count.
    let (out, _) = podssh(&s, &ca, &list);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("node://one: the pair's road answered first, in "), "{text}");
    assert!(text.contains("node://two: the pair's road answered first, in "), "{text}");
    assert!(text.lines().any(|l| l.starts_with("node://gone: ")), "{text}");
    assert_eq!(text.lines().last(), Some("2 of 3 nodes answered"), "{text}");
}

/// The refusals of a list, each before anything connects: a host's flag
/// (64), `--parallel` with no list (64), a bad `--parallel` (64), and
/// `--net` with no net held (78).
#[test]
fn a_list_refuses_a_host_s_flags_and_net_needs_a_net() {
    let s = Session::start("ping-nodes-refused");
    let run = |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let mut cmd = without_proxy(s.command(&args));
        let out = cmd.env_remove("PODSSH_NET").stdin(Stdio::null()).output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let (code, err) = run(&["ping", "--nodes", "one", "--size", "1M"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--size"), "{err}");
    let (code, err) = run(&["ping", "--parallel", "2"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--nodes or --net"), "{err}");
    let (code, err) = run(&["ping", "--nodes", "one", "--parallel", "65"]);
    assert_eq!(code, Some(64), "{err}");
    let (code, err) = run(&["ping", "--nodes", "one", "--net"]);
    assert_eq!(code, Some(64), "{err}");
    let (code, err) = run(&["ping", "--net"]);
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("--net"), "{err}");
}
