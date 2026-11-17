//! The words of a route to a Unix socket, the refusals of a node that
//! cannot serve one, and the caller's line.

use super::*;

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

#[test]
fn a_unix_target_is_known_alone_or_after_its_route() {
    assert!(is_unix("api=unix-connect:/run/api.sock"));
    assert!(is_unix("unix-connect:/run/api.sock"));
    assert!(!is_unix("web=127.0.0.1:80"));
    assert!(!is_unix("dns=udp:127.0.0.1:53"));
    let all = words(&["web=127.0.0.1:80", "api=unix-connect:/run/api.sock", "127.0.0.1:22"]);
    assert_eq!(tcp_words(&all), words(&["web=127.0.0.1:80", "127.0.0.1:22"]));
}

#[test]
fn each_unix_route_is_parsed_with_its_caller_line() {
    let all = words(&["web=127.0.0.1:80", "api=unix-connect:/run/api.sock", "agent=unix-connect:@agent"]);
    let routes = parse(&all, Some("api")).unwrap();
    assert_eq!(
        routes,
        vec![
            UnixRoute { name: "api".into(), path: "/run/api.sock".into(), caller_line: true },
            UnixRoute { name: "agent".into(), path: "@agent".into(), caller_line: false },
        ]
    );
    let both = parse(&all, Some("api, agent")).unwrap();
    assert!(both.iter().all(|r| r.caller_line));
}

#[test]
fn a_unix_target_has_a_route_a_path_and_a_name_given_once() {
    let long = format!("api=unix-connect:/{}", "a".repeat(200));
    for (list, line, says) in [
        (vec!["unix-connect:/run/api.sock"], None, "has a route"),
        (vec!["api=unix-connect:"], None, "needs the socket's PATH"),
        (vec![long.as_str()], None, "holds"),
        (vec!["-x=unix-connect:/run/a"], None, "is not a route"),
        (vec!["api=127.0.0.1:80", "api=unix-connect:/run/a"], None, "given twice"),
        (vec!["api=unix-connect:/run/a"], Some("web"), "no route web"),
        (vec!["web=127.0.0.1:80", "api=unix-connect:/run/a"], Some("web"), "no route web"),
        (vec!["api=unix-connect:/run/a"], Some(" , "), "names of routes"),
    ] {
        let refusal = parse(&words(&list), line).unwrap_err();
        assert_eq!(refusal.code, 64, "{list:?}");
        assert!(refusal.message.contains(says), "{list:?}: {}", refusal.message);
    }
}

#[test]
fn a_node_that_cannot_serve_a_unix_route_refuses_it_before_anything() {
    let base = NodeArgs {
        name: Some("lab".into()),
        targets: words(&["api=unix-connect:/run/api.sock"]),
        ..NodeArgs::default()
    };
    for (args, says) in [
        (NodeArgs { sshd: true, ..base.clone() }, "--sshd"),
        (NodeArgs { exit: true, ..base.clone() }, "--exit"),
        (NodeArgs { no_e2e: true, ..base.clone() }, "--no-e2e"),
        (NodeArgs { temporary: Some("k".into()), ..base.clone() }, "--temporary"),
        (NodeArgs { targets: words(&["127.0.0.1:22"]), caller_line: Some("api".into()), ..base.clone() }, "ROUTE="),
    ] {
        let refusal = check(&args).unwrap_err();
        assert_eq!(refusal.code, 64, "{says}");
        assert!(refusal.message.contains(says), "{says}: {}", refusal.message);
    }
    // A node with no Unix route and no --caller-line is not this module's.
    assert!(check(&NodeArgs { targets: words(&["127.0.0.1:22"]), ..base }).is_ok());
}

#[test]
fn the_caller_line_names_the_key_and_the_route_in_one_line() {
    let key = PublicKey([7; 32]);
    let line = caller_line(&key, "api");
    assert_eq!(line, format!("podssh-caller v1 {} api\n", key.fingerprint()));
    assert!(line.starts_with("podssh-caller v1 SHA256:"), "{line}");
    assert_eq!(line.matches('\n').count(), 1);
    assert_eq!(line.split_whitespace().count(), 4);
    assert_ne!(caller_line(&PublicKey([8; 32]), "api"), line, "two keys, two lines");
}

/// A route's target is a socket that an upgrade moves: a named pipe is none.
#[cfg(windows)]
#[test]
fn a_named_pipe_is_no_route_of_a_node() {
    let refusal = parse(&words(&[r"api=unix-connect:\\.\pipe\docker_engine"]), None).unwrap_err();
    assert!(refusal.message.contains("not a named pipe"), "{}", refusal.message);
}
