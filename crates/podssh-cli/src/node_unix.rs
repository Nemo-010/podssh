//! A node's route to a Unix socket: `ROUTE=unix-connect:PATH` (and `@NAME`
//! in Linux's abstract namespace). A service that listens on a socket (a
//! control API, a container runtime, an agent) needs no TCP bridge, and
//! with `--caller-line ROUTE` it learns who called: before the session's
//! first byte the node writes `podssh-caller v1 SHA256:... ROUTE` and a
//! newline. The node writes the line once its door let the key in, so the
//! line is a fact of the door, not a claim of the caller.
//!
//! A connect is no listener (rule 2). The routes of a TCP target stay
//! `pod-relay`'s; the Unix ones are kept here for the process, as a process
//! runs one node, and each road's opener reads them ([`crate::node_unix_open`]).

use std::sync::{Arc, Mutex};

use podssh_relay::identity::PublicKey;

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The kind of a Unix TARGET, as `podssh pipe` names its address.
pub(crate) const PREFIX: &str = "unix-connect:";
/// The first word of the caller's line, and its version.
pub(crate) const LINE_TAG: &str = "podssh-caller v1";

/// One route to a Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixRoute {
    /// The route's name, which the operator names as `NAME/ROUTE`.
    pub name: String,
    /// The socket: a path, or `@NAME` on Linux.
    pub path: String,
    /// Write the caller's line before the session's first byte.
    pub caller_line: bool,
}

/// The Unix routes of the node of this process.
static ROUTES: Mutex<Option<Arc<Vec<UnixRoute>>>> = Mutex::new(None);

/// Whether a TARGET word, or the target of its route, is a Unix socket.
pub(crate) fn is_unix(word: &str) -> bool {
    let target = word.split_once('=').map_or(word, |(_, target)| target);
    target.starts_with(PREFIX)
}

/// The Unix routes of the node, as [`check`] kept them.
pub(crate) fn routes() -> Arc<Vec<UnixRoute>> {
    let kept = ROUTES.lock().unwrap_or_else(|e| e.into_inner());
    kept.clone().unwrap_or_default()
}

/// Whether the node has a Unix route.
pub(crate) fn any() -> bool {
    !routes().is_empty()
}

/// The Unix route of `name`, when the node has one.
pub(crate) fn find(name: &str) -> Option<UnixRoute> {
    routes().iter().find(|r| r.name == name).cloned()
}

/// Keep `routes` for each road of this process.
fn install(routes: Vec<UnixRoute>) {
    *ROUTES.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(routes));
}

/// The checks of the Unix routes, before anything is read or connects;
/// each road then finds them kept. A roost serves an sshd on TCP, an exit
/// lends TCP, and a route travels in the end-to-end channel.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    let unix = args.targets.iter().any(|w| is_unix(w));
    if !unix && args.caller_line.is_none() {
        return Ok(());
    }
    let why = if !unix {
        Some("--caller-line names a route to a Unix socket: give ROUTE=unix-connect:PATH too")
    } else if args.sshd {
        Some("--sshd stands in front of an sshd on TCP, which a unix-connect: TARGET is not")
    } else if args.exit {
        Some("--exit lends TCP: a unix-connect: TARGET goes on a node with no --exit")
    } else if args.no_e2e {
        Some("a route travels in the end-to-end channel, which --no-e2e turns off")
    } else if args.temporary.is_some() {
        Some("--temporary serves the sshd of an upgrade, not a unix-connect: TARGET")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(Refusal::usage(why));
    }
    install(parse(&args.targets, args.caller_line.as_deref())?);
    Ok(())
}

/// The Unix routes of the TARGET words, and the routes of `--caller-line`
/// (names by commas). Each Unix TARGET has a route, as the line names it;
/// a route is given once, whatever its kind.
pub(crate) fn parse(words: &[String], caller_line: Option<&str>) -> Result<Vec<UnixRoute>, Refusal> {
    let mut routes = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for word in words {
        if let Some((name, _)) = word.split_once('=') {
            if names.contains(&name) {
                return Err(Refusal::usage(format!("the route {name} is given twice")));
            }
            names.push(name);
        }
        if !is_unix(word) {
            continue;
        }
        let Some((name, target)) = word.split_once('=') else {
            return Err(Refusal::usage(format!(
                "{word}: a unix-connect: TARGET has a route, which the operator names: ROUTE={word}"
            )));
        };
        podssh_ws::names::check_node_name(name).map_err(|_| {
            Refusal::usage(format!(
                "{word}: {name:?} is not a route: letters, digits, '.', '-' and '_', not first '-' or '.'"
            ))
        })?;
        let path = target.strip_prefix(PREFIX).unwrap_or(target);
        check_path(word, path)?;
        routes.push(UnixRoute { name: name.to_string(), path: path.to_string(), caller_line: false });
    }
    let lined: Vec<&str> =
        caller_line.unwrap_or_default().split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
    if caller_line.is_some() && lined.is_empty() {
        return Err(Refusal::usage("--caller-line takes the names of routes, separated by commas"));
    }
    for name in lined {
        let Some(route) = routes.iter_mut().find(|r| r.name == name) else {
            return Err(Refusal::usage(format!(
                "--caller-line {name}: the node has no route {name} to a Unix socket (ROUTE=unix-connect:PATH)"
            )));
        };
        route.caller_line = true;
    }
    Ok(routes)
}

/// The sockets of the Unix routes of `words`, as a service reaches them: a
/// relative PATH is refused, as a service starts in another directory; an
/// abstract `@NAME` has no file, and no directory to let through.
pub(crate) fn service_sockets(words: &[String]) -> Result<Vec<std::path::PathBuf>, Refusal> {
    let mut sockets = Vec::new();
    for word in words.iter().filter(|word| is_unix(word)) {
        let target = word.split_once('=').map_or(word.as_str(), |(_, target)| target);
        let path = target.strip_prefix(PREFIX).unwrap_or(target);
        if path.starts_with('@') {
            continue;
        }
        if !std::path::Path::new(path).is_absolute() {
            return Err(Refusal::usage(format!(
                "TARGET {word}: a service starts in another directory, so its socket needs an absolute PATH"
            )));
        }
        sockets.push(std::path::PathBuf::from(path));
    }
    Ok(sockets)
}

/// A path that a socket's address can hold: not empty, and short enough
/// with its NUL.
fn check_path(word: &str, path: &str) -> Result<(), Refusal> {
    if path.is_empty() {
        return Err(Refusal::usage(format!("TARGET {word}: unix-connect: needs the socket's PATH")));
    }
    // The session's target is a socket, which a handover moves; a pipe is none.
    #[cfg(windows)]
    if crate::pipe::unix::is_named_pipe(path) {
        return Err(Refusal::usage(format!("TARGET {word}: a node's route takes an AF_UNIX socket, not a named pipe")));
    }
    if path.len() >= crate::pipe::unix::SUN_PATH {
        return Err(Refusal::usage(format!(
            "TARGET {word}: the socket's path is {} bytes, and a socket's address holds {} at most",
            path.len(),
            crate::pipe::unix::SUN_PATH - 1
        )));
    }
    Ok(())
}

/// The TARGET words of TCP alone, which `pod-relay`'s routes serve.
pub(crate) fn tcp_words(words: &[String]) -> Vec<String> {
    words.iter().filter(|w| !is_unix(w)).cloned().collect()
}

/// The node's first line with its Unix routes beside its TCP targets.
pub(crate) fn beside(served: String) -> String {
    let routes = routes();
    if routes.is_empty() {
        return served;
    }
    let each = routes.iter().map(|r| {
        let line = if r.caller_line { " (caller line)" } else { "" };
        format!("{}={PREFIX}{}{line}", r.name, r.path)
    });
    let unix = each.collect::<Vec<_>>().join(", ");
    match served.is_empty() {
        true => unix,
        false => format!("{served}, {unix}"),
    }
}

/// The caller's line of `key` on `route`. The route's name holds no space
/// or newline (a node's name), so the line is one line of four words.
pub(crate) fn caller_line(key: &PublicKey, route: &str) -> String {
    format!("{LINE_TAG} {} {route}\n", key.fingerprint())
}

#[cfg(test)]
#[path = "node_unix_tests.rs"]
mod tests;
