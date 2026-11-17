//! The opener of a node's session by its route, with the Unix routes of
//! [`crate::node_unix`] beside `pod-relay`'s TCP ones, and the handler of
//! the pair's road that runs it ([`Routed`], `pod-relay`'s with this
//! opener). The door (allowlist, the net's policy, a grant, the person of
//! `--ask`) ran before [`open`]: a key that it refused never reaches the
//! socket.
//!
//! A Unix socket is handed on as a `TcpStream`, as `podssh pipe` hands on
//! an AF_UNIX socket of Windows: a connected stream socket of any family
//! carries bytes as a TCP one does. So each target of a route is one type,
//! and the upgrade in place moves its socket to the next binary as it
//! moves a TCP target's.

use std::io;

use podssh_relay::e2e::{ends, Ask, Refusal as NodeRefusal};
use podssh_relay::identity::PublicKey;
use podssh_relay::reverse::node::{Admit, NO_ROOM};
use podssh_relay::reverse::routes::Routes;
use podssh_relay::reverse::{Handler, Opening, SessionId};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;

use crate::node_unix::{self, UnixRoute};

/// Each direction of the pipe between a session and its channel, as
/// `pod-relay`'s.
const PIPE: usize = 256 * 1024;

/// The target of what the operator `key` asked: a Unix route of the node,
/// or else what `routes` opens. Refused as `pod-relay` refuses a route, with
/// the same words for a route that the key may not use and one that the
/// node does not have.
pub(crate) async fn open(
    routes: &Routes,
    key: &PublicKey,
    ask: &Ask,
    admit: impl FnOnce() -> bool,
) -> Result<TcpStream, NodeRefusal> {
    match ask {
        Ask::Route(name) => {
            if let Some(route) = node_unix::find(name) {
                return open_unix(routes, key, &route, admit).await;
            }
        }
        // A node whose targets are all Unix routes has no target of its own;
        // `pod-relay` would call it an exit.
        Ask::Target if routes.routes.is_empty() && routes.exit.is_none() && node_unix::any() => {
            return Err(NodeRefusal::Other(
                "the node has a target for each route only: name one, as NAME/ROUTE".into(),
            ));
        }
        _ => {}
    }
    routes.open_with(key, ask, admit).await
}

/// The socket of `route` for `key`, whose grant of the route is checked
/// here as `pod-relay` checks it; the caller's line first, when asked.
async fn open_unix(
    routes: &Routes,
    key: &PublicKey,
    route: &UnixRoute,
    admit: impl FnOnce() -> bool,
) -> Result<TcpStream, NodeRefusal> {
    // A grant used once that named this route stands for the key's line.
    if !ends::granted() {
        (routes.grant)(key, &route.name)
            .map_err(|_| NodeRefusal::Other(format!("this key may not use the route {} of the node", route.name)))?;
    }
    if !admit() {
        return Err(NodeRefusal::Other(NO_ROOM.to_string()));
    }
    let failed = |e: io::Error| NodeRefusal::NoTarget(format!("{}{}: {e}", node_unix::PREFIX, route.path));
    let mut stream = connect(&route.path).await.map_err(failed)?;
    if route.caller_line {
        // Before any byte of the session: the service reads one line, then the stream.
        let line = node_unix::caller_line(key, &route.name);
        stream.write_all(line.as_bytes()).await.map_err(failed)?;
        stream.flush().await.map_err(failed)?;
    }
    Ok(stream)
}

/// One connection to the socket at `path`, as `podssh pipe`'s
/// `unix-connect:` makes it (`@NAME` in Linux's abstract namespace), as a
/// `TcpStream` of the same descriptor.
#[cfg(unix)]
pub(crate) async fn connect(path: &str) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let unix = crate::pipe::unix::stream(path).await?.into_std()?;
    // SAFETY: a connected stream socket, whose descriptor `into_raw_fd`
    // gave up; the stream owns it from here, and closes it once.
    let stream = unsafe { std::net::TcpStream::from_raw_fd(unix.into_raw_fd()) };
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

/// An AF_UNIX socket of Windows, by WinSock, as `podssh pipe` connects it.
#[cfg(windows)]
pub(crate) async fn connect(path: &str) -> io::Result<TcpStream> {
    let stream = crate::pipe::unix::af_unix(path)?;
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

/// `pod-relay`'s handler of routes, with [`open`] in the place of its own
/// opener, so that a Unix route is reached as a TCP one is.
pub struct Routed {
    routes: Routes,
    node: ends::Node,
}

impl Routed {
    pub fn new(routes: Routes, node: ends::Node) -> Routed {
        Routed { routes, node }
    }

    /// The channel's task of one session, its target opened by [`open`]
    /// once `admit` allows it.
    fn serve(&self, admit: Admit) -> Opening<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let (routes, node) = (self.routes.clone(), self.node.clone());
        // A handover finds the channel by the layer's id of its session.
        let holds = node.holds.clone();
        tokio::spawn(holds.holding(async move {
            let opened = move |key: PublicKey, ask: Ask| async move { open(&routes, &key, &ask, admit).await };
            ends::serve_asked(theirs, &node, opened).await;
        }));
        Box::pin(async move { Ok(ours) })
    }
}

impl Handler for Routed {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        self.serve(Box::new(|| true))
    }

    /// The client counts against the layer's budget once the channel let
    /// its key in and its route passed, as `pod-relay`'s does.
    fn open_admitted(&self, _id: SessionId, admit: Admit) -> Opening<DuplexStream> {
        self.serve(admit)
    }

    /// Each session that the channel lets in gets the seed of its tokens of
    /// one leg, registered in `frames`.
    fn registers(&self, frames: Option<podssh_relay::e2e::legs::Frames>) {
        self.node.leases.attach(frames);
    }

    fn spent(&self, digest: &str) {
        self.node.leases.spent(digest);
    }
}
