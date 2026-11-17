//! The notes of a node's route to a Unix socket, and of the caller's line
//! that it may write first (T-714), apart from the others so that each file
//! stays short.

/// The node's side: `ROUTE=unix-connect:PATH` and `--caller-line ROUTES`.
pub(super) const NODE: &str = "A route may name unix-connect:PATH as its service, as a route of TCP names its \
     own (see TARGET). It offers a service that listens on a Unix socket, with no bridge of TCP. On Linux, @NAME is a name in the abstract namespace. On Windows, PATH is a \
     socket of the Unix family; a named pipe is refused, as an upgrade moves a socket alone. The node connects to \
     PATH for each session of the route, and only then; a connect is no listener. A failure names PATH and \
     its cause, and the operator gets it. \
     Such a TARGET always has a route, as an operator names it with NAME/ROUTE. It is refused with --sshd, \
     whose sshd is on TCP, and with --exit, which lends TCP. --no-e2e refuses it too, as a route travels in \
     the end-to-end channel. --caller-line ROUTES, by commas, names routes to a Unix socket. Before each \
     session's first byte, the node writes one line to that socket: podssh-caller v1, the operator's key as \
     SHA256:..., the route's name, and a newline. The service reads that line, and the rest is the session. \
     The node writes it once its door let the key in: its allowlist, the net's policy, a grant, or the person \
     of --ask. So the line is a fact of the door, and no claim of the caller. A key that the door refuses \
     never reaches the socket. Without --caller-line, the node writes nothing of its own: a plain bridge. \
     Under --install, PATH is absolute or @NAME, as a service starts in another directory (64 else). A system \
     unit lets through the directory of a socket that ProtectHome hides, read-only.";
