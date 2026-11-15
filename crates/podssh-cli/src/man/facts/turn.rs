//! The variables of the TURN road (T-621), of the file hosts' road
//! (T-738), and of the srv.us and tunnl.gg roads (T-566, T-567), apart from
//! `roads.rs` for its length.

/// `PODSSH_TURN` and its credential file.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_TURN"],
        "The TURN server of podssh ssh, of each command that reaches its server as podssh ssh does, and of podssh \
      proxy, as --turn: turns:HOST[:PORT] (RFC 7065; port 443 when none is named), in place of the relay. The \
      flag wins, and so does each other road's flag; beside PODSSH_RELAY, PODSSH_FORWARDER, PODSSH_VIA, \
      PODSSH_WSTUNNEL or PODSSH_CHISEL, or with a URI that cannot be read, it is a configuration error (78). An \
      empty value is no value.",
    ),
    (
        &["PODSSH_TURN_AUTH_FILE"],
        "The credential file of the server of --turn or PODSSH_TURN, as --turn-auth-file, which wins: a private \
      file of USER:PASSWORD, or auth-secret SECRET (see FILES).",
    ),
    (
        &["PODSSH_FILEHOSTS"],
        "The file hosts' road of a pair, the last of the last fallbacks, in \
      a build with the feature filehost (none of a release yet): each small write of a link of the resumable \
      layer is a sealed note at the public MQTT broker of PODSSH_MQTT. Each larger piece is one sealed upload to \
      a public file host of podssh's list of services, its URL a sealed note there. One request goes at a time \
      (see the notes of node and ssh). no turns it off; yes, \
      or unset, takes the hosts of the list whose terms let a program upload unasked, in the list's order; a \
      list of the services' ids, by commas, takes those alone, in that order; naming a host whose terms ask \
      for its user's consent gives it; an id that the list does not hold is a configuration error (78). \
      PODSSH_LAST_RESORT=no, or PODSSH_MQTT=no (no board), turns it off too.",
    ),
    (
        &["PODSSH_SRV_US"],
        "The srv.us road, a last fallback: the localhost.run road's shape \
          at srv.us: SSH on port 22 as nomatch, logged in with the node's own key, and the forward of port 1. It is \
          the road of podssh node --srv-us and podssh ssh node://NAME; srv.us derives the tunnel's name from that \
          key. So a client that holds the node's whole key derives it too, and races the road last, with no record; a \
          node with no other road serves it unasked after the Sandhole road. srv.us sees the node's public key. \
          no: no such road, and the flags are refused (64); HOST[:PORT]: that server of the same shape, whose \
          host key nobody names, its tunnels named under HOST; unset, empty or yes: srv.us where podssh's list of \
          services names it, else no server, and --srv-us is a configuration error (78). Another word is a \
          configuration error (78), which does not echo the value.",
    ),
    (
        &["PODSSH_TUNNL_GG"],
        "The tunnl.gg road, a last fallback: the localhost.run road's shape at tunnl.gg: SSH on port 22 with no key, \
          the forward of port 80 and the command output=json. It is the road of podssh node --tunnl-gg and podssh ssh \
          node://NAME --tunnel-url https://HOST of a name under its tunnels' zone. A node with no other road serves it \
          unasked after the srv.us road; its name is random, so a client finds it by --tunnel-url, a kept name or the \
          node's record. no: no such road, and the flags are refused (64); HOST[:PORT]: that server of the same shape, \
          whose host key nobody names; unset, empty or yes: proxy.tunnl.gg where podssh's list of services names it, \
          else no server, and --tunnl-gg is a configuration error (78). Another word is a configuration error (78), \
          which does not echo the value.",
    ),
];
