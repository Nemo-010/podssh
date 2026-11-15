//! The DERP road (T-349): pod-derp of PodUtils/podcrates (its T-031). podssh
//! keeps its glue here: its lines as a callback of text ([`Say`]), its names
//! on the wire ([`names`]), its way out by a `ProxyChoice` ([`dial::tls`],
//! the probes of [`servers`]) and its variables ([`servers::ENV`],
//! [`servers::MAIN_ENV`]).

use std::sync::Arc;

pub use pod_derp::{
    carry, client, conn, far, frame, key, link, packet, recv, rtt, send, ticket, Conn, Dialer, Key, Link, Names, Node,
    Secret, Server, Ticket, FEATURES,
};

/// Where the lines of a connection go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The events of pod-derp as lines of `say`.
pub fn events(say: Say) -> Arc<dyn pod_core::Events> {
    Arc::new(move |event: pod_core::Event| say(event.text))
}

/// podssh's names on the wire: `podssh` and `podssh/VERSION`.
pub fn names() -> Names {
    Names::podssh(podssh_ws::dial::user_agent())
}

/// The way to a DERP server.
pub mod dial {
    pub use pod_derp::dial::*;
    use podssh_ws::{ProxyChoice, Trust};

    /// TLS to each server, through `proxy`, verified with `trust`.
    pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
        pod_derp::dial::tls(podssh_ws::client::way(&proxy), trust)
    }
}

/// The DERP servers, with podssh's variables and its way out.
pub mod servers {
    use std::time::Duration;

    pub use pod_derp::servers::*;
    use podssh_ws::{ProxyChoice, Trust};

    /// The variable that names the servers in place of the fleet:
    /// `HOST[:PORT][,...]`.
    pub const ENV: &str = "PODSSH_DERP_SERVER";
    /// The variable that keeps tailcat's four alone: `no`.
    pub const MAIN_ENV: &str = "PODSSH_DERP_MAIN";

    /// Whether the main fleet follows tailcat's, by the value of [`MAIN_ENV`].
    pub fn main_wanted(value: Option<&str>) -> Result<bool, String> {
        pod_derp::servers::main_wanted(value, &super::names())
    }

    /// The fleet of the road, by [`MAIN_ENV`]; a value that is neither yes
    /// nor no keeps the main fleet, as [`from_environment`] refuses it before.
    pub fn fleet() -> Vec<Server> {
        fleet_with(main_wanted(std::env::var(MAIN_ENV).ok().as_deref()).unwrap_or(true))
    }

    /// The servers of `flag`, else of [`ENV`], else the fleet; and whether
    /// the user named them. A value of [`MAIN_ENV`] that is neither yes nor
    /// no is refused.
    pub fn from_environment(flag: Option<&str>) -> Result<(Vec<Server>, bool), String> {
        let named = flag.map(str::to_string).or_else(|| std::env::var(ENV).ok().filter(|v| !v.trim().is_empty()));
        let main = std::env::var(MAIN_ENV).ok();
        chosen(named.as_deref(), main.as_deref(), &super::names())
    }

    /// The servers that a client tries for a node whose home is `home`.
    pub fn for_client(home: &Server) -> Vec<Server> {
        for_client_in(home, &fleet())
    }

    /// derper's probe at `server`, through `proxy`.
    pub async fn probe(server: &Server, trust: &Trust, proxy: &ProxyChoice) -> Result<Duration, String> {
        pod_derp::servers::probe(server, &podssh_ws::client::getter(proxy), trust).await
    }

    /// [`probe`], with the cut of a failure beside its words.
    pub async fn probe_kept(server: &Server, trust: &Trust, proxy: &ProxyChoice) -> Result<Duration, Missed> {
        pod_derp::servers::probe_kept(server, &podssh_ws::client::getter(proxy), trust).await
    }

    /// [`probe`] of owned values: whether it answered.
    pub async fn answers(server: Server, trust: Trust, proxy: ProxyChoice) -> Result<(), String> {
        probe(&server, &trust, &proxy).await.map(|_| ())
    }

    /// The first of `servers` whose probe answers, in their order; and why
    /// each one before it did not.
    pub async fn home(servers: &[Server], trust: &Trust, proxy: &ProxyChoice) -> (Option<Server>, Vec<String>) {
        pod_derp::servers::home(servers, &podssh_ws::client::getter(proxy), trust).await
    }

    /// The words after `server` in a line, with podssh's names.
    pub fn fleet_note(server: &Server) -> String {
        server.fleet_note(&super::names())
    }
}
