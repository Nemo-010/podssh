//! The road to a service that Cloudflare's `cloudflared` publishes (T-264):
//! `pod-egress` of PodUtils/podcrates, over podssh's way out and its user
//! agent.

use std::time::Duration;

pub use pod_egress::cloudflare::*;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// What podssh says it is, where cloudflared says `cloudflared/VERSION`.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// Open a session to the tunnel of `host`, through `proxy`, with the
/// credentials of `access`. Each step is bounded by `timeout`, and each read
/// of the session by `idle`.
pub async fn connect(
    host: &str,
    access: &Access,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession, ConnectError> {
    pod_egress::cloudflare::connect(host, access, &crate::client::way(proxy), trust, timeout, idle).await
}
