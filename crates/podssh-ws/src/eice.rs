//! The road of AWS's EC2 Instance Connect Endpoint (T-351): `pod-egress` of
//! PodUtils/podcrates, over podssh's way out ([`connect`]) and its user
//! agent.

use std::time::Duration;

pub use pod_egress::eice::*;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// What podssh says it is in the upgrade, where aws-cli says its own.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// A tunnel to `target` through `endpoint`, through `proxy`, its URL signed
/// with `credentials` once TLS is up. Each step is bounded by `timeout`.
pub async fn connect(
    endpoint: &Endpoint,
    target: &Target,
    credentials: &Credentials,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelaySession, ConnectError> {
    pod_egress::eice::connect(endpoint, target, credentials, &crate::client::way(proxy), trust, timeout).await
}
