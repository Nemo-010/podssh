//! What meek_lite and WebTunnel share (T-385): `pod-egress` of
//! PodUtils/podcrates, over podssh's way out ([`reach`]).

use std::time::Duration;

pub use pod_egress::pt::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// How a transport reaches its server: podssh's way out for `proxy`.
pub fn reach(proxy: &ProxyChoice, trust: Trust, wait: Duration) -> Reach {
    Reach { way: crate::client::way(proxy), trust, wait }
}
