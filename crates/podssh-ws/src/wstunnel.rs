//! wstunnel's protocol (T-441): `pod-egress` of PodUtils/podcrates, over
//! podssh's way out ([`dial`]).

use std::time::Duration;

pub use pod_egress::wstunnel::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// How a tunnel reaches its server: podssh's way out for `proxy`.
pub fn dial(trust: &Trust, proxy: &ProxyChoice, timeout: Duration, at_end: AtEnd) -> Dial {
    Dial { way: crate::client::way(proxy), trust: trust.clone(), timeout, at_end }
}
