//! VLESS (T-440): `pod-egress` of PodUtils/podcrates, over podssh's way out
//! ([`dial`]). The Trojan and VMess roads take the same settings.

use std::time::Duration;

pub use pod_egress::vless::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// What a VLESS, Trojan or VMess road needs: podssh's way out for `proxy`.
pub fn dial(
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    answer: Duration,
    silence_is_ready: bool,
    at_end: AtEnd,
) -> Dial {
    Dial { way: crate::client::way(proxy), trust: trust.clone(), timeout, answer, silence_is_ready, at_end }
}
