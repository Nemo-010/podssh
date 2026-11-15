//! Shadowsocks in its AEAD form and Shadowsocks 2022 (T-373, T-492, T-493):
//! `pod-egress` of PodUtils/podcrates, over podssh's way out ([`dial`]).
//! The password goes into the master key and nowhere else.

use std::time::Duration;

pub use pod_egress::shadowsocks::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// What the dial of a server needs: podssh's way out for `proxy`.
pub fn dial(
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    answer: Option<Duration>,
    silence_is_ready: bool,
) -> Dial {
    Dial { way: crate::client::way(proxy), trust: trust.clone(), timeout, answer, silence_is_ready }
}
