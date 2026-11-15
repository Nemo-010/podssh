//! A WebSocket forwarder that takes its target from the client (T-369):
//! `pod-egress` of PodUtils/podcrates, over podssh's way out ([`dial`]).
//! The carrier of a session is the crate's shared part, which podssh's
//! other roads take too.

use std::time::Duration;

pub(crate) use pod_egress::carry;
pub use pod_egress::forwarder::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// What a forwarder's road needs: podssh's way out for `proxy`.
pub fn dial(trust: &Trust, proxy: &ProxyChoice, timeout: Duration, at_end: AtEnd, note: Note) -> Dial {
    Dial { way: crate::client::way(proxy), trust: trust.clone(), timeout, at_end, note }
}

/// A note of `say`, for each line of a peer.
pub fn note(say: impl Fn(&str) + Send + Sync + 'static) -> Note {
    std::sync::Arc::new(move |event: pod_core::Event| say(&event.text))
}

/// A note that drops each line.
pub fn silent() -> Note {
    std::sync::Arc::new(pod_core::NoEvents)
}
