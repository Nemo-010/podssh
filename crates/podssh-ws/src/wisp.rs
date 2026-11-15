//! A Wisp client (T-438): `pod-egress` of PodUtils/podcrates, over
//! podssh's way out ([`connect_with`]).

use std::time::Duration;

pub use pod_egress::wisp::*;

use crate::dial::ProxyChoice;
use crate::forwarder::Note;
use crate::tls::Trust;

/// What a connection needs beside its URL: podssh's way out for `proxy`.
pub fn connect_with(trust: &Trust, proxy: &ProxyChoice, timeout: Duration, note: Note) -> Connect {
    Connect { way: crate::client::way(proxy), trust: trust.clone(), timeout, note }
}
