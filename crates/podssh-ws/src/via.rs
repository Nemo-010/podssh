//! A second proxy over TLS (T-439): `pod-egress` of PodUtils/podcrates,
//! over podssh's way out ([`dial`]) and its words.

use std::time::Duration;

pub use pod_egress::via::*;

use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// Where podssh's user gives the credentials file, as a `407` names it.
pub const AUTH_FILE: &str = "--via-auth-file FILE";

/// How a [`Client`] reaches its proxy: podssh's way out for `proxy`.
pub fn dial(trust: Trust, proxy: &ProxyChoice, timeout: Duration, offer: Offer) -> Dial {
    Dial { way: crate::client::way(proxy), trust, timeout, offer, auth_file: AUTH_FILE.into() }
}
