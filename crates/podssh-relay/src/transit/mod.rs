//! The transit road (T-436): a carrier of a pair's road through a
//! magic-wormhole transit relay, by default Least Authority's at
//! `wss://relay.mw.leastauthority.com` (the operator's ruling Q65 lets
//! podssh try it unasked; its terms and limits are in docs/carriers.md):
//! `pod-transit` of PodUtils/podcrates. podssh keeps its variable, the place
//! of the road's lines, and the settings of each connection: its way out and
//! its trust.

use std::sync::Arc;

pub use pod_transit::{
    client, default_url, far, link, meet, token, Config, Dialer, Failed, Keys, Link, Missed, Node, Part, Setting, Side,
};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};

/// `no` turns the road off; a `ws://` or `wss://` URL names another relay.
pub const ENV: &str = "PODSSH_TRANSIT";

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// [`ENV`]'s value: unset, empty or yes, Least Authority's relay; no, none;
/// a `ws://` or `wss://` URL, that relay. Another word is refused, and the
/// refusal does not echo it, as a URL's query may hold a secret.
pub fn setting(value: Option<&str>) -> Result<Setting, String> {
    pod_transit::setting(ENV, value)
}

/// The settings of each connection to the relay of `url`: podssh's way out
/// through `proxy`, the roots of `trust`, and the road's lines to `say`.
pub fn config(url: WsUrl, trust: &Trust, proxy: &ProxyChoice, say: Say) -> Config {
    let events = Arc::new(move |event: pod_core::Event| say(event.text));
    Config::new(url, podssh_ws::client::way(proxy)).with_trust(trust.clone()).with_events(events)
}
