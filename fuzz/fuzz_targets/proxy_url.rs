//! A proxy URL (`podssh_ws::Proxy::parse`), as a proxy variable holds it: a
//! proxy over TCP shows only its host and port, and one on a Unix socket or at
//! a command shows that, never the credentials; and its URL, which carries
//! the credentials again for a library, parses back to the same proxy.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;
use podssh_ws::dial::{authority, Carrier};
use podssh_ws::Proxy;

fuzz_target!(|data: &[u8]| {
    let Some(url) = text(data) else { return };
    let Ok(proxy) = Proxy::parse(url) else { return };
    let shown = proxy.to_string();
    match proxy.carrier() {
        Carrier::Tcp => assert_eq!(shown, authority(&proxy.host, proxy.port)),
        // A Unix socket or a command has no host and port: it shows its
        // own address.
        _ => assert!(!shown.is_empty() && shown != authority(&proxy.host, proxy.port), "{shown}"),
    }
    assert_eq!(Proxy::parse(&proxy.url()), Ok(proxy.clone()), "{}", proxy.url());
});
