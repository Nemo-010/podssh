//! The ACME client of `podssh relay serve --acme NAME` (T-447, RFC 8555): a
//! certificate for NAME from a CA (Let's Encrypt by default), proven by
//! TLS-ALPN-01 on the role's own listener (RFC 8737), kept in the cache and
//! renewed in the role before its end: `pod-acme` of PodUtils/podcrates.
//! podssh keeps the glue: its HTTPS client through HTTPS_PROXY, the trust
//! of `--ca-file`, the places of its cache, its refusals and the place of
//! the role's lines.

use std::sync::Arc;

pub use pod_acme::{
    about, certs, client, jws, lets_encrypt, next_retry, order, renew_at, store, Acme, Failed, FIRST_RETRY, MOST_RETRY,
    RENEW_BEFORE,
};
use podssh_relay::cache::{self, Chosen};
use podssh_ws::tls_server::Served;
use podssh_ws::{ProxyChoice, Trust};

use crate::exitmap::sysexits::EX_CANTCREAT;
use crate::relay_settings::Refusal;
use certs::Leaf;

/// Where the lines of the role go: each is said on its stderr.
pub type Say = tokio::sync::mpsc::UnboundedSender<String>;

/// The client for `name` at the CA of `directory` (Let's Encrypt when
/// `None`), whose TLS is checked against `trust`, through the proxy that the
/// environment names, its state in podssh's cache.
pub fn new(name: &str, directory: Option<&str>, trust: Trust) -> Result<Acme, Refusal> {
    if cache::chosen() == Chosen::Nothing {
        return Err(Refusal::config(format!(
            "{}=none: --acme keeps its account and certificate in the cache, so that a restart asks the CA \
             for nothing; name a directory, or leave it unset",
            cache::DIR_ENV
        )));
    }
    let client = podssh_ws::client::getter(&ProxyChoice::FromEnvironment);
    let http = client::Http { client, trust, timeout: pod_acme::REQUEST };
    let places = cache::candidate_dirs();
    Acme::new(name, directory, http, &places, Arc::new(pod_core::NoEvents)).map_err(|failed| match failed {
        Failed::Directory(why) => Refusal::usage(format!("--acme-directory {why}")),
        other => Refusal { message: other.to_string(), code: EX_CANTCREAT },
    })
}

/// Keep the name's certificate for as long as the role runs, its lines to
/// `say` ([`pod_acme::keep`]). Ends only when there is no certificate to
/// serve: the first order failed.
pub async fn keep(mut acme: Acme, served: Arc<Served>, held: Option<Leaf>, say: Say) -> String {
    acme.events = Arc::new(move |event: pod_core::Event| {
        let _ = say.send(event.text);
    });
    pod_acme::keep(acme, served, held).await.to_string()
}
