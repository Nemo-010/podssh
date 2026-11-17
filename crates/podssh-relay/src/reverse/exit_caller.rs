//! The callers of a node's exit (T-721): a member of the net whose policy
//! lets it out, or a key that brings a grant of the exit, as a Cloudflare
//! Worker that holds no key of a member does. What each road of a node
//! shares:
//!
//! 1. the fixed denies of the relay role (`crate::serve::policy`): port 25
//!    and each address that is not public (private ranges, the loopback,
//!    link-local and the clouds' metadata addresses among them) and in no
//!    range of the exit's; one check for the role and the exit, so that the
//!    two never drift apart;
//! 2. a grant of the exit (feature `grant`): its principal is the node's
//!    with the route [`GRANT_ROUTE`], a word that no route's name can be, so
//!    that a grant of a route never opens the exit, nor one of the exit a
//!    route; `pod-relay`'s door reads it as that route's;
//! 3. each caller's counts ([`super::exit_count`]) at [`serve`], which wraps
//!    the channel of each session of a node: the exit's connects and
//!    refusals, and the bytes of its sessions.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite};

use super::exit_count::{Counts, Metered, Tally};
use crate::e2e::{ends, Ask, Refusal};
use crate::identity::PublicKey;
use crate::serve::policy::{shown, Policy, Refused};
use crate::serve::ranges::Range;

/// The route of a grant's principal that names the node's exit:
/// `node:SHA256:.../+exit`. A route's name never holds a '+'.
pub const GRANT_ROUTE: &str = "+exit";

/// The refusal of a port that the relay role never dials, in its words.
pub fn denied_port(host: &str, port: u16) -> Option<String> {
    Policy::default().port_allowed(host, port).err().map(|refused| refused.said())
}

/// The first address of `found` that the relay role would not dial: not
/// public, and in no range of `ranges`.
pub fn outside(found: &[SocketAddr], ranges: &[Range]) -> Option<IpAddr> {
    Policy { ranges: ranges.to_vec(), ..Policy::default() }.unlisted(found)
}

/// The role's words for a target that it does not dial for its addresses,
/// the same for each cause (GitHub #126): a caller from outside the net
/// learns nothing of the node's network by them.
pub fn not_dialed(host: &str, port: u16) -> String {
    Refused::NotDialed { target: shown(host, port), why: String::new() }.said()
}

/// The counts of the process's node, as one node runs in a process.
pub fn counts() -> Arc<Counts> {
    static COUNTS: OnceLock<Arc<Counts>> = OnceLock::new();
    COUNTS.get_or_init(Arc::default).clone()
}

/// Serve the channel of one session of `node` on `link`, as
/// [`ends::serve_asked`] does with `open`, and count each exit's target in
/// `counts`: a connect or a refusal for the caller's key, and the link's
/// bytes for it once its target opened. A session of a route or of the
/// node's own target counts toward nobody.
pub async fn serve<L, A, O, F>(link: L, node: &ends::Node, counts: Arc<Counts>, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: FnOnce(PublicKey, Ask) -> F,
    F: Future<Output = Result<A, Refusal>>,
{
    let tally = Arc::new(Tally::default());
    let link = Metered::new(link, tally.clone());
    let counted = move |key: PublicKey, ask: Ask| {
        let exit = matches!(ask, Ask::Exit { .. });
        // Called inside the async block: the channel's mark of a grant
        // (`ends::granted`) is set only while the opening is polled.
        async move {
            let opened = open(key, ask).await;
            if exit {
                match &opened {
                    Ok(_) => tally.attach(counts.connected(&key), counts.clone()),
                    Err(_) => counts.refused(&key),
                }
            }
            opened
        }
    };
    ends::serve_asked(link, node, counted).await
}

/// The door of a node's grants with its exit's beside it (feature `grant`):
/// an exit's target is redeemed by `exit` as the route [`GRANT_ROUTE`]; a
/// node with no exit refuses it before the grant is spent; each other ask
/// goes to `door`.
#[cfg(feature = "grant")]
pub fn redeem(
    door: &crate::grant::Door,
    exit: Option<&crate::grant::Door>,
    peer: &PublicKey,
    ask: &Ask,
    blob: &[u8],
    now: u64,
) -> Result<crate::grant::Redeemed, String> {
    match ask {
        Ask::Exit { .. } => match exit {
            Some(exit) => exit.redeem(peer, &Ask::Route(GRANT_ROUTE.into()), blob, now),
            None => Err("this node is no exit, so a grant of its exit lets nothing in".into()),
        },
        // No proof names it (a route's name holds no '+'); refused all the same.
        Ask::Route(route) if route == GRANT_ROUTE => Err(format!("{GRANT_ROUTE} names an exit's grant, never a route")),
        _ => door.redeem(peer, ask, blob, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn the_exit_s_denies_are_the_role_s() {
        let port25 = denied_port("140.82.112.3", 25).unwrap();
        assert_eq!(port25, "140.82.112.3:25 not in the ALLOW list: port 25 is refused");
        assert!(denied_port("140.82.112.3", 22).is_none());
        for private in ["10.0.0.1:22", "127.0.0.1:22", "169.254.169.254:80", "[fd00:ec2::254]:80", "168.63.129.16:80"] {
            assert!(outside(&at(&[private]), &[]).is_some(), "{private}");
        }
        assert!(outside(&at(&["140.82.112.3:22"]), &[]).is_none());
        let lent = [Range::parse("127.0.0.1").unwrap()];
        assert!(outside(&at(&["127.0.0.1:22"]), &lent).is_none(), "a range lends it");
        assert_eq!(outside(&at(&["140.82.112.3:22", "127.0.0.2:22"]), &lent), Some("127.0.0.2".parse().unwrap()));
        let words = not_dialed("db.internal", 5432);
        assert_eq!(words, "db.internal:5432 not in the ALLOW list: this relay dials no address of it");
    }

    #[test]
    fn the_grant_route_is_no_route_s_name() {
        assert!(crate::e2e::Ask::read(Some(GRANT_ROUTE)).is_none(), "a proof never names it as a route");
    }
}
