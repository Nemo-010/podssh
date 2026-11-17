//! The links of a session of the layer where the way refuses the WebSocket
//! upgrade: once the way refused the upgrade of one, that link and each
//! later one go on the HTTP road, a new session of the road each, which the
//! role gives to its layer (`pod-relay`'s `Dialer::link_or_road`). The
//! dialer says so in one line. `PODSSH_HTTP_ROAD` holds for these links as
//! for the contract's road: `no` keeps each link an upgrade, and a form
//! that it names is the form of each link.

use podssh_relay::forward_layer::{self, Dialer, Link, Missed};
use podssh_relay::session::client::{Client, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ended, OsEntropy};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::http_road as road;

/// `dialer` with the form that `PODSSH_HTTP_ROAD` names, and whether its
/// links may go on the HTTP road: not with `no`, nor with a word that the
/// contract's road refuses, which says so itself where it runs.
pub(crate) fn of(dialer: Dialer) -> (Dialer, bool) {
    of_setting(dialer, std::env::var(road::ENV).ok().as_deref())
}

fn of_setting(dialer: Dialer, value: Option<&str>) -> (Dialer, bool) {
    match road::asked(value) {
        Ok(road::Asked::Auto) => (dialer, true),
        Ok(road::Asked::Only(form)) => (dialer.with_road_form(Some(form)), true),
        Ok(road::Asked::No) | Err(_) => (dialer, false),
    }
}

/// A new link of `dialer`: the upgrade, or, where `by_road` lets it, the
/// HTTP road once the way refused the upgrade; `notes` hears the change.
pub(crate) async fn link(dialer: &Dialer, by_road: bool, notes: &mut (dyn FnMut(&str) + Send)) -> Result<Link, Missed> {
    if by_road {
        return dialer.link_or_road(notes).await;
    }
    dialer.link(notes).await.map(Link::Ws)
}

/// Carry `app` in `client`'s session, on a new link of `dialer` after each
/// lost one, as [`link`] opens it, until the session ends.
pub(crate) async fn carry<A, N>(dialer: &Dialer, by_road: bool, client: Client<Link>, app: A, note: N) -> Outcome
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    if by_road {
        return forward_layer::carry_or_road(dialer, client, app, note).await;
    }
    let connect = |_: &Ended| async move {
        let mut quiet = |_: &str| {};
        match dialer.link(&mut quiet).await {
            Ok(link) => Next::Link(Link::Ws(link)),
            Err(missed) if missed.is_final() => Next::Stop(missed.lines(dialer.target()).join("; ")),
            Err(missed) => Next::Retry(missed.lines(dialer.target()).join("; ")),
        }
    };
    // On the heap: the layer's future is large for a small thread's stack.
    Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::relay::Relay;
    use podssh_ws::Trust;

    fn dialer() -> Dialer {
        let relay = Relay { host: "relay.example".into(), port: 443 };
        Dialer::new(&podssh_relay::context::process(), relay, "github.com", 22, Trust::Default).unwrap()
    }

    /// The road carries the links unless the variable turns it off; a word
    /// that it does not take keeps each link an upgrade.
    #[test]
    fn the_variable_of_the_http_road_holds_for_the_links_of_the_layer() {
        for value in [None, Some(""), Some("auto"), Some("yes"), Some("split"), Some("one")] {
            assert!(of_setting(dialer(), value).1, "{value:?}");
        }
        for value in [Some("no"), Some("off"), Some("another")] {
            assert!(!of_setting(dialer(), value).1, "{value:?}");
        }
    }
}
