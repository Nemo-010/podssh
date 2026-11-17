//! How a node asks its relay by its pair's stop token: the renewal (T-592)
//! and the rotation (T-615). A node asks over HTTPS with the trust of its
//! relay. A test of months (T-710) asks a role of its own process instead,
//! whose pairs it restarts from their file; the binary never makes that
//! one, so no user of a release reaches it.

use std::sync::Arc;

use podssh_relay::pair::renew::{self, Renewed};
use podssh_relay::pair::rotate::{self, Rotated};
use podssh_relay::pair::{Pair, PairError};
use podssh_ws::Trust;

/// Where a node's requests by the stop token go.
#[derive(Clone)]
pub enum ByStop {
    /// The pair's relay, over HTTPS with this trust.
    Relay(Trust),
    /// A role of this process, for a test alone.
    #[doc(hidden)]
    Here(Arc<dyn Here>),
}

/// A role of this process that answers a node's requests by the stop token
/// as `/v1/renew/<name>` and `/v1/rotate/<name>` do: a wrong token, or a pair
/// that ended, is [`PairError::Forbidden`]. For a test alone.
#[doc(hidden)]
pub trait Here: Send + Sync {
    /// The renewal of `pair`, by its stop token.
    fn renew(&self, pair: &Pair) -> Result<Renewed, PairError>;
    /// `next` as the stop token to come of `pair`, by its stop token now.
    fn rotate(&self, pair: &Pair, next: &str) -> Result<Rotated, PairError>;
}

impl ByStop {
    /// Renew `pair` at its relay.
    pub(crate) async fn renew(&self, pair: &Pair) -> Result<Renewed, PairError> {
        match self {
            ByStop::Relay(trust) => {
                let context = podssh_relay::context::process();
                let ctx = crate::pairs::context(&pair.relay, trust, &context);
                renew::renew(&ctx, pair).await
            }
            ByStop::Here(role) => role.renew(pair),
        }
    }

    /// Ask the relay of `pair` for `next` as its stop token to come.
    pub(crate) async fn rotate(&self, pair: &Pair, next: &str) -> Result<Rotated, PairError> {
        match self {
            ByStop::Relay(trust) => {
                let context = podssh_relay::context::process();
                let ctx = crate::pairs::context(&pair.relay, trust, &context);
                rotate::rotate(&ctx, pair, next).await
            }
            ByStop::Here(role) => role.rotate(pair, next),
        }
    }
}
