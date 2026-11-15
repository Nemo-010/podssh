//! The road of GCP's Identity-Aware Proxy for TCP (T-351): `pod-egress` of
//! PodUtils/podcrates, over podssh's way out ([`connect`]), its user agent,
//! and its lines ([`carry::open`]).

use std::time::Duration;

pub use pod_egress::iap::*;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// What podssh says it is in the upgrade, where gcloud says its own.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// A new link to IAP for `target`, or one that takes the session of
/// `resume` up, through `proxy`, with `token` in its header. Each step is
/// bounded by `timeout`.
pub async fn connect(
    target: &Target,
    resume: Option<&Resume>,
    token: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelaySession, ConnectError> {
    pod_egress::iap::connect(target, resume, token, &crate::client::way(proxy), trust, timeout).await
}

/// One IAP session as a byte stream: `pod-egress`'s carrier, its events
/// said as podssh's lines.
pub mod carry {
    use std::fmt::Display;
    use std::sync::Arc;

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

    pub use pod_egress::iap::carry::*;

    /// Where the task says what it does.
    pub type Say = Arc<dyn Fn(Line) + Send + Sync>;

    /// A line of the task's.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Line {
        /// For the user: a lost link, and the new one.
        Info(String),
        /// For `-v`.
        Verbose(String),
    }

    /// The carrier's events as lines of `say`: each step for `-v`, the
    /// rest for the user.
    pub fn note(say: Say) -> pod_egress::Note {
        Arc::new(move |event: pod_core::Event| match event.kind {
            STEP => say(Line::Verbose(event.text)),
            _ => say(Line::Info(event.text)),
        })
    }

    /// The session on its first link, its lines to `say`.
    pub async fn open<S, E>(dial: Dial<S, E>, say: Say) -> Result<(DuplexStream, Carried), NotOpen<E>>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
        E: Display + Send + 'static,
    {
        pod_egress::iap::carry::open(dial, note(say)).await
    }
}
