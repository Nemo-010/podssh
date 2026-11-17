//! The resumable layer over the HTTP road, through a proxy that ends TLS
//! for the relay's name and refuses the WebSocket upgrade, as a cloud
//! container's proxy does (`http_road_cli_support`): with
//! `PODSSH_RELAY_LAYER=yes`, `podssh proxy` reads the role's offer, the way
//! refuses the upgrade of the layer's first link, and each link goes on the
//! HTTP road, with one line. The proxy then loses the road's first session
//! after some of its requests, as a role that lost it: the link is cut, and
//! the session resumes on a new session of the road, saying so, and each
//! byte comes back once.
//!
//!     cargo test -p podssh-cli --test http_road_layer_cli

mod cloud_support;
mod http_road_cli_support;
mod ssh_harness;
mod throughput_harness;

use std::sync::atomic::Ordering;

use http_road_cli_support::{bytes, echo_target, run, Bench, MIB};
use sha2::{Digest, Sha256};

/// The bytes of the session, each way: many batches, so that the cut comes
/// in its middle.
const SIZE: usize = 4 * MIB;
/// The requests of the road's first session before the proxy loses it.
const CUT_AFTER: usize = 6;

#[test]
fn podssh_proxy_resumes_its_session_of_the_layer_on_the_http_road_after_a_cut() {
    let bench = Bench::start_cutting("http-road-layer-proxy", &[], CUT_AFTER);
    let mut args = vec!["proxy".to_string()];
    args.extend(bench.relay_flags());
    args.extend(["127.0.0.1".to_string(), echo_target().to_string()]);
    let mut cmd = bench.podssh(&args, Some("split"));
    cmd.env("PODSSH_RELAY_LAYER", "yes");
    let sent = bytes(SIZE, 0x6c61_7965);
    let ran = run(cmd, sent.clone());
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    assert!(ran.err.contains("each link goes on the HTTP road"), "the road of the links was said: {}", ran.err);
    assert!(!ran.err.contains("the session goes on with no resume"), "the layer carried it: {}", ran.err);
    assert!(ran.err.contains("the session resumed"), "the session outlived the cut: {}", ran.err);
    assert!(bench.seen.cuts.load(Ordering::SeqCst) > 0, "the proxy cut the link: {}", ran.err);
    let lines = bench.seen.carried.lock().unwrap().clone();
    assert!(bench.seen.upgrades.load(Ordering::SeqCst) > 0, "the proxy refused an upgrade: {lines:?}");
    let opens = bench.seen.count("/v1/http/open-layer/");
    assert!(opens >= 2, "a second session of the road carried the resume ({opens}): {lines:?}");
    assert_eq!(bench.seen.count("/v1/http/open/"), 0, "the contract's road did not carry it: {lines:?}");
    assert_eq!(ran.out.len(), sent.len(), "each byte came back once; {}", ran.err);
    assert!(Sha256::digest(&ran.out) == Sha256::digest(&sent), "the digests differ; {}", ran.err);
}
