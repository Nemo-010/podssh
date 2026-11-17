//! The wire vectors of `docs/wire.md` through podssh's codecs (T-723): each
//! vector's fields encode to its bytes, and its bytes decode to its fields,
//! in the codecs of `pod-session`, `pod-relay` and `pod-ws` that podssh-relay
//! and podssh-ws re-export, and in the relay role's tokens. The second
//! reader, `scripts/check-wire-vectors.py`, shares no code with these; a
//! vector that both take is the page's. A changed vector needs a new version
//! of the page, which that script holds by the vectors' digest.
#![cfg(all(feature = "pair", feature = "serve"))]

#[path = "wire/closes.rs"]
mod closes;
#[path = "wire/common.rs"]
mod common;
#[path = "wire/forward.rs"]
mod forward;
#[cfg(feature = "grant")]
#[path = "wire/grants.rs"]
mod grants;
#[path = "wire/layer.rs"]
mod layer;
#[path = "wire/reverse.rs"]
mod reverse;
#[path = "wire/tokens.rs"]
mod tokens;

/// The page's version line and each file's `wire` name one version, so a
/// reader of the page reads the vectors that it describes.
#[test]
fn the_page_and_each_file_name_one_version() {
    let page = std::fs::read_to_string(common::root().join("docs/wire.md")).expect("docs/wire.md");
    let line = page.lines().find_map(|l| l.strip_prefix("Wire version: ")).expect("a version line");
    assert_eq!(line.trim().parse::<u64>().ok(), Some(common::WIRE), "the page's version");
    for part in common::PARTS {
        // `vectors` checks the version and the part of each file.
        assert!(!common::vectors(part).is_empty(), "{part}.json has no vector");
    }
}
