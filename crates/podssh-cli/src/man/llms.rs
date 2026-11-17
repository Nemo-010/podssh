//! `llms.txt` and `llms-full.txt` of this binary (`podssh man --llms index`
//! and `--llms full`), from the one model of the manual by `pod-manual`'s
//! writers: an index for an agent that meets podssh, and the manual with the
//! short documents in one file. The repository keeps both at its root, and a
//! test holds them to the model (`check::generated`), so no text is kept
//! twice by hand.

use std::io::Write;

use pod_manual::llms::{self, Doc};

use crate::exitmap::sysexits::EX_USAGE;

/// Where a document's link points: the repository's default branch.
pub const BASE: &str = "https://github.com/PodUtils/podssh/blob/main/";

/// The documents whose text `llms-full.txt` holds, in the binary: short ones
/// that an agent reads first.
fn held() -> Vec<Doc> {
    let doc =
        |path: &str, meaning: &str, body: &str| Doc { path: path.into(), meaning: meaning.into(), body: body.into() };
    vec![
        doc(
            "README.md",
            "what podssh is, how to install it, and the first session",
            include_str!("../../../../README.md"),
        ),
        doc("SECURITY.md", "the security model and how to report a fault", include_str!("../../../../SECURITY.md")),
        doc(
            "docs/target-environment.md",
            "the hosts that podssh is for: HTTPS alone, often through a proxy",
            include_str!("../../../../docs/target-environment.md"),
        ),
    ]
}

/// The documents that the index links to: the ones held, and long ones by
/// their link alone.
fn linked() -> Vec<Doc> {
    let doc = |path: &str, meaning: &str| Doc { path: path.into(), meaning: meaning.into(), body: String::new() };
    let mut docs = held();
    docs.extend([
        doc("docs/relay.md", "the relay's contract, and podssh's relay role"),
        doc("docs/mesh.md", "the mesh of a user's own nodes"),
        doc("docs/cli.md", "the command line, flag by flag, with the reasons"),
    ]);
    docs
}

/// `llms.txt`.
pub fn index() -> String {
    llms::index(&super::pod_model::manual(), &linked(), BASE)
}

/// `llms-full.txt`.
pub fn full() -> String {
    llms::full(&super::pod_model::manual(), &held())
}

/// `podssh man --llms WHICH`: `index` or `full` to stdout; another word, or
/// beside a section, `--roff` or `--json`, a usage error.
pub fn run(which: &str, with_other: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if with_other {
        let _ = writeln!(err, "podssh man: --llms takes no SECTION, --roff or --json");
        return EX_USAGE;
    }
    let text = match which {
        "index" => index(),
        "full" => full(),
        other => {
            let _ = writeln!(err, "podssh man: --llms {other}: index or full");
            return EX_USAGE;
        }
    };
    // A reader that left early (`| head`) is no fault, as with the manual.
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_manual::check::{self, assert_none};
    use std::path::Path;

    /// A road's feature adds to the manual, so the files that the repository
    /// keeps are the default build's.
    const DEFAULT_BUILD: bool = !cfg!(any(
        feature = "ts",
        feature = "iroh",
        feature = "warp",
        feature = "tor",
        feature = "zerotier",
        feature = "devtunnel",
        feature = "tox",
        feature = "yggdrasil",
        feature = "hyperdht",
        feature = "strelay",
        feature = "filehost",
        feature = "gsr"
    ));

    fn root(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(name)
    }

    #[test]
    fn the_repository_s_files_are_the_manual_s() {
        if !DEFAULT_BUILD {
            return eprintln!("skipped: a road's feature changes the manual");
        }
        let fix = "write them again: podssh man --llms index > llms.txt; podssh man --llms full > llms-full.txt";
        assert_none(check::generated(&root(llms::INDEX), &index(), fix));
        assert_none(check::generated(&root(llms::FULL), &full(), fix));
    }

    #[test]
    fn the_index_links_each_document_and_full_holds_the_manual() {
        let index = index();
        for doc in linked() {
            assert!(index.contains(&format!("({BASE}{})", doc.path)), "{}", doc.path);
        }
        let full = full();
        assert!(full.contains(&pod_manual::text::render(&super::super::pod_model::manual())));
        assert!(full.contains("<!-- document: README.md -->"));
    }

    #[test]
    fn another_word_is_a_usage_error() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run("both", false, &mut out, &mut err), EX_USAGE);
        assert_eq!(run("index", true, &mut out, &mut err), EX_USAGE);
        assert!(out.is_empty());
    }
}
