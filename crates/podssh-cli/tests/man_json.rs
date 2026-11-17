//! `podssh man --json` against the readers of `--help`: the JSON is
//! pod-manual's model, read back by the crate's reader. Each flag that
//! `--help` shows is in it with its value name and its kind, and what to
//! type instead of a refused one; each `-o` keyword, variable and exit code
//! is in it; and it is the same bytes in any environment.

use std::process::{Command, Stdio};

use pod_manual::{Block, Code, FlagKind, Manual};
use podssh_cli::flags::FlagKind as RowKind;
use serde_json::Value;

mod man_extract;
use man_extract::*;

/// The option that every verb takes; the readers need its name.
const UNIVERSAL: &str = "--help";

/// The binary's JSON, read back as the model.
fn document() -> Manual {
    let (rc, out, err) = podssh(&["man", "--json"], &[], false);
    assert_eq!(rc, 0, "{err}");
    pod_manual::json::read(&out).expect("the crate's reader takes the JSON")
}

#[test]
fn each_flag_of_help_is_in_the_json_with_its_kind() {
    let doc = document();
    for (name, verb) in sections() {
        let values = flag_map(&options(&help_text(verb)), verb);
        let command = doc.command(&name).unwrap_or_else(|| panic!("no command {name:?}"));
        let mut json = std::collections::BTreeMap::new();
        for f in &command.flags {
            json.insert(canonical(verb, &f.spelling()), f.value.clone());
        }
        assert_eq!(json, values, "{name:?}: other flags or value names");
        let Some(v) = verb else { continue };
        for row in v.flags {
            let f = command.flag(&format!("--{}", row.long)).expect("the flag");
            let instead = row.instead.filter(|i| *i != "no flag").unwrap_or_default();
            let ok = match (row.kind, &f.kind) {
                (RowKind::Supported, FlagKind::Wired) => true,
                (RowKind::Accepted, FlagKind::Ignored { .. }) => true,
                (RowKind::Refused, FlagKind::Refused { instead: i }) => i == instead,
                (RowKind::NotInFirstRelease, FlagKind::NotInRelease { .. }) => true,
                _ => false,
            };
            assert!(ok, "{name}: --{}: {:?} as {:?}", row.long, row.kind, f.kind);
        }
    }
}

#[test]
fn each_keyword_variable_and_exit_code_is_in_the_json() {
    let doc = document();
    // The keywords are a topic that ssh's section shows.
    assert_eq!(doc.command("ssh").map(|c| c.topics.clone()), Some(vec!["keywords".to_string()]));
    let keywords = doc.topics.iter().find(|t| t.key == "keywords").expect("the keywords");
    let terms: Vec<String> = keywords
        .blocks
        .iter()
        .filter_map(|b| match b {
            Block::Item { term, .. } => Some(pod_manual::model::plain(term)),
            _ => None,
        })
        .collect();
    for k in podssh_cli::ssh::keywords::HONOURED {
        assert!(terms.contains(&format!("{}={}", k.name, k.value)), "{}", k.name);
    }
    for (k, _) in podssh_cli::ssh::keywords::REFUSED.iter().chain(podssh_cli::ssh::keywords::NOTED) {
        assert!(terms.iter().any(|t| t == k), "{k}");
    }
    let text = serde_json::to_string(&keywords.blocks).unwrap();
    for k in podssh_cli::ssh::keywords::IGNORED {
        assert!(text.contains(k), "{k}");
    }
    let variables: Vec<&String> = doc.facts.variables.iter().flat_map(|g| &g.vars).flat_map(|v| &v.names).collect();
    for (list, _) in podssh_cli::man::facts::variables() {
        for n in *list {
            assert!(variables.iter().any(|v| v == n), "{n}");
        }
    }
    let codes: Vec<Code> = doc.facts.exits.iter().map(|e| e.code).collect();
    for code in [
        0,
        podssh_cli::doctor::EXIT_FAILED,
        podssh_cli::exit_codes::EXIT_USAGE,
        podssh_cli::exitmap::sysexits::EX_UNAVAILABLE,
        podssh_cli::exit_codes::EXIT_NOT_IMPLEMENTED,
        podssh_cli::exitmap::sysexits::EX_NOPERM,
        podssh_cli::exitmap::sysexits::EX_CONFIG,
        podssh_ssh::EXIT_FAILURE,
    ] {
        assert!(codes.contains(&Code::Value(code)), "{code}: {codes:?}");
    }
    assert!(codes.contains(&Code::Payload), "{codes:?}");
}

/// Run the binary with `args`; with `clear`, in an empty environment.
fn podssh(args: &[&str], set: &[(&str, &str)], clear: bool) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    if clear {
        cmd.env_clear();
        // Windows needs these to start a process at all.
        for name in ["SystemRoot", "SYSTEMROOT"] {
            if let Ok(v) = std::env::var(name) {
                cmd.env(name, v);
            }
        }
    }
    cmd.envs(set.iter().copied());
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_json_is_the_same_in_any_environment() {
    let (rc, bare, err) = podssh(&["man", "--json"], &[], true);
    assert_eq!(rc, 0, "{err}");
    let token = "podssh-test-token-0123456789abcdef";
    let set = [("PODSSH_RELAY_TOKEN", token), ("HOME", "/home/someone"), ("USERPROFILE", "C:\\Users\\someone")];
    let (rc, full, _) = podssh(&["man", "--json"], &set, false);
    assert_eq!(rc, 0);
    assert_eq!(bare, full, "the JSON depends on the environment");
    assert!(!full.contains(token) && !full.contains("someone"));
    let doc: Value = serde_json::from_str(&full).expect("one JSON object");
    assert_eq!(doc["schema"], 1);
    assert_eq!(doc["name"], "podssh");
}

/// A section is one command (an alias finds it), one table of facts, or a
/// topic's blocks; two forms at once and an unknown section are refused.
#[test]
fn a_section_gives_one_command_a_table_or_a_topic() {
    let one = |args: &[&str]| -> Value {
        let (rc, out, err) = podssh(args, &[], false);
        assert_eq!(rc, 0, "{args:?}: {err}");
        serde_json::from_str(&out).unwrap()
    };
    assert_eq!(one(&["man", "--json", "irc"])["command"]["path"][0], "chat", "an alias finds its command");
    assert!(one(&["man", "--json", "exit-status"])["exits"].is_array());
    assert!(one(&["man", "--json", "environment"])["variables"].is_array());
    assert_eq!(one(&["man", "--json", "relay-facts"])["topic"]["key"], "relay-facts");
    assert_eq!(one(&["man", "--json", "ssh"])["topics"][0]["key"], "keywords");
    for args in [&["man", "--json", "--roff"][..], &["man", "--json", "nonsense"][..]] {
        let (rc, out, err) = podssh(args, &[], false);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}
