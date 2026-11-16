//! The checks of `pod_manual::check` over podssh's manual: the rules of the
//! model, the text rules, the variables against the source and the exit
//! codes against the constants that the commands return. Each check has a
//! control that plants a drift and finds it.

use super::*;
use pod_manual::check::{self, assert_none};
use pod_manual::scan;
use std::path::{Path, PathBuf};

fn crate_src(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name).join("src")
}

/// The non-test source of the crates in this build's binary, without the
/// manual itself, which names each variable.
fn sources() -> Vec<(PathBuf, String)> {
    let mut crates = vec!["podssh-cli", "podssh-ssh", "podssh-relay", "podssh-ws"];
    // A road's crate is in the binary with its feature only.
    for (on, name) in [
        (cfg!(feature = "iroh"), "podssh-iroh"),
        (cfg!(feature = "warp"), "podssh-warp"),
        (cfg!(feature = "tor"), "podssh-tor"),
        (cfg!(feature = "ts"), "podssh-ts"),
        (cfg!(feature = "zerotier"), "podssh-zerotier"),
        (cfg!(feature = "gsr"), "podssh-gsr"),
    ] {
        if on {
            crates.push(name);
        }
    }
    let dirs: Vec<PathBuf> = crates.iter().map(|c| crate_src(c)).collect();
    let man = crate_src("podssh-cli").join("man");
    scan::rust_sources(&dirs).into_iter().filter(|(path, _)| !path.starts_with(&man)).collect()
}

/// Each exit code that podssh gives: 0, and each constant `EXIT_*` or
/// `EX_*` of a number in the crates that end the process. A code of the
/// payload (the remote command's status) is the row `N`.
fn given() -> Vec<i32> {
    let mut codes = vec![0];
    for (_, code) in scan::rust_sources(&[crate_src("podssh-cli"), crate_src("podssh-ssh")]) {
        for prefix in ["EXIT_", "EX_"] {
            for (_, n) in scan::exit_constants(&code, prefix) {
                if !codes.contains(&n) {
                    codes.push(n);
                }
            }
        }
    }
    codes
}

#[test]
fn the_model_keeps_its_own_rules() {
    assert_none(check::model(&manual()));
}

/// Each string of the manual and the help keeps the text rules: no
/// sentence over 25 words, no work id, no fault of a character.
#[test]
fn each_string_keeps_the_text_rules() {
    assert_none(check::texts(&manual()));
}

#[test]
fn each_variable_read_is_a_fact_and_each_fact_is_read() {
    assert_none(check::variables(&manual(), &sources(), &[]));
}

#[test]
fn each_exit_code_given_is_a_fact_and_each_fact_is_given() {
    assert_none(check::exit_codes(&manual(), &given()));
}

/// The controls of the sources and the codes: a wrong directory or a
/// reader that sees nothing would make each check above pass on nothing.
#[test]
fn the_sources_and_the_codes_are_read() {
    let read: Vec<String> = sources().iter().flat_map(|(_, code)| scan::variables_read(code)).collect();
    for name in ["PODSSH_SSH_CONFIG", "PODSSH_RELAY_TOKEN", "SSH_AUTH_SOCK"] {
        assert!(read.iter().any(|r| r == name), "no source reads {name}: {read:?}");
    }
    let codes = given();
    for code in [
        crate::exit_codes::EXIT_USAGE,
        crate::exitmap::sysexits::EX_CONFIG,
        crate::doctor::EXIT_FAILED,
        podssh_ssh::EXIT_FAILURE,
    ] {
        assert!(codes.contains(&code), "{code} is not found: {codes:?}");
    }
}

/// The drift that the entry plants: a variable that the code reads and no
/// fact names, a fact that no code reads, a code with no fact and a fact of
/// a code that nothing gives. Each is found.
#[test]
fn a_planted_drift_is_found() {
    let m = manual();
    let mut src = sources();
    src.push((PathBuf::from("planted.rs"), "fn f() { let _ = std::env::var(\"PODSSH_PLANTED_DRIFT\"); }".into()));
    let found = check::variables(&m, &src, &[]);
    assert!(found.iter().any(|f| f.at == "planted.rs" && f.what.contains("PODSSH_PLANTED_DRIFT")), "{found:?}");

    let mut unread = manual();
    unread.facts.variables[0].vars.push(pm::Var::reads(&["PODSSH_NEVER_READ"], "A planted fact."));
    let found = check::variables(&unread, &sources(), &[]);
    assert!(found.iter().any(|f| f.what.contains("PODSSH_NEVER_READ")), "{found:?}");

    let mut codes = given();
    codes.push(42);
    let found = check::exit_codes(&m, &codes);
    assert!(found.iter().any(|f| f.what.contains("gives 42")), "{found:?}");

    let mut extra = manual();
    extra.facts.exits.push(pm::Exit::new(3, "", "A planted fact."));
    let found = check::exit_codes(&extra, &given());
    assert!(found.iter().any(|f| f.what.contains("fact of 3")), "{found:?}");
}

/// The control of the text rules over this model: a long sentence in a note
/// of a command is found at that command.
#[test]
fn a_planted_long_note_is_found() {
    let mut m = manual();
    let ssh = m.commands.iter_mut().find(|c| c.path == ["ssh"]).expect("ssh");
    ssh.notes.push("word ".repeat(26));
    let found = check::texts(&m);
    assert!(found.iter().any(|f| f.at == "podssh ssh"), "{found:?}");
}

/// Each part of podssh's manual is in the model: each command with each
/// flag of a command that works, each variable, exit code, file and example,
/// and the topics that the model has no typed place for.
#[test]
fn the_model_holds_each_part_of_the_manual() {
    let m = manual();
    assert_eq!(m.commands.len(), VERBS.len() + 1, "the root and each verb");
    for verb in VERBS {
        let c = m.command(verb.name).unwrap_or_else(|| panic!("no command {}", verb.name));
        assert!(c.flag("--help").is_some(), "{}", verb.name);
        if flags::availability(verb) == Availability::Works {
            for row in verb.flags {
                let f = c.flag(&format!("--{}", row.long)).unwrap_or_else(|| panic!("{} --{}", verb.name, row.long));
                assert_eq!((f.short, f.value.as_deref(), f.help.as_str()), (row.short, row.arg, row.help));
            }
        }
        for alias in verb.aliases.iter().filter(|a| **a != verb.name) {
            assert_eq!(m.command(alias).map(|c| c.name()), Some(verb.name.to_string()), "{alias}");
        }
    }
    let vars: usize = m.facts.variables.iter().map(|g| g.vars.len()).sum();
    assert_eq!(vars, super::super::facts::variables().count());
    assert_eq!(m.facts.exits.len(), super::super::data::exit_codes().len());
    assert_eq!(m.facts.files.len(), super::super::data::files().len());
    assert_eq!(m.examples.len(), super::super::examples::section().blocks.len());
    assert!(!m.description.is_empty() && !m.see_also.is_empty());
    for key in ["relay-facts", "keywords", "retired-variables"] {
        let t = m.topics.iter().find(|t| t.key == key).unwrap_or_else(|| panic!("no topic {key}"));
        assert!(!t.blocks.is_empty(), "the topic {key} is empty");
    }
    // The keywords are in their topic, and their paragraphs are no notes of ssh.
    let keywords = m.topics.iter().find(|t| t.key == "keywords").expect("keywords");
    let first = crate::ssh::keywords::HONOURED[0].help;
    let item = keywords.blocks.iter().any(|b| matches!(b, pm::Block::Item { text, .. } if text == first));
    assert!(item, "{first}");
    let ssh = m.command("ssh").expect("ssh");
    let paras = keywords.blocks.iter().filter_map(|b| match b {
        pm::Block::Para { text } => Some(text),
        _ => None,
    });
    for p in paras {
        assert!(!ssh.notes.contains(p), "{p}");
    }
    assert!(m.commands.iter().any(|c| c.flags.iter().any(|f| f.repeatable)), "no flag may be repeated");
}
