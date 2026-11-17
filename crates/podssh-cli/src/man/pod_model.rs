//! podssh's manual as the model of `pod-manual`, the crate that each command
//! line of PodUtils takes its help and its manual from. It is built from the
//! tables of this binary: the commands and flags of `flags.rs`, the
//! arguments of the parser, the notes, the facts, the `-o` keywords and the
//! examples. Nothing in it is typed again.
//!
//! Each form is the crate's writer over this model: `podssh man` (text),
//! `--roff`, `--json` and `--help`. The tests give the model to
//! `pod_manual::check`, so that a drift between the code, the parser and the
//! manual fails a test by the same rules as in each other program.
//!
//! What the crate's model has no place for, and how it is held here:
//! - the heading "Conventions" of the start of the manual: its paragraphs are
//!   paragraphs of the description, with no sub-heading;
//! - the retired variables: a topic `retired-variables` of its own, as no
//!   fact of a variable may name a name that nothing reads;
//! - a file of several names (the identity files): one fact whose path is
//!   the names joined;
//! - the row `N` of EXIT STATUS, which also names `128 + N` of a signal: one
//!   payload row, as its text is one;
//! - an accepted flag's reason: its help says it, so the kind's `why` is
//!   empty, and the crate's short sentence follows the help;
//! - the bound `--timeout` that is never required (`FlagRow::optional`): no
//!   field, as it changes the parser, not the text;
//! - the subcommands of a command (`relay pair`, `job start`): podssh parses
//!   them as a positional word, so they stay in the usage and the notes;
//! - an exit code has no short name in podssh: the name stays empty.

use pod_manual as pm;

use super::model::{self as own, Block, Span};
use crate::flags::{self, Availability, FlagKind, FlagRow, Verb, VERBS};

/// The topics of the tables that the crate's model holds as typed facts or
/// as its own parts, so they are not copied as topics.
const TYPED: &[&str] = &["environment", "files", "exit-status", "examples", "see-also"];

/// The key of the topic of the `-o` keywords, which `ssh`'s section shows.
pub const KEYWORDS_KEY: &str = "keywords";

/// Why a build may lack `podssh ts`, after the crate's "Only a build with
/// the feature ts has this command:".
const TS_WHY: &str = "a release build leaves the Tailscale adapter out";

/// What a verb that parses and does nothing yet says, in place of its notes.
const NOT_YET: &str = "Not implemented yet. The command exits 70 and does nothing.";

fn span(s: &Span) -> pm::Span {
    match s {
        Span::Lit(t) => pm::Span::Lit(t.clone()),
        Span::Var(t) => pm::Span::Var(t.clone()),
        Span::Plain(t) => pm::Span::Plain(t.clone()),
    }
}

fn spans(list: &[Span]) -> Vec<pm::Span> {
    list.iter().map(span).collect()
}

/// One block of podssh's tables as a block of the crate's.
pub fn block(b: &Block) -> pm::Block {
    match b {
        Block::Para(t) => pm::Block::Para { text: t.clone() },
        Block::Line(s) => pm::Block::Line { spans: spans(s) },
        Block::Sub(t) => pm::Block::Sub { text: t.clone() },
        Block::Item { term, text } => pm::Block::Item { term: spans(term), text: text.clone() },
        Block::Table(rows) => pm::Block::Table { rows: rows.iter().map(|(t, s)| (spans(t), s.clone())).collect() },
        Block::Example { text, command } => pm::Block::Example { text: text.clone(), command: command.clone() },
    }
}

fn example(b: &Block) -> Option<pm::Example> {
    match b {
        Block::Example { text, command } => Some(pm::Example { command: command.clone(), meaning: text.clone() }),
        _ => None,
    }
}

/// What podssh does with a flag, as the crate's kind. "no flag" names
/// nothing to type, so the crate's short sentence stands alone.
pub fn kind(row: &FlagRow) -> pm::FlagKind {
    let instead = row.instead.filter(|i| *i != "no flag").unwrap_or_default().to_string();
    match row.kind {
        FlagKind::Supported => pm::FlagKind::Wired,
        FlagKind::Accepted => pm::FlagKind::Ignored { why: String::new() },
        FlagKind::Refused => pm::FlagKind::Refused { instead },
        // It refuses as a usage error, as a refused flag does.
        FlagKind::NotInFirstRelease => pm::FlagKind::NotInRelease {
            code: crate::exit_codes::EXIT_USAGE,
            why: if instead.is_empty() { instead } else { format!("use {instead}") },
        },
    }
}

/// One row of the flag table as the crate's flag, with what the row alone
/// says. Its text in each writer is `pod_manual::sections::flag_text` of it.
pub fn row_flag(row: &FlagRow) -> pm::Flag {
    pm::Flag {
        short: row.short,
        long: Some(row.long.to_string()),
        value: row.arg.map(str::to_string),
        help: row.help.to_string(),
        kind: kind(row),
        ..pm::Flag::default()
    }
}

/// One row of the flag table. `parser` is the command that `tree.rs` builds
/// from the same rows: it says which flag may be given more than once.
pub fn flag(row: &FlagRow, parser: &clap::Command) -> pm::Flag {
    let repeatable = parser
        .get_arguments()
        .find(|a| a.get_id().as_str() == row.long)
        .is_some_and(|a| matches!(a.get_action(), clap::ArgAction::Count | clap::ArgAction::Append));
    pm::Flag { repeatable, ..row_flag(row) }
}

/// The positional arguments, as the parser declares them.
fn arguments(parser: &clap::Command) -> Vec<pm::Arg> {
    parser
        .get_positionals()
        .map(|a| {
            // The same name as the manual's: the value name, else the id.
            let name = a
                .get_value_names()
                .and_then(|n| n.first())
                .map(|n| n.to_string())
                .unwrap_or_else(|| a.get_id().as_str().to_ascii_uppercase());
            pm::Arg {
                name,
                help: a.get_help().map(|h| h.to_string()).unwrap_or_default(),
                required: a.is_required_set(),
                many: a.get_num_args().is_some_and(|r| r.max_values() > 1),
                default: a.get_default_values().first().map(|d| d.to_string_lossy().into_owned()),
                values: a.get_possible_values().iter().map(|v| v.get_name().to_string()).collect(),
                env: None,
            }
        })
        .collect()
}

/// The paragraphs of a command that works here: the line that points from
/// `relay` to its facts, the notes of the manual, and those of the flags.
fn notes(verb: &Verb) -> Vec<String> {
    let mut out = Vec::new();
    // The command and the topic share a word; point from one to the other.
    if verb.name == "relay" {
        out.push(
            "The relay that podssh uses (hosts, failover, tokens, limits) is in THE RELAY: podssh man \
             relay-facts."
                .to_string(),
        );
    }
    out.extend(super::notes::for_verb(verb.name).iter().map(|n| n.to_string()));
    out.extend(crate::help::verb_notes(verb));
    out
}

/// Whether each build has the verb: a verb behind a cargo feature says so
/// in each build, and a build without it exits 70.
fn availability(verb: &Verb) -> pm::Availability {
    match flags::needed_feature(verb) {
        Some(name) => pm::Availability::Feature {
            name: name.to_string(),
            why: TS_WHY.to_string(),
            code: crate::exit_codes::EXIT_NOT_IMPLEMENTED,
        },
        None => pm::Availability::Always,
    }
}

/// One verb. A command that does not work here has no option but `--help`,
/// no argument and no note, as its options cannot be used.
fn command(verb: &'static Verb) -> pm::Command {
    let state = flags::availability(verb);
    let works = state == Availability::Works;
    let parser = crate::tree::verb_command(verb);
    let mut list: Vec<pm::Flag> =
        if works { verb.flags.iter().map(|r| flag(r, &parser)).collect() } else { Vec::new() };
    list.push(flag(&flags::HELP_FLAG, &parser));
    let notes = match state {
        Availability::Works => notes(verb),
        Availability::NotYet => vec![NOT_YET.to_string()],
        // The crate's sentence of the availability says it.
        Availability::NotInBuild => Vec::new(),
    };
    pm::Command {
        path: vec![verb.name.to_string()],
        aliases: verb.aliases.iter().filter(|a| **a != verb.name).map(|a| a.to_string()).collect(),
        about: format!("{}{}", verb.about, crate::help::availability_note(verb)),
        notes,
        usage: crate::help::usage_tail(verb).to_string(),
        args: if works { arguments(&parser) } else { Vec::new() },
        flags: list,
        availability: availability(verb),
        // The -o keywords show after the options of ssh, and `man keywords`
        // selects ssh.
        topics: if verb.name == "ssh" { vec![KEYWORDS_KEY.to_string()] } else { Vec::new() },
        ..pm::Command::default()
    }
}

/// The program itself: the options before a command, the commands by
/// purpose, and the first lines to type.
fn root() -> pm::Command {
    let options = flags::TOP_OPTIONS
        .iter()
        .map(|(short, long, help)| pm::Flag {
            short: short.strip_prefix('-').and_then(|s| s.chars().next()),
            ..pm::Flag::long(long.trim_start_matches('-'), help)
        })
        .collect();
    let groups = flags::GROUPS
        .iter()
        .map(|(title, names)| pm::Group {
            title: title.to_string(),
            commands: names.iter().map(|n| n.to_string()).collect(),
        })
        .collect();
    pm::Command {
        about: flags::ABOUT.to_string(),
        // `--help` shows the root's notes; the manual has them in DESCRIPTION.
        notes: vec![
            "podssh never guesses a destination. With no command, it lists the commands on stderr and exits 64."
                .to_string(),
        ],
        flags: options,
        groups,
        lead: super::examples::start_here().iter().filter_map(example).collect(),
        ..pm::Command::default()
    }
}

/// The blocks after the first sub-heading of `blocks`, up to the next one.
fn after_heading(blocks: &[Block]) -> Vec<pm::Block> {
    let at = |b: &Block| matches!(b, Block::Sub(_));
    blocks.iter().skip_while(|b| !at(b)).skip(1).take_while(|b| !at(b)).map(block).collect()
}

/// The topics: each prose section of the tables, the `-o` keywords and the
/// retired variables.
fn topics() -> Vec<pm::Topic> {
    let sections = super::facts::sections();
    let mut out: Vec<pm::Topic> = sections
        .iter()
        .filter(|s| !TYPED.contains(&s.key))
        .map(|s| pm::Topic {
            key: s.key.to_string(),
            aliases: s.aliases.iter().map(|a| a.to_string()).collect(),
            heading: s.heading.clone(),
            blocks: s.blocks.iter().map(block).collect(),
        })
        .collect();
    out.push(pm::Topic {
        key: KEYWORDS_KEY.into(),
        aliases: Vec::new(),
        heading: own::KEYWORDS.into(),
        blocks: own::keyword_blocks().iter().map(block).collect(),
    });
    // ENVIRONMENT's blocks are the variables, then the retired names under
    // their own sub-heading, its first one.
    if let Some(env) = sections.iter().find(|s| s.key == "environment") {
        let heading = env.blocks.iter().find_map(|b| match b {
            Block::Sub(t) => Some(t.to_uppercase()),
            _ => None,
        });
        if let Some(heading) = heading {
            out.push(pm::Topic {
                key: "retired-variables".into(),
                aliases: Vec::new(),
                heading,
                blocks: after_heading(&env.blocks),
            });
        }
    }
    out
}

/// The variables, the exit codes and the files, from the tables that the
/// manual's own sections read.
fn facts() -> pm::Facts {
    let vars = super::facts::variables().map(|(names, meaning)| pm::Var::reads(names, meaning)).collect();
    let exits = super::data::exit_codes()
        .into_iter()
        .map(|(code, meaning)| pm::Exit {
            code: match code {
                super::data::Code::Value(n) => pm::Code::Value(n),
                super::data::Code::Remote => pm::Code::Payload,
            },
            name: String::new(),
            meaning,
        })
        .collect();
    let files = super::data::files()
        .into_iter()
        .map(|(names, meaning)| pm::FileFact { path: names.join(", "), meaning })
        .collect();
    pm::Facts {
        variables: vec![pm::VarGroup { name: String::new(), vars }],
        exits,
        files,
        config: Vec::new(),
        tables: Vec::new(),
    }
}

/// The lines of SEE ALSO.
fn see_also() -> Vec<String> {
    vec![
        "podssh COMMAND --help: the help of one command, its section of this manual".into(),
        "podssh man SECTION: one section of this manual".into(),
        "podssh man --roff: this manual as a man(7) page".into(),
        "podssh man --json: this manual as one JSON object, for a program".into(),
        "podssh doctor: what this host allows, and whether the relay works".into(),
        format!("{}: the source, the releases and the issues", env!("CARGO_PKG_REPOSITORY")),
    ]
}

/// The whole manual of this binary as the crate's model.
pub fn manual() -> pm::Manual {
    let mut commands = vec![root()];
    commands.extend(VERBS.iter().map(command));
    pm::Manual {
        name: "podssh".into(),
        version: crate::help::version(),
        date: String::new(),
        about: flags::ABOUT.into(),
        names: Vec::new(),
        description: own::description(),
        commands,
        topics: topics(),
        facts: facts(),
        examples: super::examples::section().blocks.iter().filter_map(example).collect(),
        see_also: see_also(),
    }
}

#[cfg(test)]
mod tests;
