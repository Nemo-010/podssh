//! podssh's manual as the model of `pod-manual`, the crate that each command
//! line of PodUtils takes its help and its manual from. It is built from the
//! same tables as [`super::model`]: the commands and flags of `flags.rs`, the
//! arguments of the parser, the notes, the facts and the examples. Nothing in
//! it is typed again; where podssh's manual holds only rendered blocks, they
//! are read back from [`super::model::manual`].
//!
//! The writers of `podssh man` still walk podssh's own model. This one is what
//! the tests give to `pod_manual::check`, so that a drift between the code
//! and the manual fails a test by the same rules as in each other program.
//!
//! What the crate's model has no place for, and how it is held here:
//! - the heading "Conventions" of the start of the manual: its paragraphs are
//!   paragraphs of the description, with no sub-heading;
//! - the `-o` keywords of `ssh`, which podssh shows inside the section of
//!   `ssh`: a topic `keywords` of their own, with the same blocks;
//! - the retired variables, which ENVIRONMENT shows after the variables that
//!   are read: a topic `retired-variables`, as no fact of a variable may name
//!   a name that nothing reads;
//! - a file of several names (the identity files): one fact whose path is
//!   the names joined;
//! - the row `N` of EXIT STATUS, which also names `128 + N` of a signal: one
//!   payload row, as its text is one;
//! - the bound `--timeout` that is never required (`FlagRow::optional`): no
//!   field, as it changes the parser, not the text;
//! - the subcommands of a command (`relay pair`, `job start`): podssh parses
//!   them as a positional word, so they stay in the usage and the notes;
//! - an exit code has no short name in podssh: the name stays empty.

use pod_manual as pm;

use super::model::{self as own, Block, Span};
use crate::flags::{self, Availability, FlagKind, FlagRow, Verb, VERBS};

/// The topics of podssh's manual that the crate's model holds as typed facts
/// or as its own parts, so they are not copied as topics.
const TYPED: &[&str] = &["environment", "files", "exit-status", "examples", "see-also"];

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

/// One block of podssh's manual as a block of the crate's.
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

/// One row of the flag table. `parser` is the command that `tree.rs` builds
/// from the same rows: it says which flag may be given more than once.
pub fn flag(row: &FlagRow, parser: &clap::Command) -> pm::Flag {
    let kind = match row.kind {
        FlagKind::Supported => pm::FlagKind::Wired,
        // The help of such a row already says why; a second copy would drift.
        FlagKind::Accepted => pm::FlagKind::Ignored { why: String::new() },
        // The same words as `help::help_text` when a row names nothing.
        FlagKind::Refused | FlagKind::NotInFirstRelease => {
            pm::FlagKind::Refused { instead: row.instead.unwrap_or("a supported flag").to_string() }
        }
    };
    let repeatable = parser
        .get_arguments()
        .find(|a| a.get_id().as_str() == row.long)
        .is_some_and(|a| matches!(a.get_action(), clap::ArgAction::Count | clap::ArgAction::Append));
    pm::Flag {
        short: row.short,
        long: Some(row.long.to_string()),
        value: row.arg.map(str::to_string),
        help: row.help.to_string(),
        kind,
        repeatable,
        ..pm::Flag::default()
    }
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

/// The paragraphs of a command's section after its about line, but those
/// of the `-o` keywords: the notes, the line that points from `relay` to its
/// facts, and the sentence of a command that does not work here.
fn notes(section: &own::Section) -> Vec<String> {
    let mut out = Vec::new();
    let mut keywords = false;
    for b in section.blocks.iter().skip(1) {
        match b {
            Block::Sub(t) => keywords = t == own::KEYWORDS,
            Block::Para(t) if !keywords => out.push(t.clone()),
            _ => {}
        }
    }
    out
}

/// One verb. A command that does not work here has no option but `--help`
/// and no argument, as in `--help`, the manual and the JSON form.
fn command(verb: &'static Verb, section: Option<&own::Section>) -> pm::Command {
    let works = flags::availability(verb) == Availability::Works;
    let parser = crate::tree::verb_command(verb);
    let mut list: Vec<pm::Flag> =
        if works { verb.flags.iter().map(|r| flag(r, &parser)).collect() } else { Vec::new() };
    list.push(flag(&flags::HELP_FLAG, &parser));
    pm::Command {
        path: vec![verb.name.to_string()],
        aliases: verb.aliases.iter().filter(|a| **a != verb.name).map(|a| a.to_string()).collect(),
        about: format!("{}{}", verb.about, crate::help::availability_note(verb)),
        notes: section.map(notes).unwrap_or_default(),
        usage: crate::help::usage_tail(verb).to_string(),
        args: if works { arguments(&parser) } else { Vec::new() },
        flags: list,
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
        flags: options,
        groups,
        lead: super::examples::start_here().iter().filter_map(example).collect(),
        ..pm::Command::default()
    }
}

/// The blocks after the first sub-heading of `blocks`, up to the next one.
fn after_heading(blocks: &[Block], heading: Option<&str>) -> Vec<pm::Block> {
    let at = |b: &Block| matches!(b, Block::Sub(t) if heading.is_none_or(|h| t == h));
    blocks.iter().skip_while(|b| !at(b)).skip(1).take_while(|b| !matches!(b, Block::Sub(_))).map(block).collect()
}

/// The topics: each prose section of podssh's manual, the `-o` keywords and
/// the retired variables.
fn topics(manual: &own::Manual) -> Vec<pm::Topic> {
    let mut out: Vec<pm::Topic> = manual
        .sections
        .iter()
        .filter(|s| !s.command && !TYPED.contains(&s.key))
        .map(|s| pm::Topic {
            key: s.key.to_string(),
            aliases: s.aliases.iter().map(|a| a.to_string()).collect(),
            heading: s.heading.clone(),
            blocks: s.blocks.iter().map(block).collect(),
        })
        .collect();
    if let Some(ssh) = manual.sections.iter().find(|s| s.command && s.key == "ssh") {
        out.push(pm::Topic {
            key: "keywords".into(),
            aliases: Vec::new(),
            heading: own::KEYWORDS.into(),
            blocks: after_heading(&ssh.blocks, Some(own::KEYWORDS)),
        });
    }
    // ENVIRONMENT is the variables, then the retired names under their own
    // sub-heading, its first one.
    if let Some(env) = manual.sections.iter().find(|s| s.key == "environment") {
        let heading = env.blocks.iter().find_map(|b| match b {
            Block::Sub(t) => Some(t.to_uppercase()),
            _ => None,
        });
        if let Some(heading) = heading {
            out.push(pm::Topic {
                key: "retired-variables".into(),
                aliases: Vec::new(),
                heading,
                blocks: after_heading(&env.blocks, None),
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

/// The whole manual of this binary as the crate's model.
pub fn manual() -> pm::Manual {
    let ours = own::manual();
    let section = |name: &str| ours.sections.iter().find(|s| s.command && s.key == name);
    let mut commands = vec![root()];
    commands.extend(VERBS.iter().map(|v| command(v, section(v.name))));
    let description = ours
        .intro
        .iter()
        .filter_map(|b| match b {
            Block::Para(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    let examples = super::examples::section().blocks.iter().filter_map(example).collect();
    let see_also = ours
        .sections
        .iter()
        .find(|s| s.key == "see-also")
        .map(|s| {
            s.blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Item { term, text } => Some(format!("{}: {text}", own::plain(term))),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    pm::Manual {
        name: "podssh".into(),
        version: crate::help::version(),
        date: String::new(),
        about: flags::ABOUT.into(),
        names: Vec::new(),
        description,
        commands,
        topics: topics(&ours),
        facts: facts(),
        examples,
        see_also,
    }
}

#[cfg(test)]
mod tests;
