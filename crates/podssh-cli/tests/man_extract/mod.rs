//! The readers that the parity gate (`man_flag_parity.rs`) reads the two
//! renderings with: the `Options:` list of `--help`, and that of each
//! command's section of the text manual. Both are pod-manual's layout: a
//! term four spaces in, on a line of its own, then its sentence eight in.
//! They read the text a user sees, not the tables, so a writer that drops
//! or changes a row fails the gate.
#![allow(dead_code)] // each test uses a subset.

use crate::UNIVERSAL;
use podssh_cli::flags::{availability, Availability, FlagRow, Verb, VERBS};
use podssh_cli::help;
use std::collections::BTreeMap;

// ---------------------------------------------------------------- the sections

/// `""` is the top level, then each verb that works in this binary, in the
/// order of `--help`. A verb that does not work has no option but `--help`:
/// its section says that it exits 70.
pub fn sections() -> Vec<(String, Option<&'static Verb>)> {
    let mut out: Vec<(String, Option<&'static Verb>)> = vec![(String::new(), None)];
    for v in VERBS.iter().filter(|v| availability(v) == Availability::Works) {
        out.push((v.name.to_string(), Some(v)));
    }
    out
}

/// The help text for a section: the top-level help, or one verb's.
pub fn help_text(verb: Option<&'static Verb>) -> String {
    match verb {
        None => help::top_level_help(),
        Some(v) => help::verb_help(v),
    }
}

/// The words of a text with each run of white space as one space: the
/// writers wrap their lines.
pub fn squeeze(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------- one option

/// A single-character or long option spelling, as a user types it.
pub fn looks_like_flag(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix("--") {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    } else if let Some(rest) = token.strip_prefix('-') {
        rest.chars().count() == 1 && rest.chars().all(|c| c.is_ascii_alphanumeric())
    } else {
        false
    }
}

/// One option of a rendering: its flags, value name and sentence.
#[derive(Debug, Clone)]
pub struct Item {
    pub flags: Vec<String>,
    pub value: Option<String>,
    pub text: String,
}

/// The flags and the value name of one term: `-p, --port PORT`.
fn flags_and_value(term: &str) -> (Vec<String>, Option<String>) {
    let tokens: Vec<&str> = term.split_whitespace().collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i].trim_end_matches(',');
        if !looks_like_flag(token) {
            break;
        }
        names.push(token.to_string());
        i += 1;
    }
    let value = (i < tokens.len()).then(|| tokens[i..].join(" "));
    (names, value)
}

/// The items of the first `Options:` list of `text`: each term four spaces
/// in, its sentence eight in, up to the first line that is neither (the
/// blank line before the next block).
pub fn options(text: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if !inside {
            inside = line == "  Options:";
            continue;
        }
        if let Some(rest) = line.strip_prefix("        ") {
            if let Some(last) = items.last_mut() {
                if !last.text.is_empty() {
                    last.text.push(' ');
                }
                last.text.push_str(rest.trim());
            }
            continue;
        }
        match line.strip_prefix("    ") {
            Some(term) if !term.starts_with(' ') && !term.is_empty() => {
                let (flags, value) = flags_and_value(term);
                match items.last_mut() {
                    // A term too long for one line goes on at four spaces.
                    Some(last) if flags.is_empty() && last.text.is_empty() => {
                        let more = term.trim().to_string();
                        last.value = Some(last.value.take().map_or(more.clone(), |v| format!("{v} {more}")));
                    }
                    _ => items.push(Item { flags, value, text: String::new() }),
                }
            }
            _ => break,
        }
    }
    items
}

/// Each flag of a list, by its one spelling, with its value name.
pub fn flag_map(items: &[Item], verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    for item in items {
        for flag in &item.flags {
            map.insert(canonical(verb, flag), item.value.clone());
        }
    }
    map
}

/// Each flag of a list, by its one spelling, with its sentence.
pub fn descriptions(items: &[Item], verb: Option<&Verb>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in items {
        for flag in &item.flags {
            map.insert(canonical(verb, flag), item.text.clone());
        }
    }
    map
}

// ------------------------------------------------------------- the manual side

/// The manual split into regions: `""` is SYNOPSIS, which holds the options
/// before a command, and each command's region runs from its heading
/// (`podssh ssh`) to the next heading (a line that starts in column 0).
pub fn man_regions(page: &str) -> BTreeMap<String, String> {
    let mut regions: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in page.lines() {
        let heading = !line.is_empty() && !line.starts_with(' ');
        if heading {
            current = if line == "SYNOPSIS" {
                Some(String::new())
            } else {
                line.strip_prefix("podssh ").filter(|n| VERBS.iter().any(|v| v.name == *n)).map(str::to_string)
            };
            if let Some(n) = &current {
                regions.entry(n.clone()).or_default();
            }
            continue;
        }
        if let Some(name) = &current {
            let region = regions.get_mut(name).expect("the region was inserted above");
            region.push_str(line);
            region.push('\n');
        }
    }
    regions
}

// ------------------------------------------------------------- one spelling

/// `--flag`, `-f` and the aliases, as one name: the row's long spelling. A
/// token the table does not know is kept as it is, so that a flag in one
/// rendering and not in the binary is reported by name.
pub fn canonical(verb: Option<&Verb>, token: &str) -> String {
    match verb {
        Some(v) => {
            if let Some(long) = token.strip_prefix("--") {
                if v.flags.iter().any(|r| r.long == long) {
                    return format!("--{long}");
                }
            } else if token.chars().count() == 2 {
                let c = token.chars().nth(1).expect("two characters");
                if let Some(row) = v.flags.iter().find(|r| r.short == Some(c)) {
                    return format!("--{}", row.long);
                }
            }
            token.to_string()
        }
        None => podssh_cli::flags::TOP_OPTIONS
            .iter()
            .find(|(short, _, _)| *short == token)
            .map(|(_, long, _)| long.to_string())
            .unwrap_or_else(|| token.to_string()),
    }
}

/// The table itself, as the third reading: both renderings agreeing on a
/// flag that the table does not have is still a failure.
pub fn tree_map(verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    match verb {
        Some(v) => {
            for row in v.flags {
                map.insert(format!("--{}", row.long), row.arg.map(str::to_string));
            }
        }
        None => {
            for (_, long, _) in podssh_cli::flags::TOP_OPTIONS {
                map.insert(long.to_string(), None);
            }
        }
    }
    map.insert(UNIVERSAL.to_string(), None);
    map
}

/// The sentence that each writer gives a flag of the section: the row's,
/// or that of an option before a command.
pub fn sentences(verb: Option<&Verb>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    match verb {
        Some(v) => {
            for row in v.flags.iter().chain(std::iter::once(&podssh_cli::flags::HELP_FLAG)) {
                map.insert(format!("--{}", row.long), help::help_text(row));
            }
        }
        None => {
            for (_, long, about) in podssh_cli::flags::TOP_OPTIONS {
                let flag = pod_manual::Flag::long(long.trim_start_matches('-'), about);
                map.insert(long.to_string(), pod_manual::sections::flag_text(&flag));
            }
        }
    }
    map
}

/// The row for a canonical name, when the section has one.
pub fn row_for(verb: Option<&'static Verb>, canonical: &str) -> Option<&'static FlagRow> {
    let v = verb?;
    v.flags.iter().find(|r| format!("--{}", r.long) == canonical)
}
