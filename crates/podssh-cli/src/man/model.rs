//! The blocks that podssh's tables of the manual are written in: the facts,
//! the notes, the examples and the `-o` keywords in this directory. Each is
//! read into pod-manual's model by [`super::pod_model`], whose writers make
//! the text, the man page, the JSON and `--help`.

use crate::ssh::keywords;

/// Part of a term: what a user types, a value to put in its place, or text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    Lit(String),
    Var(String),
    Plain(String),
}

/// The plain text of a term, as the text page shows it.
pub fn plain(spans: &[Span]) -> String {
    spans
        .iter()
        .map(|s| match s {
            Span::Lit(t) | Span::Var(t) | Span::Plain(t) => t.as_str(),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// Prose, filled to the width of the page.
    Para(String),
    /// One line kept as it is, such as a synopsis.
    Line(Vec<Span>),
    /// A heading inside a section ("Options").
    Sub(String),
    /// A term and its description: a flag, an argument, a variable, a file.
    Item { term: Vec<Span>, text: String },
    /// Terms and descriptions in two columns, such as the list of commands.
    Table(Vec<(Vec<Span>, String)>),
    /// What a command line does, then the command line.
    Example { text: String, command: String },
}

pub struct Section {
    /// The name `podssh man NAME` selects it by.
    pub key: &'static str,
    /// Other names that select it, such as a command's aliases.
    pub aliases: Vec<&'static str>,
    pub heading: String,
    /// A command's section; the renderers put these under one heading.
    pub command: bool,
    pub blocks: Vec<Block>,
}

fn lit(t: impl Into<String>) -> Span {
    Span::Lit(t.into())
}

fn var(t: impl Into<String>) -> Span {
    Span::Var(t.into())
}

fn text(t: impl Into<String>) -> Span {
    Span::Plain(t.into())
}

fn para(t: impl Into<String>) -> Block {
    Block::Para(t.into())
}

/// The paragraphs of DESCRIPTION: what podssh is, then the conventions of
/// each command.
pub fn description() -> Vec<String> {
    vec![
        "podssh carries SSH, or another TCP stream, through a WebSocket relay on port 443. It is one \
         static binary for hosts whose only way out is HTTPS, often through an HTTP CONNECT proxy. It \
         needs no installed ssh, no root, no pty, no DNS and no user database entry."
            .into(),
        "Answers go to stdout. Diagnostics go to stderr, so stdout can carry a protocol.".into(),
        format!(
            "A question (a host key, a password, a passphrase) goes to the controlling terminal or to \
             SSH_ASKPASS. With neither, podssh refuses at once and names the remedy. When stdin, stdout and \
             stderr are all redirected, a question on the terminal waits {} s at most.",
            podssh_ssh::terminal::UNWATCHED_PROMPT.as_secs()
        ),
        "With no command, podssh lists the commands on stderr and exits 64. It never takes a word as a \
         host: podssh example.org prints the line to type, podssh ssh example.org."
            .into(),
        "podssh COMMAND --help gives the section of one command, as podssh man COMMAND does. This manual \
         is generated from the tables of this binary, so it describes this binary and no other version."
            .into(),
    ]
}

/// The heading of the `-o` keywords, which the section of `ssh` shows
/// after its options.
pub const KEYWORDS: &str = "Keywords for -o NAME=VALUE";

/// The `-o` keywords of `podssh ssh`, under [`KEYWORDS`].
pub fn keyword_blocks() -> Vec<Block> {
    let mut blocks = vec![para(
        "The name is not case-sensitive. NAME=VALUE, NAME VALUE and NAME = VALUE are the same. For a \
         single value, the first one given wins, as in OpenSSH. An unknown keyword is an error before \
         podssh connects.",
    )];
    for k in keywords::HONOURED {
        blocks.push(Block::Item { term: vec![lit(k.name), text("="), var(k.value)], text: k.help.to_string() });
    }
    blocks.push(para(
        "A LIST of Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms, PubkeyAcceptedAlgorithms or \
         CASignatureAlgorithms is read as OpenSSH reads it: a comma list replaces podssh's own, one that \
         starts with + adds to it, with - takes from it, and with ^ puts its names first; a name may be a \
         pattern of * and ?. A name that podssh does not speak is left out, and -v says so; a list that \
         leaves nothing is refused before anything connects (64; 78 in a file), and names what podssh \
         speaks. -G prints each list as podssh will offer it.",
    ));
    for (name, why) in keywords::REFUSED {
        blocks.push(Block::Item { term: vec![lit(*name)], text: format!("refused: {why}") });
    }
    blocks.push(para(
        "Accepted and not applied. podssh gives one note at the default level for a value that you gave, on the \
         command line or in your own ssh_config. It gives none for the system's file, which says it at -v, and none \
         with -q:",
    ));
    for (name, why) in keywords::NOTED {
        blocks.push(Block::Item { term: vec![lit(*name)], text: format!("not applied: {why}") });
    }
    blocks.push(para(format!(
        "Accepted with no effect, because they change nothing that podssh does; -v names the place of \
         each: {}.",
        // Groups of ten, each ended by a semicolon, so that no sentence of
        // the list passes the limit of words of the text rules.
        keywords::IGNORED.chunks(10).map(|names| names.join(", ")).collect::<Vec<_>>().join("; ")
    )));
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_keyword_is_in_the_blocks() {
        let blocks = keyword_blocks();
        let items: Vec<String> = blocks
            .iter()
            .filter_map(|b| match b {
                Block::Item { term, .. } => Some(plain(term)),
                _ => None,
            })
            .collect();
        for k in keywords::HONOURED {
            assert!(items.contains(&format!("{}={}", k.name, k.value)), "{}", k.name);
        }
        for (name, _) in keywords::REFUSED.iter().chain(keywords::NOTED) {
            assert!(items.iter().any(|t| t == name), "{name}");
        }
        let ignored = blocks.iter().any(|b| matches!(b, Block::Para(t) if t.contains("AddKeysToAgent")));
        assert!(ignored, "the ignored keywords are missing");
    }
}
