//! `podssh pipe --install NAME A B` (T-726): a pipe made a service of this
//! user by the same ways as a node and as `ssh --install`, so that a local
//! forward (`tcp-listen:` to a road) or a gateway outlives the shell that
//! started it. The service runs this binary with the words that the user
//! typed, but `--install NAME`, in the directory where they were typed;
//! after the verb, `-o BatchMode=yes` (nobody is there to answer a prompt),
//! `--env-file`, and `--keep-listening` where a side listens. The unit holds
//! paths and words alone: an address with a credential in it is refused, as
//! it would sit in the unit's command line, which other users may read.

use std::io::Write;
use std::path::Path;

use super::{Kind, Spec};
use crate::pipe::address::{self, Address};
use crate::pipe::PipeArgs;
use crate::relay_settings::Refusal;

/// `podssh pipe`'s first step: `--env-file`, `--install` and `--uninstall`.
/// `Some(code)` ends the run.
pub(crate) fn first(args: &PipeArgs, err: &mut dyn Write) -> Option<i32> {
    let ssh = &args.ssh;
    if ssh.env_file.is_some() && (ssh.install.is_some() || ssh.uninstall.is_some()) {
        let why = "--env-file is the file that --install writes for the service: give it to the service's run alone";
        return Some(Refusal::usage(why).report("pipe", err));
    }
    if ssh.install.is_some() && ssh.uninstall.is_some() {
        return Some(Refusal::usage("--install and --uninstall: give one").report("pipe", err));
    }
    if let Some(file) = &ssh.env_file {
        return super::env::apply(Path::new(file)).err().map(|refusal| refusal.report("pipe", err));
    }
    if let Some(name) = &ssh.uninstall {
        return Some(match super::ssh::checked(name, "--uninstall") {
            Ok(()) => super::uninstall(Kind::Pipe, name, err),
            Err(refusal) => refusal.report("pipe", err),
        });
    }
    let name = ssh.install.as_deref()?;
    let words =
        crate::detach::run_words()
            .ok_or_else(|| Refusal::config("--install: the words of this run were not kept"))
            .and_then(|words| {
                words.iter().map(|w| w.to_str().map(str::to_string)).collect::<Option<Vec<String>>>().ok_or_else(|| {
                    Refusal::usage("--install: a word that is not UTF-8 cannot go in a service's command")
                })
            });
    Some(match words.and_then(|words| prepare(args, name, &words)) {
        Ok((spec, notes)) => super::install(&spec, &notes, &mut std::io::stdout(), err),
        Err(refusal) => refusal.report("pipe", err),
    })
}

/// The service's command and the notes on it, from `words`, this run's
/// words with the verb first.
pub(crate) fn prepare(args: &PipeArgs, name: &str, words: &[String]) -> Result<(Spec, Vec<String>), Refusal> {
    super::ssh::checked(name, "--install")?;
    let (a, b) = address::both(args.a.as_deref(), args.b.as_deref())?;
    for side in [&a, &b] {
        if matches!(side, Address::Stdio | Address::Fd(_)) {
            return Err(Refusal::usage(
                "--install: a service has no stdin, stdout or other descriptor of a shell: give two sides that \
                 open their own, as tcp-listen:PORT and a road",
            ));
        }
    }
    for side in [args.a.as_deref(), args.b.as_deref()].into_iter().flatten() {
        if let Some(why) = credential_in(side) {
            return Err(Refusal::usage(format!("--install: {why}")));
        }
    }
    let listening = a.listens() || b.listens();
    let mut notes = Vec::new();
    let exe = super::this_binary()?;
    let env_file = super::env_file(Kind::Pipe, name, &mut notes)?;
    let words = service_words(words, &env_file, listening && !args.keep_listening);
    super::text::one_line(&words)?;
    let dir = std::env::current_dir().ok();
    if let Some(dir) = &dir {
        super::text::one_line(&[dir.display().to_string()])?;
        notes.push(format!("it runs in {}, for the relative paths of its words", dir.display()));
    }
    let spec = Spec { kind: Kind::Pipe, name: name.to_string(), exe, args: words, dir, env_file };
    Ok((spec, notes))
}

/// Why `side` holds a credential that a unit would show: the user part of
/// a URL (`wss://user:secret@host/`); none else.
pub(crate) fn credential_in(side: &str) -> Option<String> {
    let (_, rest) = side.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@').then(|| {
        let scheme = side.split("://").next().unwrap_or_default();
        format!(
            "the {scheme}:// side names a user and a password, which would sit in the service's unit: give them \
             another way, as a file of the road's flags"
        )
    })
}

/// The words of the service, from those of this run (the verb first): the
/// verb, `-o BatchMode=yes`, `--env-file FILE`, `--keep-listening` when
/// `keep` (a listening side serves each client, not only the first), then
/// the user's words but `--install NAME`.
pub(crate) fn service_words(words: &[String], env_file: &Path, keep: bool) -> Vec<String> {
    let mut out: Vec<String> = words.iter().take(1).cloned().collect();
    out.extend(["-o".to_string(), "BatchMode=yes".to_string()]);
    out.extend(["--env-file".to_string(), env_file.display().to_string()]);
    if keep {
        out.push("--keep-listening".to_string());
    }
    let mut rest = words.iter().skip(1);
    while let Some(word) = rest.next() {
        if word == "--" {
            out.push(word.clone());
            out.extend(rest.by_ref().cloned());
            break;
        }
        if word == "--install" {
            rest.next();
        } else if !word.starts_with("--install=") {
            out.push(word.clone());
        }
    }
    out
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
