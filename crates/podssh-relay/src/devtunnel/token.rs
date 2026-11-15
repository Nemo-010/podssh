//! The user's token of Dev Tunnels, from a private file that the user
//! names: one line `SCHEME TOKEN`, as `Authorization` takes it, with
//! SCHEME `github`, `aad` or `bearer`. Blank lines and lines that start
//! with `#` are skipped. A failure names the file and the rule, never a
//! byte of the token.

use std::path::Path;

use pod_core::{Class, Failure, Stage};
use pod_devtunnel::{AccessToken, Scheme, UserToken};
use zeroize::Zeroizing;

/// A setting that cannot be used: the file, or its words.
fn config(text: String) -> Failure {
    Failure::new(Stage::Host, Class::Config, text)
}

/// The token of the private file at `path`: a file that others can read is
/// refused, as ssh refuses a key.
pub fn read_token_file(path: &Path) -> Result<UserToken, Failure> {
    let shown = path.display().to_string();
    let text = crate::cache::read_private(path).map_err(config)?;
    let text = Zeroizing::new(text);
    parse_token(&text).map_err(|failure| config(format!("{shown}: {}", failure.text())))
}

/// The token of the text of a token file.
pub fn parse_token(text: &str) -> Result<UserToken, Failure> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(line) = lines.next() else {
        return Err(config("no token: give one line SCHEME TOKEN, SCHEME github, aad or bearer".into()));
    };
    if lines.next().is_some() {
        return Err(config("more than one token: give one line SCHEME TOKEN".into()));
    }
    // A bare token is refused: the scheme of a token cannot be read from
    // it, and a wrong one is a refusal of the API that names no cause.
    let Some((word, secret)) = line.split_once(char::is_whitespace) else {
        return Err(config("no scheme: give the line as SCHEME TOKEN, SCHEME github, aad or bearer".into()));
    };
    let Some(scheme) = Scheme::parse(word) else {
        return Err(config("the first word of the line is not github, aad or bearer".into()));
    };
    UserToken::new(scheme, secret.trim()).map_err(|mut failure| {
        failure.class = Class::Config;
        failure
    })
}

/// The tunnel access token of the private file at `path` (T-785): one
/// line, the token alone (`devtunnel token TUNNEL --scopes connect`), as the
/// service gives it; blank lines and `#` comments are skipped.
pub fn read_access_file(path: &Path) -> Result<AccessToken, Failure> {
    let shown = path.display().to_string();
    let text = crate::cache::read_private(path).map_err(config)?;
    let text = Zeroizing::new(text);
    parse_access(&text).map_err(|failure| config(format!("{shown}: {}", failure.text())))
}

/// The access token of the text of an access-token file.
pub fn parse_access(text: &str) -> Result<AccessToken, Failure> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(line) = lines.next() else {
        return Err(config("no token: give the tunnel's access token on one line".into()));
    };
    if lines.next().is_some() || line.contains(char::is_whitespace) {
        return Err(config("more than one word: give the tunnel's access token alone on one line".into()));
    }
    AccessToken::new(line).map_err(|mut failure| {
        failure.class = Class::Config;
        failure
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devtunnel_a_token_line_has_its_scheme_and_no_failure_shows_the_token() {
        let token = parse_token("# a comment\n\n  aad made-up-token-of-a-test \n").unwrap();
        assert_eq!(token.scheme(), Scheme::Aad);
        assert!(!format!("{token:?}").contains("made-up"));
        assert_eq!(parse_token("GitHub made-up").unwrap().scheme(), Scheme::Github);
        for bad in ["", "# only\n", "made-up-bare-token", "tunnel made-up-x", "github a\nbearer b", "github two words"]
        {
            let failure = parse_token(bad).unwrap_err();
            assert_eq!(failure.class, Class::Config, "{bad:?}");
            assert!(!failure.chain().contains("made-up"), "{}", failure.chain());
        }
    }

    #[test]
    fn devtunnel_an_access_token_is_one_word_and_no_failure_shows_it() {
        assert!(parse_access("# the tunnel's\n\n  made-up-access.of.a-test \n").is_ok());
        for bad in ["", "# only\n", "made-up one", "made-up-a\nmade-up-b", "made-up\u{7}x"] {
            let failure = parse_access(bad).unwrap_err();
            assert_eq!(failure.class, Class::Config, "{bad:?}");
            assert!(!failure.chain().contains("made-up"), "{}", failure.chain());
        }
    }
}
