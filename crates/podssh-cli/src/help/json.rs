//! `--help --json`: a command's help as data, which is its section of
//! `podssh man --json` (one model, so the two never differ). The pair, in
//! either order and with nothing else, after the verb or before it; any
//! other word is answered as before.

use std::ffi::OsString;

use crate::parsed::Parsed;

/// `-h` or `--help` and `--json`, and no other word.
fn the_pair(words: &[OsString]) -> bool {
    let words: Vec<&str> = words.iter().filter_map(|w| w.to_str()).collect();
    let help = |w: &&str| *w == "--help" || *w == "-h";
    words.len() == 2 && words.contains(&"--json") && words.iter().any(help)
}

/// The JSON of `section` (the whole manual when `None`), as `man --json` gives it.
fn json(section: Option<&str>) -> Parsed {
    let section = section.map(str::to_string);
    Parsed::Man { section, no_pager: true, roff: false, json: true, llms: None, refused: Vec::new() }
}

/// `podssh VERB --help --json`: that verb's section, else `None`.
pub fn of_verb(verb: &str, rest: &[OsString]) -> Option<Parsed> {
    the_pair(rest).then(|| json(Some(verb)))
}

/// `podssh --help --json` (the manual) or `podssh --help VERB --json` (that
/// verb's section), with `flag` the help's own word; else `None`.
pub fn of_top(flag: &OsString, rest: &[OsString]) -> Option<Parsed> {
    let mut words = vec![flag.clone()];
    match rest {
        [one] => {
            words.push(one.clone());
            the_pair(&words).then(|| json(None))
        }
        [verb, one] => {
            let verb = crate::flags::verb_for(verb.to_str()?)?;
            words.push(one.clone());
            the_pair(&words).then(|| json(Some(verb.name)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(all: &[&str]) -> Vec<OsString> {
        all.iter().map(OsString::from).collect()
    }

    fn section(parsed: Option<Parsed>) -> Option<Option<String>> {
        match parsed {
            Some(Parsed::Man { section, json: true, no_pager: true, roff: false, llms: None, refused })
                if refused.is_empty() =>
            {
                Some(section)
            }
            _ => None,
        }
    }

    #[test]
    fn the_pair_in_either_order_is_the_json_of_the_verb() {
        for rest in [["--help", "--json"], ["--json", "--help"], ["-h", "--json"]] {
            assert_eq!(section(of_verb("ssh", &words(&rest))), Some(Some("ssh".into())), "{rest:?}");
        }
    }

    #[test]
    fn another_word_is_no_help_as_json() {
        for rest in [&["--help"][..], &["--json"], &["--help", "--json", "host"], &["--help", "host"]] {
            assert!(of_verb("ssh", &words(rest)).is_none(), "{rest:?}");
        }
    }

    #[test]
    fn at_the_top_the_manual_or_a_verb() {
        let help = OsString::from("--help");
        assert_eq!(section(of_top(&help, &words(&["--json"]))), Some(None));
        assert_eq!(section(of_top(&help, &words(&["cp", "--json"]))), Some(Some("cp".into())));
        assert!(of_top(&help, &words(&["nosuchverb", "--json"])).is_none());
        assert!(of_top(&help, &words(&["cp"])).is_none());
    }
}
