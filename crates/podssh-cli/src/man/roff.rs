//! The manual as a man(7) page: what `podssh man --roff` writes, for
//! `man -l` or a man directory. The page is pod-manual's writer over
//! [`super::pod_model::manual`], so podssh writes no roff of its own: the
//! crate keeps to the man(7) macros that groff and mandoc both render, and
//! defines none (an `Fl` macro that used `\$*` once printed blank flag names
//! under groff).
//!
//! `--roff SECTION` is the crate's too ([`super::body`]): the same names
//! select a section in each form, and the section of `ssh` carries the `-o`
//! keywords, as its model says.

use pod_manual as pm;

/// The whole page.
pub fn page() -> String {
    pm::roff::render(&super::pod_model::manual())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::man::{body, pod_model, Request};

    fn requests(page: &str) -> Vec<String> {
        let first = |l: &str| l.split_whitespace().next().unwrap_or_default().to_string();
        page.lines().filter(|l| l.starts_with(['.', '\''])).map(first).collect()
    }

    /// The page of one section, as `podssh man --roff KEY` writes it.
    fn section(key: &str) -> Result<String, String> {
        body(&Request { section: Some(key), roff: true, ..Request::default() })
    }

    /// Each key of a section of the model.
    fn keys() -> Vec<String> {
        pm::sections::sections(&pod_model::manual()).into_iter().map(|s| s.key).collect()
    }

    #[test]
    fn the_first_line_is_th_and_the_name_follows() {
        let page = page();
        let first = page.lines().next().unwrap();
        assert!(first.starts_with(".TH PODSSH 1 "), "{first}");
        assert!(page.contains(".SH NAME\npodssh \\- "), "no NAME section");
    }

    /// Each section has its page, under its own title; the page of ssh
    /// carries the keywords that its model shows inside it.
    #[test]
    fn each_section_of_podssh_has_its_page() {
        for key in keys() {
            let page = section(&key).unwrap_or_else(|e| panic!("no page for {key}: {e}"));
            let title = format!(".TH {} 1 ", pm::roff::escape(&format!("PODSSH-{}", key.to_ascii_uppercase())));
            assert!(page.starts_with(&title), "{key}: {}", page.lines().next().unwrap_or(""));
        }
        let ssh = section("ssh").unwrap();
        let honoured = &crate::ssh::keywords::HONOURED[0];
        assert!(ssh.contains(&pm::roff::escape(honoured.name)), "the keywords are not in ssh's page");
        assert!(section("nonsense").is_err());
    }

    /// Each request line of each page is one of the crate's macros: no text
    /// became a request, and no macro is defined.
    #[test]
    fn the_page_uses_only_the_listed_requests() {
        let mut pages = vec![page()];
        pages.extend(keys().iter().filter_map(|k| section(k).ok()));
        for page in pages {
            for request in requests(&page) {
                assert!(pm::roff::MACROS.contains(&request.as_str()), "unlisted request {request:?}");
            }
        }
    }

    /// The control of the test above: a planted note that tries to start a
    /// request stays text, and a page with a request of its own is found.
    #[test]
    fn a_planted_request_stays_text() {
        let mut m = pod_model::manual();
        let ssh = m.commands.iter_mut().find(|c| c.path == ["ssh"]).expect("ssh");
        ssh.notes.push(".SH INJECTED\n'br\n\\fBbold\\fR -flag".into());
        let page = pm::roff::render(&m);
        assert!(requests(&page).iter().all(|r| pm::roff::MACROS.contains(&r.as_str())), "a note became a request");
        let planted = format!("{page}.de Fl\n");
        assert!(requests(&planted).iter().any(|r| !pm::roff::MACROS.contains(&r.as_str())));
    }

    /// Each flag of `ssh` is a `.TP` term with its spellings in bold and its
    /// value in italics.
    #[test]
    fn each_flag_is_a_tagged_paragraph_in_bold() {
        let page = page();
        let bold = |t: &str| format!("\\fB{}\\fR", pm::roff::escape(t));
        for row in crate::flags::SSH_FLAGS {
            let mut term = bold(&format!("--{}", row.long));
            if let Some(c) = row.short {
                term = format!("{}, {term}", bold(&format!("-{c}")));
            }
            if let Some(a) = row.arg {
                term = format!("{term} \\fI{}\\fR", pm::roff::escape(a));
            }
            assert!(page.contains(&format!(".TP\n{term}\n")), "no .TP for {term}");
        }
    }

    /// The text of a flag is the sentence that `--help` prints, its kind
    /// included once.
    #[test]
    fn the_text_of_a_flag_is_the_one_help_prints() {
        let page = page();
        let scp = crate::flags::verb_for("scp").expect("scp");
        let accepted = scp.flags.iter().find(|r| r.kind == crate::flags::FlagKind::Accepted).expect("a row");
        let squeeze = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
        let want = crate::help::help_text(accepted);
        assert!(squeeze(&page).contains(&squeeze(&pm::roff::escape(&want))), "{want}");
        assert_eq!(want.matches("Accepted and ignored").count(), 1, "{want}");
    }
}
