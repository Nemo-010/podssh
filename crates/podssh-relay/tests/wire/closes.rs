//! `closes.json`: each close of the reverse road, its payload as `pod-ws`
//! writes and reads it, and what `pod-relay`'s table makes of it.

use podssh_relay::reverse::closes::{classify, resumes, RelayClose, Retry};
use podssh_ws::session::{close_code_and_reason, close_payload};

use crate::common::{bytes, hex, name, number, of_kind, text};

/// The page's name of a retry.
fn retry(r: Retry) -> &'static str {
    match r {
        Retry::Never => "never",
        Retry::NewSession => "new-session",
        Retry::NewPair => "new-pair",
        Retry::Reconnect => "reconnect",
    }
}

#[test]
fn each_close_has_the_page_s_payload_retry_and_resume() {
    for v in of_kind("closes", "close") {
        let code = u16::try_from(number(&v, "code")).expect("a code");
        let reason = text(&v, "reason");
        assert_eq!(hex(&close_payload(Some(code), reason)), text(&v, "payload"), "{}", name(&v));
        assert_eq!(close_code_and_reason(&bytes(&v, "payload")), (Some(code), reason.to_string()), "{}", name(&v));
        let close = RelayClose { code, reason: reason.to_string(), clean: true };
        let read = classify(&close);
        assert_eq!(read.row.is_some(), v["matched"].as_bool().expect("matched"), "{}", name(&v));
        assert_eq!(retry(read.retry), text(&v, "retry"), "{}", name(&v));
        assert_eq!(resumes(&close), v["resumes"].as_bool().expect("resumes"), "{}", name(&v));
    }
}
