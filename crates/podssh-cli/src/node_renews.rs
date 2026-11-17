//! Whether a pair's relay renews it, as its node last learned (T-710), for
//! `podssh status`, which asks no relay: the node keeps one small private
//! file for each label of the store, `renews-LABEL.json`, with the pair's
//! name (no token) and what its last renewal gave. `true`: a renewal took;
//! `false`: the relay renews none, or refused the stop token. A record of
//! another pair than the one stored now says nothing of it.

use serde_json::{json, Value};

/// The file of `label`, or none for a label that the store refuses.
fn file(label: &str) -> Option<String> {
    podssh_relay::pair::file_name(label).ok().map(|_| format!("renews-{label}.json"))
}

/// Keep what the node learned of the pair `name` under `label`. A store
/// that takes no write loses a line of `status` alone: nothing is said.
pub(crate) fn record(label: &str, name: &str, renews: bool) {
    let Some(file) = file(label) else { return };
    let body = json!({ "name": name, "renews": renews, "at_ms": crate::pairs::now_ms() });
    let _ = podssh_relay::cache::store_file(&file, body.to_string().as_bytes());
}

/// `renews` of `podssh status` for the pair `name` stored under `label`:
/// `true`, `false`, or null when no node learned it of this pair.
pub(crate) fn status_value(label: &str, name: &str) -> Value {
    let text = file(label).and_then(|file| podssh_relay::cache::load_file(&file));
    of_text(text.as_deref(), name)
}

/// [`status_value`] from the file's text.
fn of_text(text: Option<&str>, name: &str) -> Value {
    let kept: Option<Value> = text.and_then(|text| serde_json::from_str(text).ok());
    let kept = kept.filter(|kept| kept["name"].as_str() == Some(name));
    kept.and_then(|kept| kept["renews"].as_bool()).map_or(Value::Null, Value::Bool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_of_the_pair_now_says_whether_it_renews() {
        let text = r#"{"name":"p-1","renews":true,"at_ms":5}"#;
        assert_eq!(of_text(Some(text), "p-1"), Value::Bool(true));
        assert_eq!(of_text(Some(&text.replace("true", "false")), "p-1"), Value::Bool(false));
    }

    #[test]
    fn no_record_or_one_of_another_pair_says_nothing() {
        assert_eq!(of_text(None, "p-1"), Value::Null);
        assert_eq!(of_text(Some(r#"{"name":"p-0","renews":true}"#), "p-1"), Value::Null, "the pair before");
        assert_eq!(of_text(Some("not json"), "p-1"), Value::Null);
        assert_eq!(of_text(Some(r#"{"name":"p-1","renews":"yes"}"#), "p-1"), Value::Null);
    }

    #[test]
    fn a_label_that_the_store_refuses_has_no_file() {
        assert_eq!(file("lab").as_deref(), Some("renews-lab.json"));
        assert!(file("../x").is_none());
    }
}
