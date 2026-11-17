//! Each caller's counts of a node's exit (T-721) for `podssh status`, which
//! asks no node: the node keeps one small private file for its label,
//! `exit-LABEL.json` in the cache, with each caller's fingerprint (never
//! more of its key), connects, refusals and bytes, written each 2 s while a
//! count moved, by a thread of its own process. `status` reads each such
//! file that the cache holds. A cache that takes no write loses the field
//! of `status` alone: the exit goes on.

use std::sync::OnceLock;
use std::time::Duration;

use podssh_relay::reverse::exit_caller;
use serde_json::{json, Value};

/// How often the file is written while a count moved.
const WRITE_EVERY: Duration = Duration::from_secs(2);
/// The prefix and the suffix of each node's file.
const PREFIX: &str = "exit-";
const SUFFIX: &str = ".json";

/// The file of `label`, or none for a label that the store refuses.
fn file(label: &str) -> Option<String> {
    podssh_relay::pair::file_name(label).ok().map(|_| format!("{PREFIX}{label}{SUFFIX}"))
}

/// Start the writer of the node `label`'s counts, once a process.
pub(crate) fn keep(label: &str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    let Some(name) = file(label) else { return };
    if STARTED.set(()).is_err() {
        return;
    }
    let label = label.to_string();
    // A thread, not a task: the roads run their own runtimes, and a node
    // keeps one writer for each of them.
    let _ = std::thread::Builder::new().name("exit-counts".into()).spawn(move || {
        let counts = exit_caller::counts();
        let mut written = None;
        loop {
            std::thread::sleep(WRITE_EVERY);
            let moved = counts.moved();
            if written == Some(moved) {
                continue;
            }
            let body = body(&label, crate::pairs::now_ms(), &counts.rows());
            if podssh_relay::cache::store_file(&name, body.to_string().as_bytes()).is_ok() {
                written = Some(moved);
            }
        }
    });
}

/// The file's body: the node's label, when it was written, and each caller.
fn body(label: &str, at_ms: i64, rows: &[podssh_relay::reverse::exit_count::Row]) -> Value {
    json!({ "label": label, "at_ms": at_ms, "callers": rows })
}

/// `exits` of `podssh status`: each node's counts that the cache holds, by
/// its label; an empty list with none.
pub(crate) fn status_value() -> Value {
    let mut names: Vec<String> = Vec::new();
    for dir in podssh_relay::cache::read_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(PREFIX) && name.ends_with(SUFFIX) && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names.sort();
    let each = names.iter().filter_map(|name| of_text(podssh_relay::cache::load_file(name).as_deref()?));
    Value::Array(each.collect())
}

/// One node's entry of `exits` from its file's text; none for a text that
/// does not read as one.
fn of_text(text: &str) -> Option<Value> {
    let kept: Value = serde_json::from_str(text).ok()?;
    let label = kept["label"].as_str()?;
    let callers = kept["callers"].as_array()?;
    Some(json!({ "label": label, "at_ms": kept["at_ms"], "callers": callers }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::reverse::exit_count::Counts;

    fn key(b: u8) -> podssh_relay::identity::PublicKey {
        podssh_relay::identity::PublicKey([b; 32])
    }

    #[test]
    fn counters_of_each_caller_read_back_as_status_shows_them() {
        let counts = Counts::default();
        counts.connected(&key(1));
        counts.refused(&key(1));
        counts.refused(&key(2));
        let text = body("gw", 5, &counts.rows()).to_string();
        let read = of_text(&text).unwrap();
        assert_eq!(read["label"], "gw");
        let callers = read["callers"].as_array().unwrap();
        let one = callers.iter().find(|c| c["key"] == key(1).fingerprint()).unwrap();
        assert_eq!((one["connects"].as_u64(), one["refusals"].as_u64()), (Some(1), Some(1)));
        assert_eq!(one["bytes_up"].as_u64(), Some(0));
        assert!(!text.contains(&key(1).hex()), "a fingerprint, never the key");
    }

    #[test]
    fn counters_file_is_per_label_and_a_bad_text_says_nothing() {
        assert_eq!(file("gw").as_deref(), Some("exit-gw.json"));
        assert!(file("../x").is_none());
        assert!(of_text("not json").is_none());
        assert!(of_text(r#"{"label":"gw"}"#).is_none(), "no callers");
    }
}
