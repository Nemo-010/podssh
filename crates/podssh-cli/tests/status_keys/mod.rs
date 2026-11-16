//! `podssh status --keys` as a process: in a scratch cache with a node's key
//! and a client's, both are listed with the fingerprints that `podssh
//! keygen -l` prints; the run makes no file; no private byte is printed.

use super::*;

/// Seeds of the repository's fixture form, not credentials.
const CLIENT_SEED: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const NODE_SEED: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";

/// The names of the files under `dir`, with their sizes and times.
fn listing(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            let m = e.metadata().unwrap();
            (e.file_name().to_string_lossy().into_owned(), m.len(), m.modified().unwrap())
        })
        .collect();
    v.sort();
    v
}

/// The rows of `role` whose file is under `home`: the runner's own cache
/// places (its runtime and temporary directories) may hold keys of its own.
fn rows_under<'a>(doc: &'a Value, role: &str, home: &Path) -> Vec<&'a Value> {
    let home = home.display().to_string();
    let rows = doc["keys"].as_array().expect("keys is a list");
    rows.iter().filter(|r| r["role"] == role && r["path"].as_str().is_some_and(|p| p.starts_with(&home))).collect()
}

#[test]
fn keys_lists_the_client_and_the_node_with_keygen_s_fingerprints() {
    let home = scratch("keys");
    let dir = cache_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, seed) in [("client.key", CLIENT_SEED), ("node-lab.key", NODE_SEED)] {
        let made = podssh_relay::cache::create_private(&dir.join(name), format!("{seed}\n").as_bytes());
        assert!(made.unwrap(), "{name}");
    }
    let before = listing(&dir);
    let (rc, out, err) = status(&home, &["--keys"], &[]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(listing(&dir), before, "the run made or changed a file");
    for seed in [CLIENT_SEED, NODE_SEED] {
        assert!(!out.contains(seed) && !err.contains(seed), "a private key leaked: {out}{err}");
    }
    let doc = one_line(&out);
    let client = rows_under(&doc, "client", &home);
    let node = rows_under(&doc, "node", &home);
    assert_eq!((client.len(), node.len()), (1, 1), "{out}");
    assert_eq!(node[0]["label"], "lab");
    for row in [client[0], node[0]] {
        assert_eq!(row["state"], "present", "{row}");
        // The public line, as a .pub file, has the fingerprint that keygen prints.
        let public = home.join("row.pub");
        std::fs::write(&public, format!("{}\n", row["public"].as_str().unwrap())).unwrap();
        let (rc, printed, err) = ran(command(&home, "keygen", &["-l", "-f", public.to_str().unwrap()], &[]));
        assert_eq!(rc, 0, "{err}");
        let fingerprint = row["fingerprint"].as_str().unwrap();
        assert!(fingerprint.starts_with("SHA256:") && printed.contains(fingerprint), "{printed} vs {row}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// No key in the cache: none is made, and the client's is absent; with no
/// cache at all, the same. Without --keys, keys is null.
#[test]
fn keys_makes_no_key_and_none_is_absent() {
    let home = scratch("keys-none");
    let dir = cache_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    let (rc, out, err) = status(&home, &["--keys"], &[]);
    assert_eq!(rc, 0, "{err}");
    assert!(listing(&dir).is_empty(), "a key was made: {:?}", listing(&dir));
    let doc = one_line(&out);
    assert!(rows_under(&doc, "client", &home).is_empty(), "{out}");
    let (rc, out, err) = status(&home, &["--keys"], &[("PODSSH_CACHE_DIR", "none")]);
    assert_eq!(rc, 0, "{err}");
    let doc = one_line(&out);
    let client: Vec<&Value> = doc["keys"].as_array().unwrap().iter().filter(|r| r["role"] == "client").collect();
    assert_eq!((client.len(), client[0]["state"].as_str()), (1, Some("absent")), "{out}");
    assert!(client[0]["path"].is_null(), "{out}");
    let (_, out, _) = status(&home, &[], &[]);
    assert!(one_line(&out)["keys"].is_null(), "{out}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A destination with --keys is a usage error: the keys are this host's.
#[test]
fn keys_with_a_destination_is_refused() {
    let home = scratch("keys-dest");
    let (rc, out, err) = status(&home, &["--keys", "user@fixture.example"], &[]);
    assert_eq!(rc, 64, "{out}{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("--keys"), "{err}");
    let _ = std::fs::remove_dir_all(&home);
}
