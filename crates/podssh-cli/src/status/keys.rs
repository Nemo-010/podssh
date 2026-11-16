//! `podssh status --keys`: the public part of each key that podssh keeps on
//! this host, for a fleet tool that fills an allowlist or a net's document.
//! A key is read and never made (`existing`, not `load`): a key made here
//! would be a new identity that no allowlist names. A key file is read only
//! to derive its public half, and no private byte goes into a row.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::Digest as _;
use zeroize::{Zeroize as _, Zeroizing};

use podssh_relay::cache::{self, Others};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::PublicKey;
use podssh_ssh::russh::keys::PublicKey as SshKey;

/// The beginnings of a node's key file, the new name and the old one.
const NODE_PREFIXES: [&str; 2] = ["node-", "iroh-node-"];
const KEY_SUFFIX: &str = ".key";
/// The keys of `~/.ssh` that may be the net's owner, as `podssh net` looks
/// for the one that signs.
const SSH_NAMES: [&str; 5] = ["id_ed25519", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk", "id_rsa"];

/// Where the keys are looked for.
pub(crate) struct Dirs {
    /// The cache as `pod-identity` reads it: the client's and the nodes' keys.
    pub identity: Vec<PathBuf>,
    /// The cache as podssh reads it: ACME's accounts and WARP's device.
    pub cache: Vec<PathBuf>,
    /// The user's home, for `~/.ssh`.
    pub home: Option<PathBuf>,
}

impl Dirs {
    fn here() -> Dirs {
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
        Dirs { identity: cache::pod_places().read(), cache: cache::read_dirs(), home }
    }
}

/// The member `keys` of the line: one row for each key.
pub fn value() -> Value {
    // The net held names its owner's public key; a fault of the net's file
    // is the member `net`'s to say.
    let owner = crate::net::store::held_or_none().map(|held| held.signed.doc.owner);
    Value::Array(rows(&Dirs::here(), owner.as_deref()))
}

/// The rows: the client's key, each node's, each ACME account, WARP's
/// device, and the net's owner when a net is held.
pub(crate) fn rows(dirs: &Dirs, owner: Option<&str>) -> Vec<Value> {
    let client = [file::CLIENT_FILE.to_string(), file::OLD_CLIENT_FILE.to_string()];
    let mut out = vec![identity_row("client", None, kept(&dirs.identity, &client))];
    for label in node_labels(&dirs.identity) {
        let names = [file::node_file(&label), file::old_node_file(&label)];
        out.push(identity_row("node", Some(&label), kept(&dirs.identity, &names)));
    }
    out.extend(acme_rows(&dirs.cache));
    out.push(warp_row(kept(&dirs.cache, &[crate::ssh::cloud::warp::DEVICE_FILE.to_string()])));
    if let Some(owner) = owner {
        out.push(owner_row(owner, dirs.home.as_deref()));
    }
    out
}

fn row(role: &str, label: Option<&str>, path: Option<&Path>, state: &str) -> Value {
    json!({
        "role": role,
        "label": label,
        "path": path.map(|p| p.display().to_string()),
        "type": null,
        "public": null,
        "fingerprint": null,
        "iroh": null,
        "state": state,
        "error": null,
    })
}

fn present(mut row: Value, kind: &str, public: String, fingerprint: String) -> Value {
    row["type"] = json!(kind);
    row["public"] = json!(public);
    row["fingerprint"] = json!(fingerprint);
    row
}

/// A file that is there and cannot be read: the reason names the file, and
/// never a part of what it holds.
fn unreadable(mut row: Value, why: String) -> Value {
    row["state"] = json!("unreadable");
    row["error"] = json!(why);
    row
}

/// The first file of `names` in `dirs`, searched as `pod-identity` searches:
/// each name in each directory, the new name first. A file that is there
/// and refused is still the answer, as it stops that search.
fn kept(dirs: &[PathBuf], names: &[String]) -> Option<PathBuf> {
    let mut paths = names.iter().flat_map(|name| dirs.iter().map(move |dir| dir.join(name)));
    paths.find(|p| std::fs::symlink_metadata(p).is_ok())
}

/// The labels of the nodes whose keys the cache holds, from the file names.
fn node_labels(dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rest = NODE_PREFIXES.iter().find_map(|prefix| name.strip_prefix(prefix));
            if let Some(label) = rest.and_then(|r| r.strip_suffix(KEY_SUFFIX)).filter(|l| !l.is_empty()) {
                labels.insert(label.to_string());
            }
        }
    }
    labels
}

/// An Ed25519 key of `pod-identity`, which both roads take: its OpenSSH
/// line, its fingerprint as `ssh-keygen -l` shows it, and its hex, the
/// node's name on the iroh road.
fn identity_row(role: &str, label: Option<&str>, path: Option<PathBuf>) -> Value {
    let Some(path) = path else { return row(role, label, None, "absent") };
    let base = row(role, label, Some(&path), "present");
    match file::existing(&Place::File(path.clone())) {
        Ok(Some(identity)) => {
            let public = identity.public();
            let mut done = present(base, "ssh-ed25519", openssh_line(&public), public.fingerprint());
            done["iroh"] = json!(public.hex());
            done
        }
        // It went away between the search and the read.
        Ok(None) => row(role, label, None, "absent"),
        Err(why) => unreadable(base, why),
    }
}

/// `ssh-ed25519 BASE64`: the key's SSH encoding, as a `.pub` file holds it.
pub(crate) fn openssh_line(key: &PublicKey) -> String {
    let mut blob = Vec::with_capacity(51);
    for part in [&b"ssh-ed25519"[..], &key.0[..]] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(blob))
}

/// The account of each CA that `relay serve --acme` keeps, by the CA's
/// directory; the first cache directory that holds one is the one in use.
fn acme_rows(dirs: &[PathBuf]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir.join(crate::acme::store::DIR)) else { continue };
        let mut cas: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        cas.sort();
        for ca in cas {
            let path = ca.join(crate::acme::store::ACCOUNT);
            let Some(label) = ca.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
            if std::fs::symlink_metadata(&path).is_err() || !seen.insert(label.clone()) {
                continue;
            }
            out.push(acme_row(&label, path));
        }
    }
    out
}

/// The account's P-256 key: its JWK, and its thumbprint (RFC 7638), which
/// the CA knows the account by.
fn acme_row(label: &str, path: PathBuf) -> Value {
    let base = row("acme", Some(label), Some(&path), "present");
    let text = match cache::read_own(&path, Others::NoAccess) {
        Ok(Some(text)) => Zeroizing::new(text),
        Ok(None) => return row("acme", Some(label), None, "absent"),
        Err(why) => return unreadable(base, why),
    };
    let Some(der) = crate::acme::certs::pem_block(&text, "PRIVATE KEY") else {
        return unreadable(base, format!("{}: no private key block", path.display()));
    };
    match crate::acme::jws::Account::from_pkcs8(&der) {
        Ok(account) => present(base, "ecdsa-p256", account.jwk().to_string(), account.thumbprint()),
        Err(why) => unreadable(base, format!("{}: {why}", path.display())),
    }
}

/// WARP's device: the public key of its certificate, as base64 of the
/// SubjectPublicKeyInfo that the service enrols, and its SHA-256. The
/// record's private key and token are read with it, and wiped.
fn warp_row(path: Option<PathBuf>) -> Value {
    let Some(path) = path else { return row("warp", None, None, "absent") };
    let base = row("warp", None, Some(&path), "present");
    let text = match cache::read_own(&path, Others::NoAccess) {
        Ok(Some(text)) => Zeroizing::new(text),
        Ok(None) => return row("warp", None, None, "absent"),
        Err(why) => return unreadable(base, why),
    };
    let not_a_record = || format!("{}: not a device record", path.display());
    let Ok(mut record) = serde_json::from_str::<Value>(&text) else { return unreadable(base, not_a_record()) };
    let cert = record["cert_pem"].as_str().map(str::to_string);
    wipe(&mut record);
    let spki = cert.and_then(|pem| {
        let der = crate::acme::certs::pem_block(&pem, "CERTIFICATE")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
        Some(parsed.public_key().raw.to_vec())
    });
    let Some(spki) = spki else { return unreadable(base, not_a_record()) };
    let engine = &base64::engine::general_purpose::STANDARD;
    let digest = sha2::Sha256::digest(&spki);
    let fingerprint = format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest));
    present(base, "ecdsa-p256", engine.encode(&spki), fingerprint)
}

/// Each string of a parsed record, overwritten before it is dropped.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(members) => members.values_mut().for_each(wipe),
        _ => {}
    }
}

/// The owner of the net held: its public key from the document, and the
/// key of `~/.ssh` whose `.pub` is that key, if this host has it. The
/// private file is never opened: its `.pub` names it.
fn owner_row(owner: &str, home: Option<&Path>) -> Value {
    let mut words = owner.split_whitespace();
    let (Some(kind), Some(body)) = (words.next(), words.next()) else {
        return unreadable(row("net_owner", None, None, "absent"), "the net's owner is not a public key".into());
    };
    let Ok(key) = SshKey::from_openssh(owner) else {
        return unreadable(row("net_owner", None, None, "absent"), "the net's owner is not a public key".into());
    };
    let found = home.and_then(|home| {
        SSH_NAMES.iter().map(|name| home.join(".ssh").join(name)).find(|path| {
            let public = std::fs::read_to_string(podssh_ssh::keygen::public_path(path)).ok();
            let same = public.as_deref().and_then(crate::keygen_sign::public_line);
            same.is_some_and(|k| k.key_data() == key.key_data()) && std::fs::symlink_metadata(path).is_ok()
        })
    });
    let state = if found.is_some() { "present" } else { "absent" };
    let base = row("net_owner", None, found.as_deref(), state);
    present(base, kind, format!("{kind} {body}"), crate::net::sign::owner_fingerprint(owner))
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
