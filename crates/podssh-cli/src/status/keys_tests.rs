//! The tests of `podssh status --keys`: each key kept is listed with its
//! public half, none is made, and no private byte reaches a row.

use super::*;
use podssh_relay::identity::Identity;
use podssh_ssh::russh::keys::ssh_key::HashAlg;

/// A seed of the repository's fixture form, not a credential.
const SEED_HEX: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const OTHER_HEX: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const OWNER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-status-keys-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A private file, as podssh makes its key files.
fn private(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    assert!(cache::create_private(path, body.as_bytes()).unwrap(), "{}", path.display());
}

fn seed(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

fn dirs(dir: &Path, home: Option<&Path>) -> Dirs {
    Dirs { identity: vec![dir.to_path_buf()], cache: vec![dir.to_path_buf()], home: home.map(Path::to_path_buf) }
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = walk(dir).iter().map(|p| p.display().to_string()).collect();
    names.sort();
    names
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries.flatten().flat_map(|e| std::iter::once(e.path()).chain(walk(&e.path()))).collect()
}

fn role<'a>(rows: &'a [Value], role: &str) -> Vec<&'a Value> {
    rows.iter().filter(|r| r["role"] == role).collect()
}

#[test]
fn the_client_and_each_node_are_listed_with_their_public_halves() {
    let dir = scratch("listed");
    private(&dir.join(file::CLIENT_FILE), &format!("{SEED_HEX}\n"));
    private(&dir.join(file::node_file("alpha")), &format!("{OTHER_HEX}\n"));
    let before = listing(&dir);
    let rows = super::rows(&dirs(&dir, None), None);
    assert_eq!(listing(&dir), before, "the run made or changed a file");
    let client = Identity::from_seed(&seed(SEED_HEX)).public();
    let node = Identity::from_seed(&seed(OTHER_HEX)).public();
    let c = role(&rows, "client")[0];
    assert_eq!(c["state"], "present", "{c}");
    assert_eq!(c["type"], "ssh-ed25519");
    assert_eq!(c["fingerprint"], client.fingerprint());
    assert_eq!(c["iroh"], client.hex());
    assert_eq!(c["path"], dir.join(file::CLIENT_FILE).display().to_string());
    let n = role(&rows, "node");
    assert_eq!(n.len(), 1, "{rows:?}");
    assert_eq!((n[0]["label"].as_str(), n[0]["fingerprint"].as_str()), (Some("alpha"), Some(&*node.fingerprint())));
    // The line is the one that OpenSSH reads, with the same fingerprint.
    let line = c["public"].as_str().unwrap();
    let parsed = SshKey::from_openssh(line).expect("an OpenSSH line");
    assert_eq!(parsed.fingerprint(HashAlg::Sha256).to_string(), client.fingerprint());
    let text = Value::Array(rows).to_string();
    assert!(!text.contains(SEED_HEX) && !text.contains(OTHER_HEX), "a private byte leaked: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no key, each is absent and none is made: a `load` in place of
/// `existing` makes the client's key file, and fails here.
#[test]
fn no_key_is_made() {
    let dir = scratch("none");
    let rows = super::rows(&dirs(&dir, None), None);
    assert!(listing(&dir).is_empty(), "a file was made: {:?}", listing(&dir));
    assert_eq!(role(&rows, "client")[0]["state"], "absent");
    assert!(role(&rows, "client")[0]["path"].is_null());
    assert!(role(&rows, "node").is_empty());
    assert_eq!(role(&rows, "warp")[0]["state"], "absent");
    assert!(role(&rows, "net_owner").is_empty(), "no net, no owner");
    // No directory at all: PODSSH_CACHE_DIR=none.
    let none = Dirs { identity: Vec::new(), cache: Vec::new(), home: None };
    assert_eq!(role(&super::rows(&none, None), "client")[0]["state"], "absent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file that is not a key is unreadable, with the file's name and none
/// of its text; it is never replaced.
#[test]
fn a_bad_key_file_is_unreadable_and_kept() {
    let dir = scratch("bad");
    let planted = "zz".repeat(32);
    private(&dir.join(file::node_file("beta")), &planted);
    let rows = super::rows(&dirs(&dir, None), None);
    let n = role(&rows, "node");
    assert_eq!(n[0]["state"], "unreadable", "{rows:?}");
    assert!(n[0]["error"].as_str().unwrap().contains("node-beta.key"));
    assert!(!Value::Array(rows.clone()).to_string().contains(&planted));
    assert_eq!(std::fs::read_to_string(dir.join(file::node_file("beta"))).unwrap(), planted);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An ACME account: its JWK and its thumbprint, never its PEM.
#[test]
fn an_acme_account_shows_its_jwk_and_thumbprint() {
    let dir = scratch("acme");
    let account = crate::acme::jws::Account::generate().unwrap();
    let pem = account.pem();
    let path = dir.join(crate::acme::store::DIR).join("ca.example-0123abcd").join(crate::acme::store::ACCOUNT);
    private(&path, &pem);
    let rows = super::rows(&dirs(&dir, None), None);
    let a = role(&rows, "acme");
    assert_eq!(a.len(), 1, "{rows:?}");
    assert_eq!(a[0]["label"], "ca.example-0123abcd");
    assert_eq!(a[0]["fingerprint"], account.thumbprint());
    assert_eq!(a[0]["public"], account.jwk().to_string());
    let text = Value::Array(rows).to_string();
    let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(body.iter().all(|line| !text.contains(line)), "the private key leaked: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A WARP record that is not one is unreadable, and none of it is shown.
#[test]
fn a_bad_warp_record_is_unreadable() {
    let dir = scratch("warp");
    let planted = r#"{"key_pem":"PLANTED-NOT-A-KEY","cert_pem":"nothing"}"#;
    private(&dir.join(crate::ssh::cloud::warp::DEVICE_FILE), planted);
    let rows = super::rows(&dirs(&dir, None), None);
    let w = role(&rows, "warp");
    assert_eq!(w[0]["state"], "unreadable", "{rows:?}");
    assert!(!Value::Array(rows).to_string().contains("PLANTED-NOT-A-KEY"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The net's owner: its key from the document, and the file of `~/.ssh`
/// whose `.pub` is that key.
#[test]
fn the_net_owner_is_found_by_its_pub_file() {
    let dir = scratch("owner");
    let home = scratch("owner-home");
    let rows = super::rows(&dirs(&dir, Some(&home)), Some(OWNER));
    let o = role(&rows, "net_owner");
    assert_eq!((o[0]["state"].as_str(), o[0]["public"].as_str()), (Some("absent"), Some(OWNER)));
    assert_eq!(o[0]["fingerprint"], crate::net::sign::owner_fingerprint(OWNER));
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_ed25519.pub"), format!("{OWNER} owner@fixture\n")).unwrap();
    // Its body is never read: a planted text stands for it.
    std::fs::write(ssh.join("id_ed25519"), "PLANTED-PRIVATE-BODY").unwrap();
    let rows = super::rows(&dirs(&dir, Some(&home)), Some(OWNER));
    let o = role(&rows, "net_owner");
    assert_eq!(o[0]["state"], "present", "{rows:?}");
    assert_eq!(o[0]["path"], ssh.join("id_ed25519").display().to_string());
    assert!(!Value::Array(rows).to_string().contains("PLANTED-PRIVATE-BODY"));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&home);
}

/// A P-256 key of p256 that signs rcgen's certificate, as WARP's device key
/// is one.
struct DeviceKey {
    signing: p256::ecdsa::SigningKey,
    point: Vec<u8>,
}

impl rcgen::PublicKeyData for DeviceKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for DeviceKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn pem_of(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A WARP record of pod-warp's form (`store.rs`: `device`, `cert_pem`,
/// `key_pem`) whose certificate is a real one of a P-256 key: its row
/// is the key's SubjectPublicKeyInfo, which P-256's fixed head and the point
/// make apart from the certificate's parser, and its SHA-256; neither the
/// private key nor the token is shown.
#[test]
fn a_warp_record_shows_its_certificate_s_public_key() {
    use base64::Engine as _;
    use p256::elliptic_curve::Generate;
    let signing = p256::ecdsa::SigningKey::generate();
    let point = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let key = DeviceKey { signing, point };
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1, 2, 3, 4]));
    let cert = params.self_signed(&key).unwrap();
    let private_body = base64::engine::general_purpose::STANDARD.encode(key.signing.to_bytes().as_slice());
    let record = serde_json::json!({
        "key_pem": pem_of("PRIVATE KEY", key.signing.to_bytes().as_slice()),
        "cert_pem": pem_of("CERTIFICATE", cert.der()),
        "device": { "id": "a-device-of-the-test", "token": "PLANTED-TOKEN-OF-THE-TEST" },
    });
    let dir = scratch("warp-real");
    private(&dir.join(crate::ssh::cloud::warp::DEVICE_FILE), &record.to_string());
    let rows = super::rows(&dirs(&dir, None), None);
    let _ = std::fs::remove_dir_all(&dir);
    let w = role(&rows, "warp");
    assert_eq!(w[0]["state"], "present", "{rows:?}");
    let mut spki = hex_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    spki.extend_from_slice(&key.point);
    let engine = &base64::engine::general_purpose::STANDARD;
    assert_eq!(w[0]["public"].as_str(), Some(engine.encode(&spki).as_str()), "{rows:?}");
    let digest = sha2::Sha256::digest(&spki);
    let fingerprint = format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest));
    assert_eq!(w[0]["fingerprint"].as_str(), Some(fingerprint.as_str()));
    let text = Value::Array(rows).to_string();
    assert!(!text.contains(&private_body) && !text.contains("PLANTED-TOKEN"), "{text}");
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}
