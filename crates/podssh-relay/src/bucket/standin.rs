//! A stand-in of the S3 API on the loopback for the road's tests, with the
//! one thing that pod-link's stand-in lacks: rights for each key on each
//! prefix, as an IAM policy grants them. Path style, plain HTTP/1.1 with
//! keep-alive, one bucket in memory; a PUT, a GET (with `Date` and
//! `Last-Modified`) and a DELETE of one object. Each request's Signature
//! Version 4 is computed again by pod-link's signer over what came, with
//! the made-up keys of [`client_key`] and [`node_key`], and its payload's
//! hash with SHA-256; a wrong one is a 403 `SignatureDoesNotMatch`, and a
//! request without a right is a 403 `AccessDenied`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pod_link::s3::sign::{self, Credentials, Signing};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const BUCKET: &str = "links";

/// The made-up keys: no service knows them.
pub fn client_key() -> Credentials {
    Credentials::new("PODSSHCLIENTTEST", "podssh-client-test-secret-not-real")
}
pub fn node_key() -> Credentials {
    Credentials::new("PODSSHNODETEST", "podssh-node-test-secret-not-real")
}

/// What a key may do under a prefix.
#[derive(Clone, Copy, Debug, Default)]
pub struct Right {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Default)]
pub struct State {
    /// Each object's body and the time it was made, in seconds.
    pub objects: Mutex<BTreeMap<String, (Vec<u8>, i64)>>,
    /// Each key's id, its key, and its rights by prefix.
    keys: Vec<(Credentials, Vec<(String, Right)>)>,
    /// Prefixes that anyone may read.
    public: Vec<String>,
    /// Requests with no right signature (403 of SigV4).
    pub refused: AtomicUsize,
    /// Signed requests that the key had no right for (403 `AccessDenied`).
    pub denied: AtomicUsize,
    pub requests: AtomicUsize,
}

/// A stand-in on its loopback port.
pub struct StandIn {
    pub port: u16,
    pub state: Arc<State>,
}

impl StandIn {
    /// The bucket, where each key holds `rights`, and `public` prefixes.
    pub async fn start(rights: Vec<(Credentials, Vec<(String, Right)>)>, public: &[&str]) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let public = public.iter().map(|p| p.to_string()).collect();
        let state = Arc::new(State { keys: rights, public, ..State::default() });
        let serving = state.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(serve(tcp, serving.clone()));
            }
        });
        StandIn { port, state }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The keys of the objects under `prefix`.
    pub fn keys(&self, prefix: &str) -> Vec<String> {
        let objects = self.state.objects.lock().unwrap();
        objects.keys().filter(|k| k.starts_with(prefix)).cloned().collect()
    }

    /// Make `key` older by `secs`, as a hello of a run long gone.
    pub fn age(&self, key: &str, secs: i64) {
        if let Some((_, made)) = self.state.objects.lock().unwrap().get_mut(key) {
            *made -= secs;
        }
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// IMF-fixdate of `secs` since 1970.
pub fn imf(secs: i64) -> String {
    let amz = sign::amz_date(secs.max(0) as u64);
    let (y, m, d) = (&amz[..4], amz[4..6].parse::<usize>().unwrap_or(1), &amz[6..8]);
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = DAYS[(secs.div_euclid(86_400)).rem_euclid(7) as usize];
    format!("{weekday}, {d} {} {y} {}:{}:{} GMT", MONTHS[m - 1], &amz[9..11], &amz[11..13], &amz[13..15])
}

/// A request as it came: its method, its path decoded, its fields in
/// lower case, its body.
struct Request {
    method: String,
    path: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

async fn read_request(tcp: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Request> {
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let mut chunk = [0u8; 8192];
        let n = tcp.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.drain(..end + 4);
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let fields: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length = fields.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    while buf.len() < length {
        let mut chunk = vec![0u8; 64 * 1024];
        let n = tcp.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf.drain(..length).collect();
    let path = decode(target.split('?').next().unwrap_or_default());
    Some(Request { method, path, fields, body })
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(Ok(b)) = text.get(i + 1..i + 3).map(|hex| u8::from_str_radix(hex, 16))
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The key that signed `request` rightly, or the error's code.
type Holder = (Credentials, Vec<(String, Right)>);

fn signer<'a>(state: &'a State, request: &Request) -> Result<Option<&'a Holder>, &'static str> {
    let Some(auth) = request.field("authorization") else { return Ok(None) };
    let id = auth.split("Credential=").nth(1).and_then(|r| r.split('/').next()).unwrap_or_default();
    let signed = auth.split("SignedHeaders=").nth(1).and_then(|r| r.split(',').next()).unwrap_or_default();
    let Some(holder) = state.keys.iter().find(|(c, _)| c.access_key == id) else { return Err("InvalidAccessKeyId") };
    let hash = request.field("x-amz-content-sha256").unwrap_or_default();
    if hash != sign::sha256_hex(&request.body) {
        return Err("XAmzContentSHA256Mismatch");
    }
    let date = request.field("x-amz-date").unwrap_or_default();
    let region = auth.split('/').nth(2).unwrap_or_default();
    let fields: Vec<(&str, &str)> =
        signed.split(';').filter_map(|name| request.field(name).map(|value| (name, value))).collect();
    let (method, path) = (request.method.as_str(), request.path.as_str());
    let signing = Signing { method, path, query: &[], headers: &fields, payload_hash: hash, date, region };
    if sign::authorization(&holder.0, &signing) != auth {
        return Err("SignatureDoesNotMatch");
    }
    Ok(Some(holder))
}

async fn answer(tcp: &mut TcpStream, status: u16, fields: &[(&str, String)], body: &[u8]) -> bool {
    let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nDate: {}\r\n", body.len(), imf(now()));
    for (name, value) in fields {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    tcp.write_all(&out).await.is_ok()
}

fn error(code: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code></Error>").into_bytes()
}

async fn serve(mut tcp: TcpStream, state: Arc<State>) {
    let mut buf = Vec::new();
    while let Some(request) = read_request(&mut tcp, &mut buf).await {
        state.requests.fetch_add(1, Ordering::SeqCst);
        let Some(key) = request.path.strip_prefix(&format!("/{BUCKET}/")).map(str::to_string) else {
            let _ = answer(&mut tcp, 404, &[], &error("NoSuchBucket")).await;
            continue;
        };
        let holder = match signer(&state, &request) {
            Ok(holder) => holder,
            Err(code) => {
                state.refused.fetch_add(1, Ordering::SeqCst);
                if !answer(&mut tcp, 403, &[], &error(code)).await {
                    return;
                }
                continue;
            }
        };
        let right = |pick: fn(&Right) -> bool| match holder {
            Some((_, rights)) => rights.iter().any(|(p, r)| key.starts_with(p.as_str()) && pick(r)),
            // Unsigned: a read of a public prefix, nothing else.
            None => {
                let read = pick(&Right { read: true, ..Right::default() });
                read && state.public.iter().any(|p| key.starts_with(p.as_str()))
            }
        };
        let (status, fields, body) = match request.method.as_str() {
            "PUT" if right(|r| r.write) => {
                state.objects.lock().unwrap().insert(key.clone(), (request.body, now()));
                (200, Vec::new(), Vec::new())
            }
            "GET" if right(|r| r.read) => match state.objects.lock().unwrap().get(&key) {
                Some((body, made)) => (200, vec![("Last-Modified", imf(*made))], body.clone()),
                None => (404, Vec::new(), error("NoSuchKey")),
            },
            "DELETE" if right(|r| r.delete) => {
                state.objects.lock().unwrap().remove(&key);
                (204, Vec::new(), Vec::new())
            }
            _ => {
                state.denied.fetch_add(1, Ordering::SeqCst);
                (403, Vec::new(), error("AccessDenied"))
            }
        };
        if !answer(&mut tcp, status, &fields, &body).await {
            return;
        }
    }
}
