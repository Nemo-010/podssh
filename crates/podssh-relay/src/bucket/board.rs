//! A bucket as the board of the file-host carrier ([`Board`]), one way at
//! each end: a note goes to `WRITE/TOPIC` with this end's write key, and a
//! note is taken from `READ/TOPIC` with its read key, or unsigned for a
//! prefix that anyone may read. Each topic is a MAC of the pair's key
//! ([`crate::filehost::keys`]), so the object names say nothing, and the
//! reader needs no LIST: it knows each name it waits for.
//!
//! A note holds its write whole ([`Board::holds_pieces`]): an object takes
//! a piece of 4 MiB, so no file host and no second request is needed.
//!
//! A reader that may not delete (a read right alone) leaves each object to
//! the bucket's own life; so a client's hello at the door is taken only
//! while it is fresh by the server's own clock ([`DOOR_FRESH`]): an old
//! run's hello, which nobody deleted, opens no link.

use std::sync::Arc;
use std::time::Duration;

use pod_link::s3::sign::Credentials;

use super::s3::{http_date, refused, Answer, Bucket};
use crate::filehost::board::{Board, Posting};
use crate::filehost::PIECE_MOST;

/// How old, by the server's `Date` against its `Last-Modified`, a hello
/// may be: a node polls its door 10 s apart at most, so a hello this old
/// is of a client that gave up.
pub const DOOR_FRESH: Duration = Duration::from_secs(10 * 60);
/// The longest pause between two reads of a way: the relay role gives a
/// node 15 s to answer an open, which crosses the bucket twice, and a GET
/// is the cheapest request at most providers.
pub const POLL_MOST: Duration = Duration::from_secs(3);
/// The longest pause between two reads of a node's door: the relay role at
/// the client pings the node from the start and gives it 60 s, so a
/// client's hello is found within 10 s.
pub const DOOR_POLL_MOST: Duration = Duration::from_secs(10);
/// The most bytes of one note: a whole piece and its seal.
pub const NOTE_MOST: usize = PIECE_MOST + crate::filehost::keys::OVERHEAD;

/// One end's two ways in one bucket.
pub struct BucketBoard {
    bucket: Arc<Bucket>,
    write: String,
    read: String,
    write_key: Credentials,
    read_key: Option<Credentials>,
    door: String,
    name: String,
}

impl BucketBoard {
    /// The board of an end that writes under `write` with `write_key` and
    /// reads under `read` with `read_key` (none: unsigned); `door` is the
    /// pair's door topic, whose hellos must be fresh.
    pub fn new(
        bucket: Arc<Bucket>,
        write: &str,
        read: &str,
        write_key: Credentials,
        read_key: Option<Credentials>,
        door: String,
    ) -> BucketBoard {
        let name = format!("the bucket {}", bucket.shown());
        let (write, read) = (write.trim_end_matches('/').to_string(), read.trim_end_matches('/').to_string());
        BucketBoard { bucket, write, read, write_key, read_key, door, name }
    }

    fn key(prefix: &str, topic: &str) -> String {
        if prefix.is_empty() {
            topic.to_string()
        } else {
            format!("{prefix}/{topic}")
        }
    }
}

/// Whether a hello that `answer` gave is fresh: no `Date` or no
/// `Last-Modified` says nothing, so it is taken, as a stand-in's may lack
/// them.
pub fn fresh(answer: &Answer) -> bool {
    let (Some(now), Some(made)) = (answer.date.as_deref(), answer.modified.as_deref()) else { return true };
    match (http_date(now), http_date(made)) {
        (Some(now), Some(made)) => now.saturating_sub(made) <= DOOR_FRESH.as_secs() as i64,
        _ => true,
    }
}

impl Board for BucketBoard {
    fn name(&self) -> &str {
        &self.name
    }

    fn most(&self) -> usize {
        NOTE_MOST
    }

    fn holds_pieces(&self) -> bool {
        true
    }

    fn poll_most(&self) -> Option<Duration> {
        Some(POLL_MOST)
    }

    fn door_poll_most(&self) -> Option<Duration> {
        Some(DOOR_POLL_MOST)
    }

    fn put<'a>(&'a self, topic: &'a str, payload: Vec<u8>) -> Posting<'a, ()> {
        Box::pin(async move {
            let key = Self::key(&self.write, topic);
            let answer = self.bucket.request("PUT", &key, Some(&self.write_key), &payload, 0).await?;
            match answer.status {
                200..=299 => Ok(()),
                _ => Err(refused("a PUT", &answer)),
            }
        })
    }

    fn take<'a>(&'a self, topic: &'a str) -> Posting<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let key = Self::key(&self.read, topic);
            let answer = self.bucket.request("GET", &key, self.read_key.as_ref(), &[], NOTE_MOST).await?;
            match answer.status {
                200 if topic == self.door && !fresh(&answer) => Ok(None),
                200 => Ok(Some(answer.body)),
                // A reader with no LIST right gets 403 for a missing object
                // from AWS; both say that nothing waits.
                404 | 403 if answer_is_missing(&answer) => Ok(None),
                _ => Err(refused("a GET", &answer)),
            }
        })
    }

    fn clear<'a>(&'a self, topic: &'a str) -> Posting<'a, ()> {
        Box::pin(async move {
            // A reader with no delete right leaves the object to the
            // bucket's life: the carrier ignores this answer.
            let key = Self::key(&self.read, topic);
            let answer = self.bucket.request("DELETE", &key, self.read_key.as_ref(), &[], 0).await?;
            match answer.status {
                200..=299 | 404 => Ok(()),
                _ => Err(refused("a DELETE", &answer)),
            }
        })
    }
}

/// A 404, or the 403 `AccessDenied` that AWS gives for a missing object to
/// a key that may not list the bucket: both are an object not there yet. A
/// 403 of another code (a wrong signature, `SignatureDoesNotMatch`) is not.
fn answer_is_missing(answer: &Answer) -> bool {
    if answer.status == 404 {
        return true;
    }
    let text = String::from_utf8_lossy(&answer.body);
    text.contains("<Code>AccessDenied</Code>")
}
