//! The note of a node's net at a URL (T-715), apart from the others so that
//! each file stays short.

/// The node's side: `--net-url`, `--net-owner`, `--net-ttl`, `--net-stale`.
pub(super) const NODE: &str = "With --net-url URL --net-owner KEY, the node takes its net from the signed document at \
     URL. A change of the net then needs no copy of a file to each node. URL is https:// alone; an http:// URL, \
     or one with a user or a password, is refused (64). TLS alone is not the trust. Each document must be signed by \
     the owner of --net-owner, its fingerprint SHA256:... or its public key. One of another owner, with a bad \
     signature, or with a serial not higher than the one held is refused; the copy held stays. A document that is \
     taken goes where podssh net take puts one, and each door of the node reads it at the next session. The node \
     fetches it once before it goes online. A fetch that fails stops the start (78) when no copy from the URL is \
     held; else the copy of before is read. Then it fetches it again each --net-ttl seconds (300, at least 60), one \
     fetch at a time. Each fetch is one GET through the proxy, with the trust of --ca-file, 64 KiB at most, with no \
     redirect. A fetch that fails is a line, and the copy ages. Past --net-ttl and --net-stale (3600 s) the net lets \
     nobody in, and a line says so. Sessions that live go on, and the keys of --allow still come in. A fetch that \
     works opens the door again. The record of the last fetch, net-url.json in the cache, names the URL by its host \
     alone. podssh status --net shows it. NetUrl and NetOwner of the settings file stand in for the flags. \
     --install writes them into the service, and --temporary refuses them (64).";
