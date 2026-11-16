//! The notes of Yggdrasil's road (T-735), a last fallback of the operator's
//! ruling Q78 after the Tox road's: a node of a pair that joins Yggdrasil's
//! network through one public `wss://` peer under a key of the pair's own,
//! and a client that reaches it there by that key. Only a build with the
//! feature `yggdrasil` has it.

/// The note of `podssh node`, after the Tox road's.
pub(super) const NODE: &str = "In a build with the feature yggdrasil, a node of the pair's road also waits for \
     the pair's operators in Yggdrasil's network. It does so only with a TCP TARGET, the resumable layer and the \
     end-to-end channel (no --plain, no --no-e2e). This is the last fallback after the Tox road. It takes one \
     WebSocket (ygg-ws) through HTTPS_PROXY to a public wss:// peer. The peer is the one that the SHA-256 of the \
     pair's name picks among those that podssh's list of services names. There is none while the list names \
     none. Or the peer is the one of PODSSH_YGGDRASIL (a wss:// or ws:// URL, yggdrasil-go of your own with that \
     Listen). Its handshake is signed, and Ironwood, Yggdrasil's router, runs over it. The node's key in the \
     network comes from the pair's name and connect token. Its operators thus know it with no word between the \
     two ends; a client's hello proves the token. Each session is a stream of its own, served with the resumable \
     layer under the keeper of its other roads. While the road is up the node is a router of the network too, as \
     each node of Yggdrasil is. It dials its peer again, after 1 s, doubled to 32 s, when the link goes. Its \
     line names the peer. For a public one, it says that the peer carries the sessions of this road. It says too \
     that the peers on the path see the two ends' keys, the times and the sizes; the channel keeps the bytes \
     from them. PODSSH_YGGDRASIL=no turns the road off, and PODSSH_LAST_RESORT=no turns off the public peers.";

/// The note of `podssh ssh`, after the Tox road's.
pub(super) const SSH: &str = "In a build with the feature yggdrasil, node://NAME also races Yggdrasil's road of its \
     pair, only once each road before it failed. It comes after the Tox road and before the Serveo road, the last \
     fallback: this end joins Yggdrasil's network with a fresh key through the pair's peer, once a run. That peer is \
     the one that the SHA-256 of its name picks among the public wss:// peers of podssh's list of services. Or it is \
     the peer of PODSSH_YGGDRASIL. This end then says hello to the node's key, which both ends make of the pair's \
     connect token. The hello holds a proof of the token, and goes again each 1 s, until the node welcomes it. It \
     waits 45 s at most: the first lookup across the network takes some seconds. The \
     network drops what it cannot place, so each link keeps its own order, window (256 KiB) and resends \
     inside the packets. Before its first link through a public peer, a line says that the peer carries the session. \
     It says too that this end routes for the network while the road is up. PODSSH_YGGDRASIL=no or \
     PODSSH_LAST_RESORT=no (for the public peers) turns it off, and --no-e2e leaves it out. podssh ping \
     node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow the Tox road's, in node's and ssh's, and hold each
    /// claim of Q78's third party.
    #[test]
    fn the_notes_of_yggdrasil_s_road_follow_the_tox_road_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of Yggdrasil's road");
        assert_eq!(node[at - 1], super::super::notes_tox::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of Yggdrasil's road");
        assert_eq!(ssh[at - 1], super::super::notes_tox::SSH);
        for text in ["PODSSH_LAST_RESORT=no", "PODSSH_YGGDRASIL=no", "feature yggdrasil", "SHA-256", "wss://"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("router of the network"));
    }
}
