//! The notes of the onion road (T-578), the last fallback of the operator's
//! ruling Q78 after Syncthing's relay road: a node of a pair that waits as
//! an onion service of the Tor network, of restricted discovery for a key of
//! the pair's own, and a client that reaches it by its address. Only a build
//! with the feature `tor` has it.

/// The note of `podssh node`, after Syncthing's relay road's.
pub(super) const NODE: &str = "In a build with the feature tor, a node of the pair's road waits as an onion \
     service of the Tor network too. There it waits for the pair's operators, the last fallback after \
     Syncthing's relay road. It does so only with a TCP TARGET, the resumable layer and the end-to-end channel \
     (no --plain, no --no-e2e). Arti bootstraps in podssh's process through the Tor road (HTTPS_PROXY, \
     PODSSH_TOR_PORTS, PODSSH_TOR_BRIDGES and PODSSH_TOR_NETWORK hold). It keeps a directory of the cache of the \
     node's own, where Arti keeps the service's key. The service's address thus stays from one start to the \
     next. Every circuit of the service is a connection out to a Tor relay: the node listens on nothing. Its \
     descriptor is of restricted discovery, readable only with a key that both ends make of the pair's name and \
     connect token. Each stream to its virtual port is served with the resumable layer under the keeper of its \
     other roads. Its line says its address, which a node of this host keeps under NAME. A node of DERP puts the \
     address in its record of pkarr (onion=), where it keeps one. The line says too that the Tor network's \
     volunteer relays carry the sessions of this road; the channel keeps the bytes from them. \
     PODSSH_ONION=no or PODSSH_LAST_RESORT=no turns the road off.";

/// The note of `podssh ssh`, after Syncthing's relay road's.
pub(super) const SSH: &str =
    "In a build with the feature tor, node://NAME also races the onion road of its pair, only \
     once each road before it failed. It comes after Syncthing's relay road and before the Serveo road, the last \
     fallback: this end bootstraps Arti through the Tor road, once a run, and puts the pair's key of restricted \
     discovery in its keystore. It then opens a stream to the node's onion service. The address is that of \
     PODSSH_ONION (the node's line says it). Else it is the one of the node's record of pkarr where the net names the \
     node's key, read again at each link. Else it is the one kept under NAME by a node of this host or by a run that \
     was given it. It waits 120 s at most. Before its first circuit, a \
     line says that the Tor network carries the session. PODSSH_ONION=no or PODSSH_LAST_RESORT=no turns it \
     off, and --no-e2e leaves it out. podssh ping node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow Syncthing's relay road's, in node's and ssh's, and
    /// hold each claim of Q78's third party.
    #[test]
    fn the_notes_of_the_onion_road_follow_syncthing_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of the onion road");
        assert_eq!(node[at - 1], super::super::notes_strelay::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of the onion road");
        assert_eq!(ssh[at - 1], super::super::notes_strelay::SSH);
        for text in ["PODSSH_LAST_RESORT=no", "PODSSH_ONION=no", "feature tor", "Tor network", "restricted discovery"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("listens on nothing"));
    }
}
