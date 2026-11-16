//! The notes of Tox's relay road (T-734), a last fallback of the operator's
//! ruling Q78 after ZeroTier's: a node of a pair that waits on one of the
//! Tox project's public TCP relays under a key of the pair's own, and a
//! client that reaches it there. Only a build with the feature `tox` has it.

/// The note of `podssh node`, after ZeroTier's road's.
pub(super) const NODE: &str = "In a build with the feature tox, a node of the pair's road also waits on a TCP \
     relay of the Tox project's public nodes. There it waits for the pair's operators, the last fallback after \
     ZeroTier's. It does so only with a TCP TARGET, the resumable layer and the end-to-end channel (no --plain, \
     no --no-e2e). The relay is the one that the SHA-256 of the pair's name picks among those that podssh's list \
     of services names. There is none while the list names none. Or it is the relay of PODSSH_TOX (IP:PORT=KEY, \
     c-toxcore's tox-bootstrapd of your own with its TCP relay). The node reaches it by one TCP connection \
     through HTTPS_PROXY. The node's key on the relay comes from the pair's name and connect token. Its \
     operators thus know it with no word between the two ends; each session has a connection with a fresh key of \
     its own, offered to the client out of band. This way one session's pace never holds another's. The node \
     serves each with the resumable layer under the keeper of its other roads. It dials the relay again, after 1 \
     s, doubled to 32 s, when it goes. Its line names the relay. For a public one, it says that the relay \
     carries the sessions of this road. That relay sees the two ends' keys, the times and the sizes; the \
     channel keeps the bytes from it. PODSSH_TOX=no turns the road off, and PODSSH_LAST_RESORT=no turns \
     off the public relays.";

/// The note of `podssh ssh`, after ZeroTier's road's.
pub(super) const SSH: &str = "In a build with the feature tox, node://NAME also races Tox's relay road of its pair, \
     only once each road before it failed. It comes after ZeroTier's road and before the Serveo road, the last \
     fallback: a connection with a fresh key to the relay of the pair. That relay is the one that the SHA-256 of its \
     name picks among the Tox project's public relays of podssh's list of services. Or it is the relay of PODSSH_TOX. \
     Then a hello goes to the node's key, which both ends make of the pair's connect token, again each 2 s. Last comes \
     a routed connection to the key that the node offers. It \
     waits 30 s at most for the node's answer. The relay passes no more than a short queue, so the stream \
     keeps its own order, window (32 KiB) and resends inside the relay's packets. Before its first link \
     through a public relay, a line says that the Tox project's relay carries the session. PODSSH_TOX=no or \
     PODSSH_LAST_RESORT=no (for the public relays) turns it off, and --no-e2e leaves it out. podssh ping \
     node://NAME does not measure it.";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The notes follow ZeroTier's road's, in node's and ssh's, and hold
    /// each claim of Q78's third party.
    #[test]
    fn the_notes_of_tox_s_road_follow_zerotier_s() {
        let node = for_verb("node");
        let at = node.iter().position(|n| *n == super::NODE).expect("node's note of Tox's road");
        assert_eq!(node[at - 1], super::super::notes_zerotier::NODE);
        let ssh = for_verb("ssh");
        let at = ssh.iter().position(|n| *n == super::SSH).expect("ssh's note of Tox's road");
        assert_eq!(ssh[at - 1], super::super::notes_zerotier::SSH);
        for text in ["PODSSH_LAST_RESORT=no", "PODSSH_TOX=no", "PODSSH_TOX", "feature tox", "SHA-256"] {
            assert!(super::NODE.contains(text) && super::SSH.contains(text), "{text}");
        }
        assert!(super::SSH.contains("--no-e2e") && super::NODE.contains("tox-bootstrapd"));
    }
}
