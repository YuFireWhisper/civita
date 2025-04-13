use std::collections::HashMap;

use crate::crypto::keypair::PublicKey;

#[derive(Debug)]
pub struct PeerInfo {
    pub index: u16,
    pub public_key: PublicKey,
}

impl PeerInfo {
    pub fn from_map(peers: HashMap<libp2p::PeerId, PublicKey>) -> HashMap<libp2p::PeerId, Self> {
        assert!(
            peers.len() <= u16::MAX as usize,
            "ids length is exceeding the maximum"
        );

        let mut entries: Vec<_> = peers.into_iter().collect();
        entries.sort_by_key(|(peer_id, _)| *peer_id);

        entries
            .into_iter()
            .enumerate()
            .map(|(i, (peer_id, keypair))| {
                (
                    peer_id,
                    PeerInfo {
                        index: (i + 1) as u16,
                        public_key: keypair,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libp2p::PeerId;

    use crate::crypto::{self, dkg::joint_feldman::peer_info::PeerInfo, keypair::PublicKey};

    #[test]
    fn valid_input() {
        let mut peers = HashMap::new();
        for _ in 0..10 {
            let (_, pk) = crypto::keypair::generate_secp256k1();
            let peer_id = PeerId::random();
            peers.insert(peer_id, pk);
        }

        let peer_info = PeerInfo::from_map(peers);
        assert_eq!(peer_info.len(), 10);
    }

    #[test]
    fn empty_input() {
        let empty_peers: HashMap<libp2p::PeerId, PublicKey> = HashMap::new();
        let result = PeerInfo::from_map(empty_peers);
        assert_eq!(result.len(), 0);
    }

    #[test]
    #[should_panic]
    fn panic_exceeding_length() {
        let mut peers = HashMap::new();
        for _ in 0..u16::MAX as usize + 1 {
            let (_, pk) = crypto::keypair::generate_secp256k1();
            let peer_id = PeerId::random();
            peers.insert(peer_id, pk);
        }

        let _ = PeerInfo::from_map(peers);
    }
}
