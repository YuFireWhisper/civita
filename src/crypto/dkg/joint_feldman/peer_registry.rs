use std::collections::{hash_map, HashMap};

use crate::crypto::keypair::PublicKey;

#[cfg_attr(test, allow(dead_code))]
const MAX_PEERS: usize = if cfg!(test) { 10 } else { u16::MAX as usize };

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
struct PeerInfo {
    pub index: u16,
    pub public_key: PublicKey,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct PeerRegistry {
    peer_to_info: HashMap<libp2p::PeerId, PeerInfo>,
    index_to_peer: HashMap<u16, libp2p::PeerId>,
}

pub struct IndexPeerIterator<'a> {
    iter: hash_map::Iter<'a, u16, libp2p::PeerId>,
}

pub struct IndexKeyIterator<'a> {
    iter: hash_map::Iter<'a, u16, libp2p::PeerId>,
    registry: &'a PeerRegistry,
}

pub struct PeerKeyIterator<'a> {
    iter: hash_map::Iter<'a, libp2p::PeerId, PeerInfo>,
}

impl PeerRegistry {
    pub fn new(peers: HashMap<libp2p::PeerId, PublicKey>) -> Self {
        assert!(
            peers.len() <= MAX_PEERS,
            "ids length is exceeding the maximum"
        );

        let mut entries: Vec<_> = peers.into_iter().collect();
        entries.sort_by_key(|(peer_id, _)| *peer_id);

        let mut peer_to_info = HashMap::new();
        let mut index_to_peer = HashMap::new();

        for (i, (peer_id, keypair)) in entries.into_iter().enumerate() {
            let index = (i + 1).try_into().expect("unreachable: index is too large");

            let info = PeerInfo {
                index,
                public_key: keypair,
            };

            peer_to_info.insert(peer_id, info);
            index_to_peer.insert(index, peer_id);
        }

        Self {
            peer_to_info,
            index_to_peer,
        }
    }

    pub fn get_index(&self, peer_id: &libp2p::PeerId) -> Option<u16> {
        self.peer_to_info.get(peer_id).map(|info| info.index)
    }

    pub fn get_public_key_by_index(&self, index: u16) -> Option<&PublicKey> {
        assert!(index > 0, "index must be greater than 0, but got {}", index);
        self.index_to_peer
            .get(&index)
            .and_then(|peer_id| self.peer_to_info.get(peer_id).map(|info| &info.public_key))
    }

    pub fn get_public_key_by_peer_id(&self, peer_id: &libp2p::PeerId) -> Option<&PublicKey> {
        self.peer_to_info.get(peer_id).map(|info| &info.public_key)
    }

    pub fn get_peer_id_by_index(&self, index: u16) -> Option<&libp2p::PeerId> {
        assert!(index > 0, "index must be greater than 0, but got {}", index);
        self.index_to_peer.get(&index)
    }

    pub fn contains(&self, peer_id: &libp2p::PeerId) -> bool {
        self.peer_to_info.contains_key(peer_id)
    }

    pub fn iter_index_peer(&self) -> IndexPeerIterator<'_> {
        self.into_iter()
    }

    pub fn iter_index_keys(&self) -> IndexKeyIterator<'_> {
        IndexKeyIterator {
            iter: self.index_to_peer.iter(),
            registry: self,
        }
    }

    pub fn iter_peer_keys(&self) -> PeerKeyIterator<'_> {
        PeerKeyIterator {
            iter: self.peer_to_info.iter(),
        }
    }

    pub fn peer_ids(&self) -> impl Iterator<Item = &libp2p::PeerId> {
        self.index_to_peer.values()
    }

    pub fn indices(&self) -> impl Iterator<Item = &u16> {
        self.index_to_peer.keys()
    }

    pub fn len(&self) -> u16 {
        self.index_to_peer
            .len()
            .try_into()
            .expect("unreachable: length is too large")
    }

    pub fn is_empty(&self) -> bool {
        self.index_to_peer.is_empty()
    }
}

impl<'a> IntoIterator for &'a PeerRegistry {
    type Item = (libp2p::PeerId, u16);
    type IntoIter = IndexPeerIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        IndexPeerIterator {
            iter: self.index_to_peer.iter(),
        }
    }
}

impl<'a> Iterator for IndexPeerIterator<'a> {
    type Item = (libp2p::PeerId, u16);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((index, peer_id)) = self.iter.next() {
            Some((*peer_id, *index))
        } else {
            None
        }
    }
}

impl<'a> Iterator for IndexKeyIterator<'a> {
    type Item = (u16, &'a PublicKey);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((index, peer_id)) = self.iter.next() {
            if let Some(info) = self.registry.peer_to_info.get(peer_id) {
                return Some((*index, &info.public_key));
            }
        }
        None
    }
}

impl<'a> Iterator for PeerKeyIterator<'a> {
    type Item = (libp2p::PeerId, &'a PublicKey);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((peer_id, info)) = self.iter.next() {
            return Some((*peer_id, &info.public_key));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::crypto::{
        dkg::joint_feldman::peer_registry::{PeerRegistry, MAX_PEERS},
        keypair::{self, PublicKey},
    };

    const NUM_PEERS: usize = 3;

    fn generate_peers(nums: usize) -> HashMap<libp2p::PeerId, PublicKey> {
        let mut peers_map = HashMap::new();

        for _ in 0..nums {
            let peer_id = libp2p::PeerId::random();
            let public_key = keypair::generate_secp256k1().1;
            peers_map.insert(peer_id, public_key);
        }

        peers_map
    }

    #[test]
    fn successful_valid_input() {
        let peers = generate_peers(NUM_PEERS);

        let result = PeerRegistry::new(peers);

        assert_eq!(result.len(), NUM_PEERS as u16);
    }

    #[test]
    #[should_panic(expected = "ids length is exceeding the maximum")]
    fn panic_exceeding_maximum() {
        let peers = generate_peers(MAX_PEERS + 1);
        let _ = PeerRegistry::new(peers);
    }

    #[test]
    fn return_correct_index() {
        let peers = generate_peers(NUM_PEERS);
        let peer = *peers.keys().next().unwrap();
        let registry = PeerRegistry::new(peers);

        let index = registry.get_index(&peer);

        assert!(index.is_some());
        assert!(index.unwrap() >= 1 && index.unwrap() <= NUM_PEERS as u16);
    }

    #[test]
    fn return_none_for_invalid_peer() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let invalid_peer_id = libp2p::PeerId::random();
        let index = registry.get_index(&invalid_peer_id);

        assert!(index.is_none());
    }

    #[test]
    fn return_correct_public_key_by_index() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        for i in 1..=NUM_PEERS as u16 {
            let public_key = registry.get_public_key_by_index(i);
            assert!(public_key.is_some());
        }
    }

    #[test]
    #[should_panic(expected = "index must be greater than 0, but got 0")]
    fn panic_for_get_public_key_by_zero_index() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let _ = registry.get_public_key_by_index(0);
    }

    #[test]
    fn return_none_for_invalid_index() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let invalid_index = NUM_PEERS as u16 + 1;
        let public_key = registry.get_public_key_by_index(invalid_index);

        assert!(public_key.is_none());
    }

    #[test]
    fn return_correct_public_key_by_peer_id() {
        let peers = generate_peers(NUM_PEERS);
        let peer = *peers.keys().next().unwrap();
        let expected_public_key = peers.get(&peer).unwrap().clone();
        let registry = PeerRegistry::new(peers);

        let public_key = registry.get_public_key_by_peer_id(&peer);

        assert!(public_key.is_some());
        assert_eq!(public_key.unwrap(), &expected_public_key);
    }

    #[test]
    fn return_correct_peer_id_by_index() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        for i in 1..=NUM_PEERS as u16 {
            let peer_id = registry.get_peer_id_by_index(i);
            assert!(peer_id.is_some());
        }
    }

    #[test]
    #[should_panic(expected = "index must be greater than 0, but got 0")]
    fn panic_for_get_peer_id_by_zero_index() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let _ = registry.get_peer_id_by_index(0);
    }

    #[test]
    fn return_none_for_invalid_peer_id() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let invalid_peer_id = libp2p::PeerId::random();
        let public_key = registry.get_public_key_by_peer_id(&invalid_peer_id);

        assert!(public_key.is_none());
    }

    #[test]
    fn true_if_peer_id_exists() {
        let peers = generate_peers(NUM_PEERS);
        let peer = *peers.keys().next().unwrap();
        let registry = PeerRegistry::new(peers);

        assert!(registry.contains(&peer));
    }

    #[test]
    fn false_if_peer_id_does_not_exist() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let invalid_peer_id = libp2p::PeerId::random();
        assert!(!registry.contains(&invalid_peer_id));
    }

    #[test]
    fn iter_index_peer_should_iterate_all() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for (peer_id, index) in registry.iter_index_peer() {
            assert!(registry.contains(&peer_id));
            assert_eq!(registry.get_index(&peer_id), Some(index));
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn iter_index_keys_should_iterate_all() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for (index, public_key) in registry.iter_index_keys() {
            assert!(registry.get_public_key_by_index(index).is_some());
            assert_eq!(registry.get_public_key_by_index(index), Some(public_key));
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn iter_peer_keys_should_iterate_all() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for (peer_id, index) in registry.iter_peer_keys() {
            assert!(registry.contains(&peer_id));
            assert_eq!(registry.get_public_key_by_peer_id(&peer_id), Some(index));
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn peer_ids_should_return_all_peer_ids() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for peer_id in registry.peer_ids() {
            assert!(registry.contains(peer_id));
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn indices_should_return_all_indices() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for index in registry.indices() {
            assert!(registry.get_public_key_by_index(*index).is_some());
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn len_should_return_correct_number_of_peers() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        assert_eq!(registry.len(), NUM_PEERS as u16);
    }

    #[test]
    fn returns_true_if_empty() {
        let peers = generate_peers(0);
        let registry = PeerRegistry::new(peers);

        assert!(registry.is_empty());
    }

    #[test]
    fn returns_false_if_not_empty() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        assert!(!registry.is_empty());
    }

    #[test]
    fn iter_index_peer_should_return_correct_items() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let mut count = 0;
        for (peer_id, index) in registry.iter_index_peer() {
            assert!(registry.contains(&peer_id));
            assert_eq!(registry.get_index(&peer_id), Some(index));
            count += 1;
        }

        assert_eq!(count, NUM_PEERS);
    }

    #[test]
    fn index_should_sort_by_peer_id() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers.clone());

        let mut sorted_peers: Vec<_> = peers.keys().cloned().collect();
        sorted_peers.sort();

        for (i, peer_id) in sorted_peers.iter().enumerate() {
            assert_eq!(registry.get_index(peer_id), Some((i + 1) as u16));
        }
    }

    #[test]
    fn index_should_start_from_1() {
        let peers = generate_peers(NUM_PEERS);
        let registry = PeerRegistry::new(peers);

        let min_index = registry
            .indices()
            .min()
            .expect("Expected at least one index");
        assert_eq!(*min_index, 1, "Index should start from 1");
    }
}
