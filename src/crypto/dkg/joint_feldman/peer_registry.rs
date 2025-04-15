use std::collections::{hash_map, HashMap};

use crate::crypto::keypair::PublicKey;

#[derive(Clone)]
#[derive(Debug)]
struct PeerInfo {
    pub index: u16,
    pub public_key: PublicKey,
}

#[derive(Clone)]
#[derive(Debug)]
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

impl PeerRegistry {
    pub fn new(peers: HashMap<libp2p::PeerId, PublicKey>) -> Self {
        assert!(
            peers.len() <= u16::MAX as usize,
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
        self.index_to_peer
            .get(&index)
            .and_then(|peer_id| self.peer_to_info.get(peer_id).map(|info| &info.public_key))
    }

    pub fn get_public_key_by_peer_id(&self, peer_id: &libp2p::PeerId) -> Option<&PublicKey> {
        self.peer_to_info.get(peer_id).map(|info| &info.public_key)
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
