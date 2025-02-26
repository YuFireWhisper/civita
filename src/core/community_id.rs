use std::hash::{DefaultHasher, Hash, Hasher};

use libp2p::PeerId;

pub struct CommunityId(pub [u8; 32]);

impl CommunityId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }

    pub fn from_peer_id(peer_id: &PeerId, total_communities: usize) -> Self {
        let mut hasher = DefaultHasher::new();
        peer_id.hash(&mut hasher);
        let hash = hasher.finish();

        let community_index = (hash % total_communities as u64) as usize;

        let mut id = [0; 32];
        let bytes = community_index.to_le_bytes();
        id[..bytes.len()].copy_from_slice(&bytes);

        Self(id)
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use libp2p::PeerId;

    use crate::core::community_id::CommunityId;

    #[test]
    fn test_new() {
        let id_bytes = [1; 32];
        let id = CommunityId::new(id_bytes);
        assert_eq!(id.0, id_bytes, "CommunityId should store the ID bytes");
    }

    #[test]
    fn test_from_peer_id() {
        let peer_id = PeerId::random();
        let total_communities = 10;
        let id = CommunityId::from_peer_id(&peer_id, total_communities);

        let mut hasher = DefaultHasher::new();
        peer_id.hash(&mut hasher);
        let hash = hasher.finish();

        let community_index = (hash % total_communities as u64) as usize;

        let mut id_bytes = [0; 32];
        let bytes = community_index.to_le_bytes();
        id_bytes[..bytes.len()].copy_from_slice(&bytes);

        assert_eq!(
            id.0, id_bytes,
            "CommunityId should be derived from the PeerId"
        );
    }
}
