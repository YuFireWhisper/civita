use libp2p::PeerId;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResidentId(pub PeerId);

impl ResidentId {
    pub fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    pub fn random() -> Self {
        Self(PeerId::random())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use libp2p::PeerId;

    use crate::resident::resident_id::ResidentId;

    #[test]
    fn test_new() {
        let peer_id = PeerId::random();
        let resident_id = ResidentId::new(peer_id);
        assert_eq!(resident_id.0, peer_id, "ResidentId should store the PeerId");
    }

    #[test]
    fn test_random() {
        const NUM_IDS: usize = 10;

        let mut resident_ids = HashSet::new();
        for _ in 0..NUM_IDS {
            resident_ids.insert(ResidentId::random());
        }

        assert_eq!(
            resident_ids.len(),
            NUM_IDS,
            "ResidentId::random() should generate unique IDs"
        );
    }
}
