use libp2p::PeerId;

pub struct ResidentId(pub PeerId);

impl ResidentId {
    pub fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;

    use crate::resident::resident_id::ResidentId;

    #[test]
    fn test_new() {
        let peer_id = PeerId::random();
        let resident_id = ResidentId::new(peer_id);
        assert_eq!(resident_id.0, peer_id, "ResidentId should store the PeerId");
    }
}
