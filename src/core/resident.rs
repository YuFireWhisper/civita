use libp2p::{identity::Keypair, Multiaddr, PeerId};

#[derive(Debug, Default)]
struct Resident {
    keypair: Option<Keypair>,
    addr: Option<Multiaddr>,
    bootstrap_peer_id: Option<PeerId>,
    bootstrap_addr: Option<Multiaddr>,
}

impl Resident {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resident_new() {
        let resident = Resident::new();

        assert!(resident.keypair.is_none());
        assert!(resident.addr.is_none());
        assert!(resident.bootstrap_peer_id.is_none());
        assert!(resident.bootstrap_addr.is_none());
    }

    #[test]
    fn test_resident_set_keypair() {
        let keypair = Keypair::generate_ed25519();

        let resident = Resident::new()
            .set_keypair(keypair);

        assert!(resident.keypair.is_some());
    }
}
