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
}
