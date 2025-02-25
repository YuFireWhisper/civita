use std::{fs, io};

use libp2p::{
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    Multiaddr, PeerId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResidentError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Keypair decoding error: {0}")]
    KeypairDecodingError(#[from] libp2p::identity::DecodingError),
}

type ResidentResult<T> = Result<T, ResidentError>;

#[derive(Debug, Default, Clone)]
struct Resident {
    peer_id: Option<PeerId>,
    multiaddr: Option<Multiaddr>,
    keypair: Option<Keypair>,
    bootstrap_peer_id: Option<PeerId>,
    bootstrap_addr: Option<Multiaddr>,
}

impl Resident {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_multiaddr(mut self, addr: Multiaddr) -> Self {
        self.multiaddr = Some(addr);
        self
    }

    pub fn set_keypair_and_peer_id_from_file(self, path: &str) -> ResidentResult<Self> {
        let keypair_bytes = fs::read(path)?;
        let keypair = Keypair::from_protobuf_encoding(&keypair_bytes)?;
        Ok(self.set_keypair_and_peer_id(keypair))
    }

    pub fn set_keypair_and_peer_id(mut self, keypair: Keypair) -> Self {
        let peer_id = PeerId::from_public_key(&keypair.public());

        self.peer_id = Some(peer_id);
        self.keypair = Some(keypair);
        self
    }

    pub fn set_bootstrap_from_other_resident(self, other: Resident) -> Self {
        self.set_bootstrap_peer_id(other.bootstrap_peer_id.unwrap())
            .set_bootstrap_addr(other.bootstrap_addr.unwrap())
    }

    pub fn set_bootstrap_peer_id(mut self, peer_id: PeerId) -> Self {
        self.bootstrap_peer_id = Some(peer_id);
        self
    }

    pub fn set_bootstrap_addr(mut self, addr: Multiaddr) -> Self {
        self.bootstrap_addr = Some(addr);
        self
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ResidentEvent")]
struct ResidentBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

#[derive(Debug)]
enum ResidentEvent {
    Kad(kad::Event),
}

impl From<kad::Event> for ResidentEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_resident_new() {
        let resident = Resident::new();

        assert!(resident.keypair.is_none());
        assert!(resident.multiaddr.is_none());
        assert!(resident.bootstrap_peer_id.is_none());
        assert!(resident.bootstrap_addr.is_none());
    }

    #[test]
    fn test_resident_set_multiaddr() {
        let multiaddr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

        let resident = Resident::new().set_multiaddr(multiaddr.clone());

        assert!(resident.multiaddr.is_some());
        assert_eq!(resident.multiaddr.unwrap(), multiaddr);
    }

    #[test]
    fn test_set_keypair_and_peer_id_from_file_success() {
        let (keypair, temp_file) = generate_keypair_and_write_to_file();

        let resident = Resident::new()
            .set_keypair_and_peer_id_from_file(temp_file.path().to_str().unwrap())
            .unwrap();

        assert!(resident.peer_id.is_some());
        assert_eq!(resident.peer_id.unwrap(), PeerId::from_public_key(&keypair.public()));

        assert!(resident.keypair.is_some());
        assert_eq!(resident.keypair.unwrap().public(), keypair.public());
    }

    fn generate_keypair_and_write_to_file() -> (Keypair, NamedTempFile) {
        let keypair = Keypair::generate_ed25519();
        let keypair_bytes = keypair.to_protobuf_encoding().unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&keypair_bytes).unwrap();

        (keypair, temp_file)
    }

    #[test]
    fn test_set_keypair_and_peer_id_from_file_file_not_found() {
        let path = "nonexistent_file.keypair";

        let result = Resident::new().set_keypair_and_peer_id_from_file(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_set_keypair_and_peer_id_from_file_invalid_keypair() {
        let temp_file = write_invalid_keypair_to_file();

        let result = Resident::new().set_keypair_and_peer_id_from_file(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
    }

    fn write_invalid_keypair_to_file() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid keypair data").unwrap();

        temp_file
    }

    #[test]
    fn test_set_keypair_and_peer_id() {
        let keypair = Keypair::generate_ed25519();

        let resident = Resident::new().set_keypair_and_peer_id(keypair);

        assert!(resident.peer_id.is_some());
        assert!(resident.keypair.is_some());
    }

    #[test]
    fn test_resident_set_bootstrap_from_other_resident() {
        let other = Resident::new()
            .set_bootstrap_peer_id(PeerId::random())
            .set_bootstrap_addr("/ip4/0.0.0.0/tcp/0".parse().unwrap());

        let resident = Resident::new().set_bootstrap_from_other_resident(other.clone());

        assert!(resident.bootstrap_peer_id.is_some());
        assert_eq!(
            resident.bootstrap_peer_id.unwrap(),
            other.bootstrap_peer_id.unwrap()
        );

        assert!(resident.bootstrap_addr.is_some());
        assert_eq!(
            resident.bootstrap_addr.unwrap(),
            other.bootstrap_addr.unwrap()
        );
    }

    #[test]
    fn test_resident_set_bootstrap_peer_id() {
        let peer_id = PeerId::random();

        let resident = Resident::new().set_bootstrap_peer_id(peer_id);

        assert!(resident.bootstrap_peer_id.is_some());
        assert_eq!(resident.bootstrap_peer_id.unwrap(), peer_id);
    }

    #[test]
    fn test_resident_set_bootstrap_addr() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

        let resident = Resident::new().set_bootstrap_addr(addr.clone());

        assert!(resident.bootstrap_addr.is_some());
        assert_eq!(resident.bootstrap_addr.unwrap(), addr);
    }
}
