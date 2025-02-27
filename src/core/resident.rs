use libp2p::{identity, noise, swarm, TransportError};
use std::{fs, io};

use libp2p::{identity::Keypair, Multiaddr, PeerId};
use thiserror::Error;

use crate::network::resident_network::{ResidentNetwork, ResidentNetworkError};

#[derive(Debug, Error)]
pub enum ResidentError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Keypair decoding error: {0}")]
    KeypairDecoding(#[from] identity::DecodingError),
    #[error("Noise error: {0}")]
    NoiseError(#[from] noise::Error),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Swarm dial error: {0}")]
    SwarmDial(#[from] swarm::DialError),
    #[error("Resident network error: {0}")]
    ResidentNetwork(#[from] ResidentNetworkError),
    #[error("Peer ID is not set")]
    MissingPeerId,
    #[error("Multiaddr is not set")]
    MissingMultiaddr,
    #[error("Bootstrap peer ID is not set but multiaddr is set")]
    MissingBootstrapPeerId,
    #[error("Bootstrap multiaddr is not set but peer ID is set")]
    MissingBootstrapMultiaddr,
}

impl<T: std::fmt::Debug> From<TransportError<T>> for ResidentError {
    fn from(err: TransportError<T>) -> Self {
        ResidentError::Transport(format!("{:?}", err))
    }
}

type ResidentResult<T> = Result<T, ResidentError>;

#[derive(Default)]
pub struct Resident {
    peer_id: Option<PeerId>,
    multiaddr: Option<Multiaddr>,
    keypair: Option<Keypair>,
    bootstrap_peer_id: Option<PeerId>,
    bootstrap_multiaddr: Option<Multiaddr>,
    resident_network: Option<ResidentNetwork>,
}

impl Resident {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_multiaddr(mut self, addr: Multiaddr) -> Self {
        self.multiaddr = Some(addr);
        self
    }

    pub fn with_keypair_from_file(self, path: &str) -> ResidentResult<Self> {
        let keypair_bytes = fs::read(path)?;
        let keypair = Keypair::from_protobuf_encoding(&keypair_bytes)?;
        Ok(self.with_keypair(keypair))
    }

    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        let peer_id = PeerId::from_public_key(&keypair.public());

        self.peer_id = Some(peer_id);
        self.keypair = Some(keypair);
        self
    }

    pub fn with_bootstrap_from_resident(self, other: Resident) -> ResidentResult<Self> {
        let peer_id = other.peer_id.ok_or(ResidentError::MissingPeerId)?;
        let multiaddr = other.multiaddr.ok_or(ResidentError::MissingMultiaddr)?;
        Ok(self.with_bootstrap(peer_id, multiaddr))
    }

    pub fn with_bootstrap(mut self, peer_id: PeerId, multiaddr: Multiaddr) -> Self {
        self.bootstrap_peer_id = Some(peer_id);
        self.bootstrap_multiaddr = Some(multiaddr);
        self
    }

    pub async fn build(mut self) -> ResidentResult<Self> {
        let peer_id = self.get_peer_id()?;
        let keypair = self.get_keypair()?;
        let multiaddr = self.get_multiaddr_clone()?;

        let mut resident_network = ResidentNetwork::new(peer_id, keypair, multiaddr);

        if let Some((peer_id, bootstrap_multiaddr)) = self.get_bootstrap_info()? {
            resident_network.dial(peer_id, bootstrap_multiaddr).await?;
        }

        self.resident_network = Some(resident_network);

        Ok(self)
    }

    fn get_peer_id(&self) -> ResidentResult<PeerId> {
        self.peer_id.ok_or(ResidentError::MissingPeerId)
    }

    fn get_keypair(&self) -> ResidentResult<&Keypair> {
        self.keypair.as_ref().ok_or(ResidentError::MissingPeerId)
    }

    fn get_multiaddr_clone(&self) -> ResidentResult<Multiaddr> {
        self.multiaddr
            .clone()
            .ok_or(ResidentError::MissingMultiaddr)
    }

    fn get_bootstrap_info(&self) -> ResidentResult<Option<(PeerId, Multiaddr)>> {
        match (self.bootstrap_peer_id, &self.bootstrap_multiaddr) {
            (None, None) => Ok(None),
            (Some(peer_id), Some(multiaddr)) => Ok(Some((peer_id, multiaddr.clone()))),
            (None, Some(_)) => Err(ResidentError::MissingBootstrapPeerId),
            (Some(_), None) => Err(ResidentError::MissingBootstrapMultiaddr),
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::core::resident::Resident;

    struct TestFixtures {
        base_multiaddr: Multiaddr,
        keypair: Keypair,
    }

    impl TestFixtures {
        fn new() -> Self {
            Self {
                base_multiaddr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                keypair: Keypair::generate_ed25519(),
            }
        }

        fn create_basic_resident(&self) -> Resident {
            Resident::new()
                .with_keypair(self.keypair.clone())
                .with_multiaddr(self.base_multiaddr.clone())
        }

        fn generate_keypair_file(&self) -> (Keypair, NamedTempFile) {
            let keypair = self.keypair.clone();
            let mut temp_file = NamedTempFile::new().unwrap();
            let keypair_bytes = keypair.to_protobuf_encoding().unwrap();
            temp_file.write_all(&keypair_bytes).unwrap();
            (keypair, temp_file)
        }

        fn generate_invalid_keypair_file(&self) -> NamedTempFile {
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(b"invalid keypair data").unwrap();
            temp_file
        }
    }

    #[test]
    fn test_new_with_no_fields_set() {
        let resident = Resident::new();

        assert!(resident.peer_id.is_none());
        assert!(resident.multiaddr.is_none());
        assert!(resident.keypair.is_none());
        assert!(resident.bootstrap_peer_id.is_none());
        assert!(resident.bootstrap_multiaddr.is_none());
        assert!(resident.resident_network.is_none());
    }

    #[test]
    fn test_with_multiaddr() {
        let fixtures = TestFixtures::new();

        let resident = Resident::new().with_multiaddr(fixtures.base_multiaddr.clone());

        assert_eq!(resident.multiaddr.unwrap(), fixtures.base_multiaddr);
    }

    #[test]
    fn test_with_keypair_from_file_success() {
        let fixtures = TestFixtures::new();
        let (keypair, temp_file) = fixtures.generate_keypair_file();

        let resident = Resident::new()
            .with_keypair_from_file(temp_file.path().to_str().unwrap())
            .unwrap();

        assert_eq!(
            resident.peer_id.unwrap(),
            PeerId::from_public_key(&keypair.public())
        );
        assert_eq!(resident.keypair.unwrap().public(), keypair.public());
    }

    #[test]
    fn test_with_keypair_from_file_file_not_found() {
        let result = Resident::new().with_keypair_from_file("nonexistent_file.keypair");

        assert!(result.is_err());
    }

    #[test]
    fn test_with_keypair_from_file_invalid_keypair() {
        let fixtures = TestFixtures::new();
        let temp_file = fixtures.generate_invalid_keypair_file();

        let result = Resident::new().with_keypair_from_file(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
    }

    #[test]
    fn test_with_keypair() {
        let fixtures = TestFixtures::new();

        let resident = Resident::new().with_keypair(fixtures.keypair.clone());

        assert!(resident.peer_id.is_some());
        assert!(resident.keypair.is_some());
    }

    #[test]
    fn test_with_bootstrap_from_resident() {
        let fixtures = TestFixtures::new();
        let other = fixtures.create_basic_resident();
        let resident = Resident::new().with_bootstrap_from_resident(other);

        let resident = resident.unwrap();
        assert!(resident.bootstrap_peer_id.is_some());
        assert!(resident.bootstrap_multiaddr.is_some());
    }

    #[test]
    fn test_with_bootstrap() {
        let fixtures = TestFixtures::new();
        let peer_id = PeerId::random();
        let resident = Resident::new().with_bootstrap(peer_id, fixtures.base_multiaddr.clone());

        assert_eq!(resident.bootstrap_peer_id.unwrap(), peer_id);
        assert_eq!(
            resident.bootstrap_multiaddr.unwrap(),
            fixtures.base_multiaddr
        );
    }
}
