use libp2p::{identity, noise, swarm, yamux, Transport, TransportError};
use std::{fs, io};

use libp2p::{
    core::upgrade::Version,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    tcp::tokio,
    Multiaddr, PeerId, Swarm,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResidentError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Keypair decoding error: {0}")]
    KeypairDecodingError(#[from] identity::DecodingError),
    #[error("Noise error: {0}")]
    NoiseError(#[from] noise::Error),
    #[error("Transport error: {0}")]
    TransportError(String),
    #[error("Swarm dial error: {0}")]
    SwarmDialError(#[from] swarm::DialError),
    #[error("Peer ID is not set")]
    PeerIdNotSet,
    #[error("Multiaddr is not set")]
    MultiaddrNotSet,
    #[error("Bootstrap peer ID is not set but multiaddr is set")]
    BootstrapPeerIdNotSet,
    #[error("Bootstrap multiaddr is not set but peer ID is set")]
    BootstrapMultiaddrNotSet,
}

impl<T: std::fmt::Debug> From<TransportError<T>> for ResidentError {
    fn from(err: TransportError<T>) -> Self {
        ResidentError::TransportError(format!("{:?}", err))
    }
}

type ResidentResult<T> = Result<T, ResidentError>;

#[derive(Default)]
struct Resident {
    peer_id: Option<PeerId>,
    multiaddr: Option<Multiaddr>,
    keypair: Option<Keypair>,
    bootstrap_peer_id: Option<PeerId>,
    bootstrap_multiaddr: Option<Multiaddr>,
    swarm: Option<Swarm<ResidentBehaviour>>,
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
        let bootstrap_peer_id = other.peer_id.ok_or(ResidentError::PeerIdNotSet)?;
        let bootstrap_multiaddr = other.multiaddr.ok_or(ResidentError::MultiaddrNotSet)?;

        Ok(self
            .with_bootstrap_peer_id(bootstrap_peer_id)
            .with_bootstrap_multiaddr(bootstrap_multiaddr))
    }

    pub fn with_bootstrap_peer_id(mut self, peer_id: PeerId) -> Self {
        self.bootstrap_peer_id = Some(peer_id);
        self
    }

    pub fn with_bootstrap_multiaddr(mut self, multiaddr: Multiaddr) -> Self {
        self.bootstrap_multiaddr = Some(multiaddr);
        self
    }

    pub fn build(mut self) -> ResidentResult<Self> {
        let keypair = self.get_keypair()?;
        let peer_id = self.get_peer_id()?;
        let multiaddr = self.get_multiaddr_clone()?;

        let transport = tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(keypair)?)
            .multiplex(yamux::Config::default())
            .boxed();

        let behaviour = ResidentBehaviour::new(peer_id);
        let swarm_config = swarm::Config::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        swarm.listen_on(multiaddr)?;

        if let Some((peer_id, bootstrap_multiaddr)) = self.get_bootstrap_info()? {
            swarm.dial(bootstrap_multiaddr.clone())?;
            swarm
                .behaviour_mut()
                .kad
                .add_address(&peer_id, bootstrap_multiaddr);
        }

        self.swarm = Some(swarm);
        Ok(self)
    }

    fn get_peer_id(&self) -> ResidentResult<PeerId> {
        self.peer_id.ok_or(ResidentError::PeerIdNotSet)
    }

    fn get_keypair_cloned(&self) -> ResidentResult<Keypair> {
        self.keypair.clone().ok_or(ResidentError::PeerIdNotSet)
    }

    fn get_keypair(&self) -> ResidentResult<&Keypair> {
        self.keypair.as_ref().ok_or(ResidentError::PeerIdNotSet)
    }

    fn get_multiaddr_clone(&self) -> ResidentResult<Multiaddr> {
        self.multiaddr.clone().ok_or(ResidentError::MultiaddrNotSet)
    }

    fn get_bootstrap_info(&self) -> ResidentResult<Option<(PeerId, Multiaddr)>> {
        match (self.bootstrap_peer_id, &self.bootstrap_multiaddr) {
            (None, None) => Ok(None),
            (Some(peer_id), Some(multiaddr)) => Ok(Some((peer_id, multiaddr.clone()))),
            (None, Some(_)) => Err(ResidentError::BootstrapPeerIdNotSet),
            (Some(_), None) => Err(ResidentError::BootstrapMultiaddrNotSet),
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ResidentEvent")]
struct ResidentBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

impl ResidentBehaviour {
    fn new(peer_id: PeerId) -> Self {
        let memory_store = MemoryStore::new(peer_id);
        Self {
            kad: kad::Behaviour::new(peer_id, memory_store),
        }
    }
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
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::core::resident::Resident;

    #[test]
    fn test_resident_new() {
        let resident = Resident::new();

        assert!(resident.keypair.is_none());
        assert!(resident.multiaddr.is_none());
        assert!(resident.bootstrap_peer_id.is_none());
        assert!(resident.bootstrap_multiaddr.is_none());
    }

    #[test]
    fn test_with_multiaddr() {
        let multiaddr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

        let resident = Resident::new().with_multiaddr(multiaddr.clone());

        assert!(resident.multiaddr.is_some());
        assert_eq!(resident.multiaddr.unwrap(), multiaddr);
    }

    #[test]
    fn test_with_keypair_from_file_success() {
        let (keypair, temp_file) = generate_keypair_and_write_to_file();

        let resident = Resident::new()
            .with_keypair_from_file(temp_file.path().to_str().unwrap())
            .unwrap();

        assert!(resident.peer_id.is_some());
        assert_eq!(
            resident.peer_id.unwrap(),
            PeerId::from_public_key(&keypair.public())
        );

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
    fn test_with_keypair_from_file_file_not_found() {
        let path = "nonexistent_file.keypair";

        let result = Resident::new().with_keypair_from_file(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_with_keypair_from_file_invalid_keypair() {
        let temp_file = write_invalid_keypair_to_file();

        let result = Resident::new().with_keypair_from_file(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
    }

    fn write_invalid_keypair_to_file() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid keypair data").unwrap();

        temp_file
    }

    #[test]
    fn test_with_keypair() {
        let keypair = Keypair::generate_ed25519();

        let resident = Resident::new().with_keypair(keypair);

        assert!(resident.peer_id.is_some());
        assert!(resident.keypair.is_some());
    }

    #[test]
    fn test_resident_with_bootstrap_from_resident() {
        let keypair = Keypair::generate_ed25519();
        let other = Resident::new()
            .with_keypair(keypair)
            .with_multiaddr("/ip4/0.0.0.0/tcp/0".parse().unwrap());

        let resident = Resident::new().with_bootstrap_from_resident(other);

        assert!(resident.is_ok());
        assert!(resident.as_ref().unwrap().bootstrap_peer_id.is_some());
        assert!(resident.as_ref().unwrap().bootstrap_multiaddr.is_some());
    }

    #[test]
    fn test_resident_with_bootstrap_peer_id() {
        let peer_id = PeerId::random();

        let resident = Resident::new().with_bootstrap_peer_id(peer_id);

        assert!(resident.bootstrap_peer_id.is_some());
        assert_eq!(resident.bootstrap_peer_id.unwrap(), peer_id);
    }

    #[test]
    fn test_resident_set_bootstrap_addr() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();

        let resident = Resident::new().with_bootstrap_multiaddr(addr.clone());

        assert!(resident.bootstrap_multiaddr.is_some());
        assert_eq!(resident.bootstrap_multiaddr.unwrap(), addr);
    }

    #[tokio::test]
    async fn test_build_success_minimum_requirements() {
        let resident = create_basic_resident();

        let result = resident.build();

        assert!(result.is_ok());
        let built_resident = result.unwrap();
        assert!(built_resident.swarm.is_some());
        assert!(built_resident.peer_id.is_some());
        assert!(built_resident.multiaddr.is_some());
    }

    fn create_basic_resident() -> Resident {
        let keypair = Keypair::generate_ed25519();
        let multiaddr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        Resident::new()
            .with_keypair(keypair)
            .with_multiaddr(multiaddr)
    }
}
