use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::crypto::{
    dkg::joint_feldman::peer_registry::PeerRegistry,
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::{self, Point, Scalar},
        vss::{
            encrypted_share::{self, EncryptedShare},
            DecryptedShares, EncryptedShares,
        },
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Peer not found: {0}")]
    PeerNotFound(libp2p::PeerId),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),
}

pub enum Output {
    Success {
        shares: Vec<Scalar>,
        comms: HashMap<libp2p::PeerId, Vec<Point>>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

pub enum ActionNeeded {
    Report(DecryptedShares),
    None,
}

#[derive(Debug)]
#[derive(Default)]
struct PeerInfo {
    en_shares: Option<EncryptedShares>,
    de_shares: Option<DecryptedShares>,
    comms: Option<Vec<Point>>,
    got_invalid: bool,
}

#[derive(Debug)]
#[derive(PartialEq, Eq)]
enum Status {
    Pending,
    Verifying(HashSet<libp2p::PeerId>), // Reporter peer ids
}

#[derive(Debug)]
pub struct Event {
    peer_infos: HashMap<libp2p::PeerId, PeerInfo>,
    peer_registry: Arc<PeerRegistry>,
    invalid_peers: HashSet<libp2p::PeerId>,
    own_peer: libp2p::PeerId,
    own_index_one_base: u16,
    own_shares: Vec<Scalar>,
    own_comms: Option<Vec<Point>>,
    own_de_shares: Option<DecryptedShares>,
    is_reported: bool,
    secret_key: Arc<SecretKey>,
    status: Status,
}

impl PeerInfo {
    pub fn from_registry(registry: &Arc<PeerRegistry>) -> HashMap<libp2p::PeerId, Self> {
        registry
            .peer_ids()
            .map(|peer_id| (*peer_id, Self::default()))
            .collect()
    }

    pub fn set_en_shares_and_comms(
        &mut self,
        en_shares: EncryptedShares,
        comms: Vec<Point>,
        pk: &PublicKey,
    ) -> Result<Option<Vec<u16>>> {
        self.en_shares = Some(en_shares);
        self.comms = Some(comms);

        if self.is_complete() {
            self.verify(pk)
        } else {
            Ok(None)
        }
    }

    fn is_complete(&self) -> bool {
        self.en_shares.is_some() && self.de_shares.is_some() && self.comms.is_some()
    }

    fn verify(&self, pk: &PublicKey) -> Result<Option<Vec<u16>>> {
        assert!(self.is_complete(), "PeerInfo is not complete");

        let en_shares = self
            .en_shares
            .as_ref()
            .expect("unreachable: encrypted_shares is None");
        let de_shares = self
            .de_shares
            .as_ref()
            .expect("unreachable: decrypted_shares is None");
        let comms = self
            .comms
            .as_ref()
            .expect("unreachable: commitments is None");

        let mut invalid_indices = Vec::new();
        for (index, en_share) in en_shares.iter() {
            let de_share = match de_shares.get(&index) {
                Some(de_share) => de_share,
                None => {
                    invalid_indices.push(index);
                    continue;
                }
            };

            Self::verify_de_to_en(de_share, en_share, pk)?;
            if !de_share.verify(index, comms)? {
                invalid_indices.push(index);
            }
        }

        if invalid_indices.is_empty() {
            Ok(None)
        } else {
            Ok(Some(invalid_indices))
        }
    }

    fn verify_de_to_en(
        de_share: &Scalar,
        en_share: &EncryptedShare,
        pk: &PublicKey,
    ) -> Result<bool> {
        let de_share_bytes = de_share.to_vec()?;
        let expected_en_share = pk.encrypt(&de_share_bytes)?;
        Ok(en_share.as_slice() == expected_en_share.as_slice())
    }

    pub fn set_de_shares(
        &mut self,
        de_shares: DecryptedShares,
        pk: &PublicKey,
    ) -> Result<Option<Vec<u16>>> {
        self.de_shares = Some(de_shares);

        if self.is_complete() {
            self.verify(pk)
        } else {
            Ok(None)
        }
    }

    pub fn set_got_invalid(&mut self) {
        self.got_invalid = true;
    }

    pub fn is_got_invalid(&self) -> bool {
        self.got_invalid
    }
}

impl Event {
    pub fn new(
        peer_registry: Arc<PeerRegistry>,
        secret_key: Arc<SecretKey>,
        own_peer: libp2p::PeerId,
    ) -> Self {
        let own_index_one_base = peer_registry
            .get_index(&own_peer)
            .expect("Own peer should be in the registry");

        Self {
            peer_infos: PeerInfo::from_registry(&peer_registry),
            peer_registry,
            invalid_peers: HashSet::new(),
            own_peer,
            own_index_one_base,
            own_shares: Vec::new(),
            own_comms: None,
            own_de_shares: None,
            is_reported: false,
            secret_key,
            status: Status::Pending,
        }
    }

    pub fn set_own_components(
        &mut self,
        de_shares: DecryptedShares,
        comms: Vec<Point>,
    ) -> ActionNeeded {
        if self.is_verifying() && !self.is_reported {
            self.is_reported = true;
            return ActionNeeded::Report(de_shares);
        }

        self.own_shares.push(
            de_shares
                .get(&self.own_index_one_base)
                .expect("own share should be present")
                .clone(),
        );
        self.own_comms = Some(comms);

        ActionNeeded::None
    }

    fn is_verifying(&self) -> bool {
        matches!(self.status, Status::Verifying(_))
    }

    fn set_status_to_verifying(&mut self) {
        if self.status == Status::Pending {
            self.status = Status::Verifying(HashSet::new());
        }
    }

    pub fn add_en_shares_and_comms(
        &mut self,
        peer_id: libp2p::PeerId,
        en_shares: EncryptedShares,
        comms: Vec<Point>,
    ) -> Result<ActionNeeded> {
        if !self.peer_infos.contains_key(&peer_id) {
            return Ok(ActionNeeded::None);
        }

        if self.process_own_share(&en_shares, &comms).is_err() {
            return Ok(self.handle_invalid_peer(peer_id));
        }

        let indices = {
            let peer_info = self
                .peer_infos
                .get_mut(&peer_id)
                .ok_or(Error::PeerNotFound(peer_id))?;
            let pk = self
                .peer_registry
                .get_public_key_by_peer_id(&peer_id)
                .expect("unreachable: PublicKey not found");
            peer_info.set_en_shares_and_comms(en_shares, comms, pk)?
        };

        if let Some(indices) = indices {
            self.mark_peers_by_indices(&indices);
            return Ok(self.handle_invalid_peer(peer_id));
        }

        Ok(ActionNeeded::None)
    }

    fn process_own_share(
        &mut self,
        encrypted_shares: &EncryptedShares,
        commitments: &[Point],
    ) -> std::result::Result<(), ()> {
        let encrypted_share = match encrypted_shares.get(&self.own_index_one_base) {
            Some(share) => share,
            None => return Err(()),
        };

        let decrypted_share = match encrypted_share.to_scalar(&self.secret_key) {
            Ok(share) => share,
            Err(_) => return Err(()),
        };

        if !self
            .verify_share(&decrypted_share, commitments)
            .unwrap_or(false)
        {
            return Err(());
        }

        self.own_shares.push(decrypted_share);
        Ok(())
    }

    fn handle_invalid_peer(&mut self, peer_id: libp2p::PeerId) -> ActionNeeded {
        self.set_status_to_verifying();
        self.invalid_peers.insert(peer_id);
        self.peer_infos.remove(&peer_id);

        if !self.is_reported && self.own_de_shares.is_some() {
            self.is_reported = true;
            if let Some(de_shares) = self.own_de_shares.take() {
                return ActionNeeded::Report(de_shares);
            }
        }

        ActionNeeded::None
    }

    fn verify_share(&self, de_share: &Scalar, comms: &[Point]) -> Result<bool> {
        de_share
            .verify(self.own_index_one_base, comms)
            .map_err(Error::from)
    }

    fn mark_peers_by_indices(&mut self, indices: &[u16]) {
        indices.iter().for_each(|index| {
            let peer_id = self
                .peer_registry
                .get_peer_id_by_index(*index)
                .expect("unreachable: Peer ID not found");
            let peer_info = self
                .peer_infos
                .get_mut(peer_id)
                .expect("unreachable: PeerInfo not found");
            peer_info.set_got_invalid();
        });
    }

    pub fn add_reporter(
        &mut self,
        reporter: libp2p::PeerId,
        de_shares: DecryptedShares,
    ) -> Result<ActionNeeded> {
        self.set_status_to_verifying();

        if let Status::Verifying(ref mut reporters) = self.status {
            reporters.insert(reporter);
        } else {
            panic!("unreachable: status should be Verifying");
        }

        self.add_decrypted_shares(reporter, de_shares)
    }

    pub fn add_decrypted_shares(
        &mut self,
        peer_id: libp2p::PeerId,
        de_shares: DecryptedShares,
    ) -> Result<ActionNeeded> {
        let indices = {
            let peer_info = self
                .peer_infos
                .get_mut(&peer_id)
                .ok_or(Error::PeerNotFound(peer_id))?;
            let pk = self
                .peer_registry
                .get_public_key_by_peer_id(&peer_id)
                .expect("unreachable: PublicKey not found");
            peer_info.set_de_shares(de_shares, pk)?
        };

        if let Some(indices) = indices {
            self.mark_peers_by_indices(&indices);
            Ok(self.handle_invalid_peer(peer_id))
        } else {
            Ok(ActionNeeded::None)
        }
    }

    pub fn output(self) -> Output {
        let mut all_invalid_peers = self.invalid_peers.to_owned();

        if let Status::Verifying(reporters) = &self.status {
            self.detect_malicious_report(&mut all_invalid_peers, reporters);
        }

        if !all_invalid_peers.is_empty() {
            Output::Failure {
                invalid_peers: all_invalid_peers,
            }
        } else {
            let mut comms = HashMap::new();
            for (peer_id, peer_info) in &self.peer_infos {
                if let Some(peer_comms) = &peer_info.comms {
                    comms.insert(*peer_id, peer_comms.to_owned());
                }
            }
            comms.insert(
                self.own_peer,
                self.own_comms
                    .as_ref()
                    .expect("Own comms should be set before output")
                    .to_owned(),
            );

            Output::Success {
                shares: self.own_shares,
                comms,
            }
        }
    }

    fn detect_malicious_report(
        &self,
        all_invalid_peers: &mut HashSet<libp2p::PeerId>,
        reporters: &HashSet<libp2p::PeerId>,
    ) {
        for reporter in reporters {
            let peer_info = self
                .peer_infos
                .get(reporter)
                .expect("unreachable: PeerInfo not found");

            if !peer_info.is_got_invalid() {
                all_invalid_peers.insert(*reporter);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::crypto::{
        dkg::joint_feldman::{
            event::{ActionNeeded, Event, Output, Status},
            peer_registry::PeerRegistry,
        },
        keypair::{self, PublicKey, SecretKey},
        primitives::{
            algebra::{Point, Scheme},
            vss::{DecryptedShares, EncryptedShares, Vss},
        },
    };

    const NUM_PEERS: u16 = 3;
    const THRESHOLD: u16 = 2;
    const SCHEME: Scheme = Scheme::Secp256k1;
    const OWN_INDEX_ZERO_BASE: u16 = 0;

    struct TestPeerInfo {
        peer_id: libp2p::PeerId,
        sk: SecretKey,
        pk: PublicKey,
        de_shares: DecryptedShares,
        valid_comms: Vec<Point>,
        invalid_comms: Vec<Point>,
    }

    struct TestContext {
        peers: Vec<TestPeerInfo>,
        peer_registry: Arc<PeerRegistry>,
    }

    impl TestPeerInfo {
        pub fn generate(peer: libp2p::PeerId) -> Self {
            let (sk, pk) = keypair::generate_secp256k1();
            let (de_shares, valid_comms) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

            let invalid_comms = valid_comms
                .iter()
                .map(|_| Point::zero(SCHEME))
                .collect::<Vec<_>>();

            Self {
                peer_id: peer,
                sk,
                pk,
                de_shares,
                valid_comms,
                invalid_comms,
            }
        }

        pub fn generate_en_shares(&self, registry: &PeerRegistry) -> EncryptedShares {
            EncryptedShares::from_decrypted(&self.de_shares, registry.iter_index_keys())
                .expect("EncryptedShares generation succeeded")
        }
    }

    impl TestContext {
        pub fn setup(num: u16) -> Self {
            let mut peers = Vec::new();
            let mut peer_map = HashMap::new();

            for _ in 0..num {
                let peer_id = libp2p::PeerId::random();
                let peer_info = TestPeerInfo::generate(peer_id);
                peer_map.insert(peer_id, peer_info.pk.clone());
                peers.push(peer_info);
            }

            let peer_registry = PeerRegistry::new(peer_map);

            Self {
                peers,
                peer_registry: Arc::new(peer_registry),
            }
        }

        pub fn create_event(&self, own_index: u16) -> Event {
            let secret_key = self
                .peers
                .get(own_index as usize)
                .expect("unreachable: Peer should be in the list")
                .sk
                .clone();
            let peer_id = self
                .peers
                .get(own_index as usize)
                .expect("unreachable: Peer should be in the list")
                .peer_id;

            Event::new(self.peer_registry.clone(), Arc::new(secret_key), peer_id)
        }
    }

    #[test]
    fn initialize_correctly() {
        let context = TestContext::setup(NUM_PEERS);
        let event = context.create_event(OWN_INDEX_ZERO_BASE);

        assert_eq!(event.peer_registry, context.peer_registry);
        assert!(matches!(event.status, Status::Pending));
        assert!(!event.is_reported);
    }

    #[test]
    fn succeeds_with_valid_compoments() {
        const TARGET_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = context.peers[TARGET_INDEX].peer_id;
        let en_shares = context.peers[TARGET_INDEX].generate_en_shares(&context.peer_registry);
        let comms = context.peers[TARGET_INDEX].valid_comms.clone();

        let result = event.add_en_shares_and_comms(peer_id, en_shares, comms);

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ActionNeeded::None));
        assert!(event.invalid_peers.is_empty());
        assert!(event.peer_infos.contains_key(&peer_id));
    }

    #[test]
    fn fails_with_invalid_compoments() {
        const TARGET_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = context.peers[TARGET_INDEX].peer_id;
        let en_shares = context.peers[TARGET_INDEX].generate_en_shares(&context.peer_registry);
        let comms = context.peers[TARGET_INDEX].invalid_comms.clone();

        let result = event.add_en_shares_and_comms(peer_id, en_shares, comms);

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ActionNeeded::None));
        assert!(event.invalid_peers.contains(&peer_id));
        assert_eq!(event.invalid_peers.len(), 1);
        assert!(!event.peer_infos.contains_key(&peer_id));
        assert_eq!(event.peer_infos.len(), (NUM_PEERS - 1) as usize);
        assert!(matches!(event.status, Status::Verifying(_)));
        assert!(!event.is_reported);
    }

    #[test]
    fn return_none_when_add_unknown_peer() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = libp2p::PeerId::random();
        let en_shares = context.peers[1].generate_en_shares(&context.peer_registry);
        let comms = context.peers[1].valid_comms.clone();

        let result = event.add_en_shares_and_comms(peer_id, en_shares, comms);

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ActionNeeded::None));
        assert!(event.invalid_peers.is_empty());
    }

    #[test]
    fn returns_none_when_not_reporting() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let own_de_shares = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .de_shares
            .clone();
        let own_comms = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .valid_comms
            .clone();

        let result = event.set_own_components(own_de_shares, own_comms);

        assert!(matches!(result, ActionNeeded::None));
        assert!(!event.is_reported);
    }

    #[test]
    fn returns_report_when_reporting() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let own_de_shares = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .de_shares
            .clone();
        let own_comms = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .valid_comms
            .clone();

        event.set_status_to_verifying();
        let result = event.set_own_components(own_de_shares, own_comms);

        assert!(matches!(result, ActionNeeded::Report(_)));
        assert!(event.is_reported);
    }

    #[test]
    fn entrys_verifying_state_when_add_reporter() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = context.peers[1].peer_id;
        let de_shares = context.peers[1].de_shares.clone();

        event.add_reporter(peer_id, de_shares).unwrap();

        assert!(matches!(event.status, Status::Verifying(_)));
    }

    #[test]
    fn output_all_peers_valid() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        for i in 0..NUM_PEERS {
            if i == OWN_INDEX_ZERO_BASE {
                let own_de_shares = context.peers[i as usize].de_shares.clone();
                let own_comms = context.peers[i as usize].valid_comms.clone();

                event.set_own_components(own_de_shares, own_comms);
                continue;
            }

            let peer_id = context.peers[i as usize].peer_id;
            let en_shares = context.peers[i as usize].generate_en_shares(&context.peer_registry);
            let comms = context.peers[i as usize].valid_comms.clone();

            event
                .add_en_shares_and_comms(peer_id, en_shares, comms)
                .unwrap();
        }

        let output = event.output();

        match output {
            Output::Success { shares, comms } => {
                assert_eq!(shares.len(), NUM_PEERS as usize);
                assert_eq!(comms.len(), NUM_PEERS as usize);
            }
            _ => panic!("Expected success output"),
        }
    }

    #[test]
    fn output_some_peers_invalid() {
        const INVALID_PEER_INDEX: usize = 1;
        const VALID_PEER_INDEX: usize = 2;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let invalid_peer_id = context.peers[INVALID_PEER_INDEX].peer_id;
        let invalid_en_shares =
            context.peers[INVALID_PEER_INDEX].generate_en_shares(&context.peer_registry);
        let invalid_comms = context.peers[INVALID_PEER_INDEX].invalid_comms.clone();

        event
            .add_en_shares_and_comms(invalid_peer_id, invalid_en_shares, invalid_comms)
            .unwrap();

        let valid_peer_id = context.peers[VALID_PEER_INDEX].peer_id;
        let valid_en_shares =
            context.peers[VALID_PEER_INDEX].generate_en_shares(&context.peer_registry);
        let valid_comms = context.peers[VALID_PEER_INDEX].valid_comms.clone();
        event
            .add_en_shares_and_comms(valid_peer_id, valid_en_shares, valid_comms)
            .unwrap();

        let own_de_shares = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .de_shares
            .clone();
        let own_comms = context.peers[OWN_INDEX_ZERO_BASE as usize]
            .valid_comms
            .clone();
        event.set_own_components(own_de_shares, own_comms);

        let output = event.output();

        match output {
            Output::Failure { invalid_peers } => {
                assert_eq!(invalid_peers.len(), 1);
                assert!(invalid_peers.contains(&invalid_peer_id));
            }
            _ => panic!("Expected failure output"),
        }
    }

    #[test]
    #[should_panic(expected = "Own comms should be set before output")]
    fn output_own_comms_not_set() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            let peer_id = context.peers[i as usize].peer_id;
            let en_shares = context.peers[i as usize].generate_en_shares(&context.peer_registry);
            let comms = context.peers[i as usize].valid_comms.clone();

            event
                .add_en_shares_and_comms(peer_id, en_shares, comms)
                .unwrap();
        }

        event.output();
    }

    #[test]
    fn detect_malicious_report() {
        const MALICIOUS_REPORTER_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        for i in 0..NUM_PEERS {
            if i == OWN_INDEX_ZERO_BASE {
                let own_de_shares = context.peers[i as usize].de_shares.clone();
                let own_comms = context.peers[i as usize].valid_comms.clone();

                event.set_own_components(own_de_shares, own_comms);
                continue;
            }

            let peer_id = context.peers[i as usize].peer_id;
            let en_shares = context.peers[i as usize].generate_en_shares(&context.peer_registry);
            let comms = context.peers[i as usize].valid_comms.clone();

            event
                .add_en_shares_and_comms(peer_id, en_shares, comms)
                .unwrap();
        }

        let malicious_peer_id = context.peers[MALICIOUS_REPORTER_INDEX].peer_id;
        let malicious_de_shares = context.peers[MALICIOUS_REPORTER_INDEX].de_shares.clone();
        event
            .add_reporter(malicious_peer_id, malicious_de_shares)
            .unwrap();

        for i in 0..NUM_PEERS {
            if i == MALICIOUS_REPORTER_INDEX as u16 {
                continue;
            }

            let peer_id = context.peers[i as usize].peer_id;
            let de_shares = context.peers[i as usize].de_shares.clone();
            event.add_decrypted_shares(peer_id, de_shares).unwrap();
        }

        let output = event.output();

        match output {
            Output::Failure { invalid_peers } => {
                assert_eq!(invalid_peers.len(), 1);
                assert!(invalid_peers.contains(&malicious_peer_id));
            }
            _ => panic!("Expected failure output"),
        }
    }
}
