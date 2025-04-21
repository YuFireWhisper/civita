use std::{collections::HashSet, sync::Arc};

use crate::crypto::{
    index_map::IndexedMap,
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

#[derive(Debug)]
pub enum Output {
    Success {
        shares: Vec<Scalar>,
        comms: IndexedMap<libp2p::PeerId, Vec<Point>>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

#[derive(Debug)]
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
    peer_infos: IndexedMap<libp2p::PeerId, PeerInfo>,
    peer_pks: Arc<IndexedMap<libp2p::PeerId, PublicKey>>,
    invalid_peers: HashSet<libp2p::PeerId>,
    own_peer: libp2p::PeerId,
    own_shares: Vec<Scalar>,
    own_comms: Option<Vec<Point>>,
    own_de_shares: Option<DecryptedShares>,
    is_reported: bool,
    secret_key: Arc<SecretKey>,
    status: Status,
}

impl PeerInfo {
    pub fn new(peer_ids: impl Iterator<Item = libp2p::PeerId>) -> IndexedMap<libp2p::PeerId, Self> {
        let mut peer_infos = IndexedMap::new();
        for peer_id in peer_ids {
            peer_infos.insert(peer_id, Self::default());
        }
        peer_infos
    }

    pub fn set_component(
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

    pub fn is_components_set(&self) -> bool {
        self.en_shares.is_some() && self.comms.is_some()
    }

    pub fn is_de_shares_set(&self) -> bool {
        self.de_shares.is_some()
    }
}

impl Event {
    pub fn new(
        peer_pks: Arc<IndexedMap<libp2p::PeerId, PublicKey>>,
        secret_key: Arc<SecretKey>,
        own_peer: libp2p::PeerId,
    ) -> Self {
        assert!(
            peer_pks.contains_key(&own_peer),
            "Own peer must be in the peer_pks map",
        );

        Self {
            peer_infos: PeerInfo::new(peer_pks.keys().cloned()),
            peer_pks,
            invalid_peers: HashSet::new(),
            own_peer,
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
                .get(&self.get_own_index())
                .expect("own share should be present")
                .clone(),
        );
        self.own_comms = Some(comms);

        ActionNeeded::None
    }

    fn get_own_index(&self) -> u16 {
        self.peer_infos
            .get_index(&self.own_peer)
            .expect("unreachable: own peer not found")
    }

    fn is_verifying(&self) -> bool {
        matches!(self.status, Status::Verifying(_))
    }

    fn set_status_to_verifying(&mut self) {
        if self.status == Status::Pending {
            self.status = Status::Verifying(HashSet::new());
        }
    }

    pub fn add_component(
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
                .peer_pks
                .get(&peer_id)
                .expect("unreachable: PublicKey not found");
            peer_info.set_component(en_shares, comms, pk)?
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
        let encrypted_share = match encrypted_shares.get(&self.get_own_index()) {
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
        println!("Invalid peer: {peer_id}");

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
            .verify(self.get_own_index(), comms)
            .map_err(Error::from)
    }

    fn mark_peers_by_indices(&mut self, indices: &[u16]) {
        indices.iter().for_each(|index| {
            let peer_info = self
                .peer_infos
                .get_mut_by_index(index)
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
                .peer_pks
                .get(&peer_id)
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

        self.detect_not_set_component_peers(&mut all_invalid_peers);
        self.detect_not_set_de_shares_peers(&mut all_invalid_peers);
        self.detect_malicious_report(&mut all_invalid_peers);

        if !all_invalid_peers.is_empty() {
            return Output::Failure {
                invalid_peers: all_invalid_peers,
            };
        }

        let mut comms = self
            .peer_infos
            .iter()
            .filter_map(|(peer_id, peer_info)| {
                if peer_id == &self.own_peer {
                    return None;
                }
                let comms = peer_info
                    .comms
                    .as_ref()
                    .expect("comms should be set before output");
                Some((*peer_id, comms.to_owned()))
            })
            .collect::<IndexedMap<_, _>>();

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

    fn detect_not_set_component_peers(&self, all_invalid_peers: &mut HashSet<libp2p::PeerId>) {
        for (peer_id, peer_info) in &self.peer_infos {
            if !peer_info.is_components_set() && peer_id != &self.own_peer {
                all_invalid_peers.insert(*peer_id);
            }
        }
    }

    fn detect_not_set_de_shares_peers(&self, all_invalid_peers: &mut HashSet<libp2p::PeerId>) {
        if !self.is_verifying() {
            return;
        }

        for (peer_id, peer_info) in &self.peer_infos {
            if !peer_info.is_de_shares_set() && peer_id != &self.own_peer {
                all_invalid_peers.insert(*peer_id);
            }
        }
    }

    fn detect_malicious_report(&self, all_invalid_peers: &mut HashSet<libp2p::PeerId>) {
        if let Status::Verifying(reporters) = &self.status {
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::crypto::{
        dkg::joint_feldman::event::{ActionNeeded, Event, Output, Status},
        index_map::IndexedMap,
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
        peer_infos: Vec<TestPeerInfo>,
        peer_pks: Arc<IndexedMap<libp2p::PeerId, PublicKey>>,
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

        pub fn generate_en_shares<'a>(
            &self,
            peer_pks: impl Iterator<Item = (&'a u16, &'a PublicKey)>,
        ) -> EncryptedShares {
            EncryptedShares::from_decrypted(&self.de_shares, peer_pks)
                .expect("EncryptedShares generation succeeded")
        }
    }

    impl TestContext {
        pub fn setup(num: u16) -> Self {
            let mut peer_infos = Vec::new();
            let mut peer_pks = IndexedMap::new();

            for _ in 0..num {
                let peer_id = libp2p::PeerId::random();
                let peer_info = TestPeerInfo::generate(peer_id);
                peer_pks.insert(peer_id, peer_info.pk.clone());
                peer_infos.push(peer_info);
            }

            Self {
                peer_infos,
                peer_pks: Arc::new(peer_pks),
            }
        }

        pub fn create_event(&self, own_index: u16) -> Event {
            let secret_key = self.peer_infos[own_index as usize].sk.clone();
            let peer_id = self.peer_infos[own_index as usize].peer_id;

            Event::new(self.peer_pks.clone(), Arc::new(secret_key), peer_id)
        }

        pub fn set_own_components(&self, event: &mut Event, index: u16) {
            let own_de_shares = self.peer_infos[index as usize].de_shares.clone();
            let own_comms = self.get_comms(index, true);
            event.set_own_components(own_de_shares, own_comms);
        }

        fn get_comms(&self, index: u16, is_valid: bool) -> Vec<Point> {
            if is_valid {
                self.peer_infos[index as usize].valid_comms.clone()
            } else {
                self.peer_infos[index as usize].invalid_comms.clone()
            }
        }

        pub fn add_valid_components(
            &self,
            event: &mut Event,
            index: u16,
        ) -> Result<ActionNeeded, String> {
            let peer_id = self.get_peer_id(index);
            let en_shares = self.get_encrypted_shares(index);
            let comms = self.get_comms(index, true);

            event
                .add_component(peer_id, en_shares, comms)
                .map_err(|e| e.to_string())
        }

        pub fn get_peer_id(&self, index: u16) -> libp2p::PeerId {
            self.peer_infos[index as usize].peer_id
        }

        pub fn get_encrypted_shares(&self, index: u16) -> EncryptedShares {
            self.peer_infos[index as usize].generate_en_shares(self.peer_pks.iter_indexed_values())
        }

        pub fn add_invalid_components(
            &self,
            event: &mut Event,
            index: u16,
        ) -> Result<ActionNeeded, String> {
            let peer_id = self.get_peer_id(index);
            let en_shares = self.get_encrypted_shares(index);
            let comms = self.get_comms(index, false);

            event
                .add_component(peer_id, en_shares, comms)
                .map_err(|e| e.to_string())
        }

        pub fn add_decrypted_shares(
            &self,
            event: &mut Event,
            index: u16,
        ) -> Result<ActionNeeded, String> {
            let peer_id = self.peer_infos[index as usize].peer_id;
            let de_shares = self.peer_infos[index as usize].de_shares.clone();

            event
                .add_decrypted_shares(peer_id, de_shares)
                .map_err(|e| e.to_string())
        }

        pub fn add_reporter(&self, event: &mut Event, index: u16) -> Result<ActionNeeded, String> {
            let peer_id = self.peer_infos[index as usize].peer_id;
            let de_shares = self.peer_infos[index as usize].de_shares.clone();

            event
                .add_reporter(peer_id, de_shares)
                .map_err(|e| e.to_string())
        }
    }

    fn assert_success_output(output: Output, expected_peer_count: u16) {
        match output {
            Output::Success { shares, comms } => {
                assert_eq!(shares.len(), expected_peer_count as usize);
                assert_eq!(comms.len(), expected_peer_count);
            }
            _ => panic!("Expected success output"),
        }
    }

    fn assert_failure_output(output: Output, invalid_peer_ids: &[libp2p::PeerId]) {
        match output {
            Output::Failure { invalid_peers } => {
                assert_eq!(invalid_peers.len(), invalid_peer_ids.len());
                for peer_id in invalid_peer_ids {
                    assert!(invalid_peers.contains(peer_id));
                }
            }
            _ => panic!("Expected failure output"),
        }
    }

    #[test]
    fn initialize_correctly() {
        let context = TestContext::setup(NUM_PEERS);
        let event = context.create_event(OWN_INDEX_ZERO_BASE);

        assert_eq!(
            event.own_peer,
            context.peer_infos[OWN_INDEX_ZERO_BASE as usize].peer_id
        );
        assert!(matches!(event.status, Status::Pending));
        assert!(!event.is_reported);
    }

    #[test]
    fn succeeds_with_valid_compoments() {
        const TARGET_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = context.get_peer_id(TARGET_INDEX as u16);
        let result = context.add_valid_components(&mut event, TARGET_INDEX as u16);

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

        let peer_id = context.get_peer_id(TARGET_INDEX as u16);
        let result = context.add_invalid_components(&mut event, TARGET_INDEX as u16);

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ActionNeeded::None));
        assert!(event.invalid_peers.contains(&peer_id));
        assert_eq!(event.invalid_peers.len(), 1);
        assert!(!event.peer_infos.contains_key(&peer_id));
        assert_eq!(event.peer_infos.len(), (NUM_PEERS - 1));
        assert!(matches!(event.status, Status::Verifying(_)));
        assert!(!event.is_reported);
    }

    #[test]
    fn return_none_when_add_unknown_peer() {
        const TARGET_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        let peer_id = libp2p::PeerId::random();
        let en_shares = context.get_encrypted_shares(TARGET_INDEX as u16);
        let comms = context.peer_infos[1].valid_comms.clone();

        let result = event.add_component(peer_id, en_shares, comms);

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ActionNeeded::None));
        assert!(event.invalid_peers.is_empty());
    }

    #[test]
    fn returns_none_when_not_reporting() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        assert!(!event.is_reported);
    }

    #[test]
    fn returns_report_when_reporting() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        event.set_status_to_verifying();
        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        assert!(event.is_reported);
    }

    #[test]
    fn entrys_verifying_state_when_add_reporter() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.add_reporter(&mut event, 1).unwrap();

        assert!(matches!(event.status, Status::Verifying(_)));
    }

    #[test]
    fn output_all_peers_valid() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            context.add_valid_components(&mut event, i).unwrap();
        }

        let output = event.output();
        assert_success_output(output, NUM_PEERS);
    }

    #[test]
    fn output_some_peers_invalid() {
        const INVALID_PEER_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        context
            .add_invalid_components(&mut event, INVALID_PEER_INDEX as u16)
            .unwrap();

        for i in 1..NUM_PEERS {
            if i as usize == INVALID_PEER_INDEX {
                continue;
            }
            context.add_valid_components(&mut event, i).unwrap();
            context.add_decrypted_shares(&mut event, i).unwrap();
        }

        let output = event.output();
        assert_failure_output(output, &[context.peer_infos[INVALID_PEER_INDEX].peer_id]);
    }

    #[test]
    #[should_panic(expected = "Own comms should be set before output")]
    fn output_own_comms_not_set() {
        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            context.add_valid_components(&mut event, i).unwrap();
        }

        event.output();
    }

    #[test]
    fn detect_not_set_component_peers() {
        const NOT_SET_COMPONENT_PEER_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            if i as usize == NOT_SET_COMPONENT_PEER_INDEX {
                continue;
            }
            context.add_valid_components(&mut event, i).unwrap();
        }

        let output = event.output();
        assert_failure_output(
            output,
            &[context.peer_infos[NOT_SET_COMPONENT_PEER_INDEX].peer_id],
        );
    }

    #[test]
    fn detect_not_set_de_shares_peers() {
        const NOT_SET_DE_SHARES_PEER_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        event.set_status_to_verifying();
        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            context.add_valid_components(&mut event, i).unwrap();

            if i as usize != NOT_SET_DE_SHARES_PEER_INDEX {
                context.add_decrypted_shares(&mut event, i).unwrap();
            }
        }

        let output = event.output();
        assert_failure_output(
            output,
            &[context.peer_infos[NOT_SET_DE_SHARES_PEER_INDEX].peer_id],
        );
    }

    #[test]
    fn detect_malicious_report() {
        const MALICIOUS_REPORTER_INDEX: usize = 1;

        let context = TestContext::setup(NUM_PEERS);
        let mut event = context.create_event(OWN_INDEX_ZERO_BASE);

        context.set_own_components(&mut event, OWN_INDEX_ZERO_BASE);

        for i in 1..NUM_PEERS {
            context.add_valid_components(&mut event, i).unwrap();

            if i as usize == MALICIOUS_REPORTER_INDEX {
                context.add_reporter(&mut event, i).unwrap();
            } else {
                context.add_decrypted_shares(&mut event, i).unwrap();
            }
        }

        let output = event.output();
        assert_failure_output(
            output,
            &[context.peer_infos[MALICIOUS_REPORTER_INDEX].peer_id],
        );
    }
}
