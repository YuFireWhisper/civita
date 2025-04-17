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
    own_index_one_base: u16,
    own_shares: Vec<Scalar>,
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

    fn is_complete(&self) -> bool {
        self.en_shares.is_some() && self.de_shares.is_some() && self.comms.is_some()
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
            own_index_one_base,
            own_shares: Vec::new(),
            own_de_shares: None,
            is_reported: false,
            secret_key,
            status: Status::Pending,
        }
    }

    pub fn set_own_de_shares(&mut self, de_shares: DecryptedShares) -> ActionNeeded {
        if self.is_verifying() && !self.is_reported {
            self.is_reported = true;
            return ActionNeeded::Report(de_shares);
        }

        self.own_de_shares = Some(de_shares);

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
    ) -> Result<std::result::Result<(), ()>> {
        let encrypted_share = match encrypted_shares.get(&self.own_index_one_base) {
            Some(share) => share,
            None => return Ok(Err(())),
        };

        let decrypted_share = match encrypted_share.to_scalar(&self.secret_key) {
            Ok(share) => share,
            Err(_) => return Ok(Err(())),
        };

        if !self.verify_share(&decrypted_share, commitments)? {
            return Ok(Err(()));
        }

        self.own_shares.push(decrypted_share);
        Ok(Ok(()))
    }

    fn handle_invalid_peer(&mut self, peer_id: libp2p::PeerId) -> ActionNeeded {
        self.set_status_to_verifying();
        self.invalid_peers.insert(peer_id);
        self.peer_infos.remove(&peer_id);

        if !self.is_reported {
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
        }

        Ok(self.handle_invalid_peer(peer_id))
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

            if peer_info.is_got_invalid() {
                all_invalid_peers.insert(*reporter);
            }
        }
    }
}
