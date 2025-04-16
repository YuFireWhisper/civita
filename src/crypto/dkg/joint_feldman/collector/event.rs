use std::collections::{HashMap, HashSet};

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
    Report,
    None,
}

#[derive(Debug)]
struct PeerInfo<'a> {
    en_shares: Option<EncryptedShares>,
    de_shares: Option<DecryptedShares>,
    comms: Option<Vec<Point>>,
    pk: &'a PublicKey,
    got_invalid: bool,
}

#[derive(Debug)]
#[derive(PartialEq, Eq)]
enum Status {
    Pending,
    Verifying(HashSet<libp2p::PeerId>), // Reporter peer ids
}

#[derive(Debug)]
pub struct Event<'a> {
    peers: HashMap<libp2p::PeerId, PeerInfo<'a>>,
    peer_registry: &'a PeerRegistry,
    invalid_peers: HashSet<libp2p::PeerId>,
    own_index_one_base: u16,
    own_shares: Vec<Scalar>,
    secret_key: &'a SecretKey,
    status: Status,
}

impl<'a> PeerInfo<'a> {
    pub fn set_en_shares_and_comms(
        &mut self,
        en_shares: EncryptedShares,
        comms: Vec<Point>,
    ) -> Result<Option<Vec<u16>>> {
        self.en_shares = Some(en_shares);
        self.comms = Some(comms);

        if self.is_complete() {
            self.verify()
        } else {
            Ok(None)
        }
    }

    fn verify(&self) -> Result<Option<Vec<u16>>> {
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
        let public_key = self.pk;

        let mut invalid_indices = Vec::new();
        for (index, en_share) in en_shares.iter() {
            let de_share = match de_shares.get(&index) {
                Some(de_share) => de_share,
                None => {
                    invalid_indices.push(index);
                    continue;
                }
            };

            Self::verify_de_to_en(de_share, en_share, public_key)?;
            if !de_share.verify(index, comms)? {
                invalid_indices.push(index);
            }
        }

        return if invalid_indices.is_empty() {
            Ok(None)
        } else {
            Ok(Some(invalid_indices))
        };
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

    pub fn set_de_shares(&mut self, de_shares: DecryptedShares) -> Result<Option<Vec<u16>>> {
        self.de_shares = Some(de_shares);

        if self.is_complete() {
            self.verify()
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

impl<'a> Event<'a> {
    pub fn new(
        peer_registry: &'a PeerRegistry,
        secret_key: &'a SecretKey,
        own_peer: libp2p::PeerId,
    ) -> Self {
        let own_index_one_base = peer_registry
            .get_index(&own_peer)
            .expect("Own peer should be in the registry");

        Self {
            peers: peer_registry.into(),
            peer_registry,
            invalid_peers: HashSet::new(),
            own_index_one_base,
            own_shares: Vec::new(),
            secret_key,
            status: Status::Pending,
        }
    }

    pub fn set_status_to_verifying(&mut self) {
        if self.status == Status::Pending {
            self.status = Status::Verifying(HashSet::new());
        }
    }

    pub fn set_en_shares_and_comms(
        &mut self,
        peer_id: libp2p::PeerId,
        en_shares: EncryptedShares,
        comms: Vec<Point>,
    ) -> Result<ActionNeeded> {
        if !self.peers.contains_key(&peer_id) {
            return Ok(ActionNeeded::None);
        }

        if self.process_own_share(&en_shares, &comms).is_err() {
            self.invalid_peers.insert(peer_id);
            self.peers.remove(&peer_id);
            return Ok(self.check_if_reporting_needed());
        }

        let indices = {
            let peer_info = self
                .peers
                .get_mut(&peer_id)
                .ok_or(Error::PeerNotFound(peer_id))?;
            peer_info.set_en_shares_and_comms(en_shares, comms)?
        };

        if let Some(indices) = indices {
            self.mark_peers_by_indices(&indices);
            self.invalid_peers.insert(peer_id);
            self.peers.remove(&peer_id);
            return Ok(self.check_if_reporting_needed());
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

        let decrypted_share = match encrypted_share.to_scalar(self.secret_key) {
            Ok(share) => share,
            Err(_) => return Ok(Err(())),
        };

        if !self.verify_share(&decrypted_share, commitments)? {
            return Ok(Err(()));
        }

        self.own_shares.push(decrypted_share);
        Ok(Ok(()))
    }

    fn check_if_reporting_needed(&mut self) -> ActionNeeded {
        if self.status == Status::Pending {
            self.set_status_to_verifying();
            ActionNeeded::Report
        } else {
            ActionNeeded::None
        }
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
                .peers
                .get_mut(&peer_id)
                .expect("unreachable: PeerInfo not found");
            peer_info.set_got_invalid();
        });
    }

    pub fn set_reporter(
        &mut self,
        reporter: libp2p::PeerId,
        de_shares: DecryptedShares,
    ) -> Result<()> {
        match self.status {
            Status::Pending => {
                let mut reporters = HashSet::new();
                reporters.insert(reporter);
                self.status = Status::Verifying(reporters);
            }
            Status::Verifying(ref mut reporters) => {
                reporters.insert(reporter);
            }
        }

        self.set_decrypted_shares(reporter, de_shares)?;

        Ok(())
    }

    pub fn set_decrypted_shares(
        &mut self,
        peer_id: libp2p::PeerId,
        de_shares: DecryptedShares,
    ) -> Result<()> {
        let indices = {
            let peer_info = self
                .peers
                .get_mut(&peer_id)
                .ok_or(Error::PeerNotFound(peer_id))?;
            peer_info.set_de_shares(de_shares.clone())?
        };

        if let Some(indices) = indices {
            self.mark_peers_by_indices(&indices);
            self.invalid_peers.insert(peer_id);
            self.peers.remove(&peer_id);
        }

        Ok(())
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
            for (peer_id, peer_info) in &self.peers {
                if let Some(peer_comms) = &peer_info.comms {
                    comms.insert(*peer_id, peer_comms.clone());
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
                .peers
                .get(reporter)
                .expect("unreachable: PeerInfo not found");

            if peer_info.is_got_invalid() {
                all_invalid_peers.insert(*reporter);
            }
        }
    }
}

impl<'a> From<&'a PeerRegistry> for HashMap<libp2p::PeerId, PeerInfo<'a>> {
    fn from(peers: &'a PeerRegistry) -> Self {
        let mut peer_map = HashMap::new();
        for (peer_id, public_key) in peers.iter_peer_keys() {
            peer_map.insert(
                peer_id,
                PeerInfo {
                    en_shares: None,
                    de_shares: None,
                    comms: None,
                    pk: public_key,
                    got_invalid: false,
                },
            );
        }
        peer_map
    }
}
