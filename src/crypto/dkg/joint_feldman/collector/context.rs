use std::collections::{HashMap, HashSet};

use crate::crypto::{
    dkg::joint_feldman::peer_info::PeerInfo,
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::element::{Public, Secret},
        vss::{Shares, SharesError, Vss},
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Shares(#[from] SharesError),

    #[error("Keypair operation failed: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Share not found for peer with index {0}")]
    ShareNotFound(u16),

    #[error("Peer with ID {0} not found")]
    PeerNotFound(libp2p::PeerId),

    #[error("Event with ID {0} not found")]
    EventNotFound(String),
}

pub enum VerificationResult {
    AccusedFailed,
    PlaintiffFailed,
}

#[derive(Debug)]
#[derive(Default)]
pub struct Event {
    pairs: HashMap<u16, Shares>,
}

#[derive(Debug)]
pub struct Context {
    peers: HashMap<libp2p::PeerId, PeerInfo>,
    invalid_peers: HashSet<libp2p::PeerId>,
    secret_key: SecretKey,
    own_index: u16,
    events: HashMap<Vec<u8>, Event>,
}

impl Event {
    pub fn add_peer(&mut self, source_index: u16, shares: Shares) {
        self.pairs.insert(source_index, shares);
    }

    pub fn verify<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &self,
        accused_index: u16,
        plaintiff_index: u16,
        accused_raw_share: &[u8],
        plaintiff_public_key: &PublicKey,
    ) -> Result<VerificationResult> {
        let accused_share = self
            .pairs
            .get(&accused_index)
            .ok_or(Error::ShareNotFound(accused_index))?;

        let encrypted_share = match accused_share.shares.get(&plaintiff_index) {
            Some(share) => share,
            None => return Ok(VerificationResult::AccusedFailed),
        };

        if !is_share_matching(accused_raw_share, encrypted_share, plaintiff_public_key)? {
            return Ok(VerificationResult::AccusedFailed);
        }

        if verify_share_against_commitments::<SK, PK, V>(
            plaintiff_index,
            encrypted_share,
            &accused_share.commitments,
        ) {
            Ok(VerificationResult::PlaintiffFailed)
        } else {
            Ok(VerificationResult::AccusedFailed)
        }
    }

    pub fn share(&self, index: u16) -> Result<&Shares> {
        self.pairs.get(&index).ok_or(Error::ShareNotFound(index))
    }

    pub fn peer_count(&self) -> usize {
        self.pairs.len()
    }
}

fn is_share_matching(
    raw_share: &[u8],
    encrypted_share: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let expected_encrypted_share = public_key.encrypt(raw_share)?;
    Ok(encrypted_share == &expected_encrypted_share)
}

fn verify_share_against_commitments<SK: Secret, PK: Public, V: Vss<SK, PK>>(
    index: u16,
    encrypted_share: &[u8],
    commitments: &[Vec<u8>],
) -> bool {
    let share = SK::from_bytes(encrypted_share);
    let commitments: Vec<_> = commitments.iter().map(|c| PK::from_bytes(c)).collect();

    V::verify(&index, &share, &commitments)
}

impl Context {
    pub fn new(
        peers: HashMap<libp2p::PeerId, PeerInfo>,
        secret_key: SecretKey,
        own_peer: libp2p::PeerId,
    ) -> Self {
        let own_index = peers
            .get(&own_peer)
            .expect("Own peer not found in the list")
            .index;

        Self {
            peers,
            invalid_peers: HashSet::new(),
            secret_key,
            own_index,
            events: HashMap::new(),
        }
    }

    pub fn add_event<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &mut self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        shares: Shares,
    ) -> Result<()> {
        if self.invalid_peers.contains(&source) || !self.peers.contains_key(&source) {
            return Ok(());
        }

        if shares.verify::<SK, PK, V>(&self.own_index, &self.secret_key)? {
            let index = self
                .peer_index(source)
                .expect("unrechable: index not found");
            let event = self.events.entry(id).or_default();
            event.add_peer(index, shares);
        } else {
            self.invalid_peers.insert(source);
        }

        Ok(())
    }

    fn peer_index(&self, peer_id: libp2p::PeerId) -> Result<u16> {
        self.peers
            .get(&peer_id)
            .map(|peer| peer.index)
            .ok_or(Error::PeerNotFound(peer_id))
    }

    pub fn verify<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &self,
        id: Vec<u8>,
        accused_peer: libp2p::PeerId,
        plaintiff_peer: libp2p::PeerId,
        accused_raw_share: &[u8],
    ) -> Result<VerificationResult> {
        let accused_index = self.peer_index(accused_peer)?;
        let plaintiff_index = self.peer_index(plaintiff_peer)?;
        let plaintiff_public_key = self.peer_public_key(&plaintiff_peer)?;
        let event = self.events.get(&id).ok_or(Error::EventNotFound(
            String::from_utf8_lossy(&id).to_string(),
        ))?;

        event.verify::<SK, PK, V>(
            accused_index,
            plaintiff_index,
            accused_raw_share,
            plaintiff_public_key,
        )
    }

    fn peer_public_key(&self, peer: &libp2p::PeerId) -> Result<&PublicKey> {
        self.peers
            .get(peer)
            .map(|peer_info| &peer_info.public_key)
            .ok_or(Error::PeerNotFound(*peer))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{dkg::joint_feldman::collector::context::Event, primitives::vss::Shares};

    #[test]
    fn length_up() {
        const NUMS: usize = 10;

        let mut event = Event::default();
        for i in 0..NUMS {
            event.add_peer(i as u16, Shares::empty());
            assert_eq!(event.pairs.len(), i + 1);
        }
    }
}
