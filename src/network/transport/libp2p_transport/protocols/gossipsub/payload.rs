use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    index_map::IndexedMap,
    keypair::{PublicKey, VrfProof},
    primitives::{
        algebra::{Point, Scalar},
        vss::{encrypted_share::EncryptedShares, DecryptedShares},
    },
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    VSSComponent {
        id: Vec<u8>,
        encrypted_shares: EncryptedShares,
        commitments: Vec<Point>,
    },

    VSSReport {
        id: Vec<u8>,
        decrypted_shares: DecryptedShares,
    },

    VSSReportResponse {
        id: Vec<u8>,
        decrypted_shares: DecryptedShares,
    },

    TssNonceShare {
        id: Vec<u8>,
        share: Scalar,
    },

    TssSignatureShare {
        id: Vec<u8>,
        share: Scalar,
    },

    CommitteeCandiates {
        count: u32,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    },

    CommitteeGenerateSuccess {
        request_hash: [u8; 32],
        committee_pub_key: Point,
    },

    CommitteeGenerateFailure {
        request_hash: [u8; 32],
        invalid_peers: HashSet<libp2p::PeerId>,
    },

    CommitteeChange {
        epoch: u64,
        members: IndexedMap<libp2p::PeerId, PublicKey>,
        public_key: Point,
    },

    CommitteeElection {
        seed: [u8; 32],
    },

    CommitteeElectionResponse {
        seed: [u8; 32],
        public_key: PublicKey,
        proof: VrfProof,
    },

    // For testing
    Raw(Vec<u8>),

    // For testing
    RawWithSignature {
        raw: Vec<u8>,
    },
}

impl Payload {
    pub fn require_committee_signature(&self) -> bool {
        match self {
            // Need
            Payload::CommitteeChange { .. } => true,
            Payload::CommitteeElection { .. } => true,
            Payload::RawWithSignature { .. } => true,

            // Don't need
            Payload::VSSComponent { .. } => false,
            Payload::VSSReport { .. } => false,
            Payload::VSSReportResponse { .. } => false,
            Payload::TssNonceShare { .. } => false,
            Payload::TssSignatureShare { .. } => false,
            Payload::CommitteeCandiates { .. } => true,
            Payload::CommitteeGenerateSuccess { .. } => false,
            Payload::CommitteeGenerateFailure { .. } => false,
            Payload::CommitteeElectionResponse { .. } => false,
            Payload::Raw(_) => false,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.try_into()
    }
}

impl TryFrom<&Payload> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Payload) -> Result<Self, Self::Error> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<Vec<u8>> for Payload {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(&value, bincode::config::standard())
            .map(|(p, _)| p)
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {}
