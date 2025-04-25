use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    index_map::IndexedMap,
    keypair::{PublicKey, VrfProof},
    primitives::{
        algebra::{Point, Scalar},
        vss::{encrypted_share::EncryptedShares, DecryptedShares},
    },
    tss::Signature,
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
        signature: Option<Signature>,
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
        signature: Option<Signature>,
    },

    CommitteeElection {
        seed: [u8; 32],
        signature: Option<Signature>,
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
        signature: Option<Signature>,
    },
}

impl Payload {
    pub fn take_signature(&mut self) -> Option<Signature> {
        match self {
            Payload::CommitteeCandiates { signature, .. } => signature.take(),
            Payload::CommitteeChange { signature, .. } => signature.take(),
            Payload::CommitteeElection { signature, .. } => signature.take(),
            Payload::RawWithSignature { signature, .. } => signature.take(),
            _ => None,
        }
    }

    pub fn need_signature(&self) -> bool {
        matches!(
            self,
            Payload::CommitteeCandiates { .. }
                | Payload::CommitteeChange { .. }
                | Payload::CommitteeElection { .. }
                | Payload::RawWithSignature { .. }
        )
    }

    pub fn set_signature(&mut self, sig: Signature) {
        match self {
            Payload::CommitteeCandiates { signature, .. } => *signature = Some(sig),
            Payload::CommitteeChange { signature, .. } => *signature = Some(sig),
            Payload::CommitteeElection { signature, .. } => *signature = Some(sig),
            _ => {}
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
mod tests {
    use crate::{
        crypto::{
            index_map::IndexedMap,
            primitives::algebra::{Point, Scalar},
            tss::{schnorr::signature::Signature as SchnorrSignature, Signature},
        },
        network::transport::libp2p_transport::protocols::gossipsub::Payload,
    };

    fn create_signature() -> Signature {
        Signature::Schnorr(SchnorrSignature::new(
            Scalar::secp256k1_zero(),
            Point::secp256k1_zero(),
        ))
    }

    #[test]
    fn field_should_be_none() {
        let mut payload = Payload::RawWithSignature {
            raw: vec![],
            signature: Some(create_signature()),
        };
        payload.take_signature();

        let expected = Payload::RawWithSignature {
            raw: vec![],
            signature: None,
        };

        assert_eq!(payload, expected);
    }

    #[test]
    fn return_true_if_have_signature_field() {
        let payload = Payload::CommitteeCandiates {
            count: 0,
            candidates: IndexedMap::new(),
            signature: Some(create_signature()),
        };
        assert!(payload.need_signature());
    }
}
