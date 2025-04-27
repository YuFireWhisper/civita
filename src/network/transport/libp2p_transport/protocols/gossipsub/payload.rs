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

    CommitteeCandidates {
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
            Payload::CommitteeCandidates { .. } => true,
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
mod tests {
    use crate::network::transport::libp2p_transport::protocols::gossipsub::Payload;

    #[test]
    fn success_convert_with_vec() {
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let payload = Payload::Raw(PAYLOAD.to_vec());
        let payload_vec = payload.to_vec().unwrap();
        let payload_from_vec = Payload::try_from(payload_vec).unwrap();

        assert_eq!(payload, payload_from_vec);
    }

    #[test]
    fn returns_true_when_committee_signature_required() {
        let payload = Payload::RawWithSignature { raw: vec![] };

        assert!(
            payload.require_committee_signature(),
            "Expected payload to require committee signature"
        );
    }

    #[test]
    fn returns_false_when_committee_signature_not_required() {
        let payload = Payload::Raw(vec![]);

        assert!(
            !payload.require_committee_signature(),
            "Expected payload to not require committee signature"
        );
    }

    #[test]
    fn error_when_decoding_invalid_payload() {
        let invalid_payload = vec![0, 1, 2, 3, 4];

        let result = Payload::try_from(invalid_payload);

        assert!(
            result.is_err(),
            "Expected error when decoding invalid payload"
        );
    }
}
