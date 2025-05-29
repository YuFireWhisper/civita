use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};

use libp2p::gossipsub::MessageId;
use serde::{Deserialize, Serialize};

use crate::{
    constants::HashArray,
    crypto::{
        algebra::{Point, Scalar},
        keypair::{PublicKey, ResidentSignature, VrfProof},
        vss::{encrypted_share::EncryptedShares, DecryptedShares},
    },
    network::transport::store::merkle_dag::KeyArray,
    resident::Record,
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

    ElectionEligibilityProof {
        proof: VrfProof,
        public_key: PublicKey,
        payload_hash: [u8; 32],
    },

    ElectionFailure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },

    ConsensusTime {
        end_time: SystemTime,
    },

    ConsensusTimeResponse {
        end_time: SystemTime,
        is_accepted: bool,
    },

    QueryCommitteeState,

    QueryCommitteeStateResponse {
        message_id: MessageId,
        state: Vec<u8>,
    },

    Proposal(Vec<u8>),

    ProposalProcessingComplete {
        final_node: Vec<u8>,
        total_stakes_impact: i32,
        processed: HashSet<HashArray>,
        next: Vec<(KeyArray, Record)>,
        proofs: HashMap<PublicKey, (VrfProof, ResidentSignature)>,
    },

    ConsensusCandidate {
        public_key: PublicKey,
        proof: VrfProof,
        signature: ResidentSignature,
    },

    // For testing
    Raw(Vec<u8>),

    // For testing
    RawWithSignature {
        raw: Vec<u8>,
    },
}

impl Payload {
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.try_into()
    }

    pub fn require_signature(&self) -> bool {
        matches!(self, Payload::RawWithSignature { .. })
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
    use crate::network::transport::protocols::gossipsub::Payload;

    #[test]
    fn success_convert_with_vec() {
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let payload = Payload::Raw(PAYLOAD.to_vec());
        let payload_vec = payload.to_vec().unwrap();
        let payload_from_vec = Payload::try_from(payload_vec).unwrap();

        assert_eq!(payload, payload_from_vec);
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
