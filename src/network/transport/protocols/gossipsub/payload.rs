use std::{collections::HashSet, time::SystemTime};

use serde::{Deserialize, Serialize};

use crate::{
    committee,
    crypto::{
        algebra::{Point, Scalar},
        keypair::{PublicKey, VrfProof},
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

    ElectionEligibilityProof {
        proof: VrfProof,
        public_key: PublicKey,
        payload_hash: [u8; 32],
    },

    ElectionSuccess {
        info: committee::Info,
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
