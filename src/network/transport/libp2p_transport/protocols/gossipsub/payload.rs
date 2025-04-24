use std::collections::HashSet;

use libp2p::gossipsub::MessageId;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    index_map::IndexedMap,
    keypair::PublicKey,
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
    VrfRequest,

    VrfProof {
        message_id: MessageId,
        public_key: Vec<u8>,
        proof: Vec<u8>,
    },

    VrfConsensus {
        message_id: MessageId,
        random: [u8; 32],
    },

    VrfProcessFailure(MessageId),

    DkgVSS(Vec<u8>),

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
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
        signature: Option<Signature>,
    },

    CommitteeGenerateSuccess {
        request_hash: Vec<u8>,
        committee_pub_key: Point,
    },

    CommitteeGenerateFailure {
        request_hash: Vec<u8>,
        invalid_peers: HashSet<libp2p::PeerId>,
    },

    CommitteeChange {
        members: IndexedMap<libp2p::PeerId, PublicKey>,
        new_public_key: Point,
        signature: Option<Signature>,
    },

    // For testing
    Raw(Vec<u8>),

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
            _ => None,
        }
    }

    pub fn is_need_committee_signature(&self) -> bool {
        matches!(
            self,
            Payload::CommitteeCandiates { .. } | Payload::CommitteeChange { .. }
        )
    }

    pub fn set_signature(&mut self, sig: Signature) {
        match self {
            Payload::CommitteeCandiates { signature, .. } => *signature = Some(sig),
            Payload::CommitteeChange { signature, .. } => *signature = Some(sig),
            _ => {}
        }
    }

    pub fn create_vrf_proof(message_id: MessageId, public_key: Vec<u8>, proof: Vec<u8>) -> Payload {
        Payload::VrfProof {
            message_id,
            public_key,
            proof,
        }
    }

    pub fn create_vrf_consensus(message_id: MessageId, random: [u8; 32]) -> Payload {
        Payload::VrfConsensus { message_id, random }
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
    use libp2p::gossipsub::MessageId;

    use crate::{
        crypto::{
            index_map::IndexedMap,
            primitives::algebra::{Point, Scalar},
            tss::{schnorr::signature::Signature as SchnorrSignature, Signature},
        },
        network::transport::libp2p_transport::protocols::gossipsub::Payload,
    };

    const MESSAGE_ID: &str = "MESSAGE_ID";
    const RANDOM: [u8; 32] = [1; 32];

    fn create_message_id() -> MessageId {
        MessageId::from(MESSAGE_ID)
    }

    fn create_signature() -> Signature {
        Signature::Schnorr(SchnorrSignature::new(
            Scalar::secp256k1_zero(),
            Point::secp256k1_zero(),
        ))
    }

    #[test]
    fn field_should_be_none() {
        let mut payload = Payload::CommitteeCandiates {
            candidates: IndexedMap::new(),
            signature: Some(create_signature()),
        };
        payload.take_signature();

        let expected = Payload::CommitteeCandiates {
            candidates: IndexedMap::new(),
            signature: None,
        };

        assert_eq!(payload, expected);
    }

    #[test]
    fn return_true_if_have_signature_field() {
        let payload = Payload::CommitteeCandiates {
            candidates: IndexedMap::new(),
            signature: Some(create_signature()),
        };
        assert!(payload.is_need_committee_signature());
    }

    #[test]
    fn test_create_vrf_consensus() {
        let message_id = create_message_id();
        let expected = Payload::VrfConsensus {
            message_id: message_id.clone(),
            random: RANDOM,
        };

        let result = Payload::create_vrf_consensus(message_id, RANDOM);

        assert_eq!(
            result, expected,
            "Expected: {:?}, got: {:?}",
            expected, result
        );
    }
}
