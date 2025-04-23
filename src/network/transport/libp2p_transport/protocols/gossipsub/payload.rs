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
        signature: Signature,
    },

    CommitteeGenerateSuccess {
        candidates_hash: Vec<u8>,
        committee_pub_key: Point,
        signature: Signature,
    },

    CommitteeGenerateFailure {
        candidates_hash: Vec<u8>,
        invalid_peers: HashSet<libp2p::PeerId>,
    },

    // For testing
    Raw(Vec<u8>),
}

impl Payload {
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

    pub fn to_vec(self) -> Result<Vec<u8>, serde_json::Error> {
        self.try_into()
    }
}

impl TryInto<Vec<u8>> for Payload {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for Payload {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::gossipsub::MessageId;

    use crate::network::transport::libp2p_transport::protocols::gossipsub::Payload;

    const MESSAGE_ID: &str = "MESSAGE_ID";
    const RANDOM: [u8; 32] = [1; 32];

    fn create_message_id() -> MessageId {
        MessageId::from(MESSAGE_ID)
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
