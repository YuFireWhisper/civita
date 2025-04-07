use std::collections::HashSet;

use libp2p::{gossipsub::MessageId, PeerId};
use serde::{Deserialize, Serialize};

use crate::{crypto::dkg::Data, network::transport::libp2p_transport::protocols::kad};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

    // Raw message, for other node checks
    DkgSign(Vec<u8>),

    // Signature object
    DkgSignResponse(Vec<u8>),

    // Signature object
    DkgSignFinal(Vec<u8>),

    CommitteeSignatureRequest(kad::Payload),

    CommitteeSignatureResponse {
        request_msg_id: MessageId,
        partial_sig: Data,
    },

    CommitteeChange {
        new_members: HashSet<PeerId>,
        new_committee_pub_key: Vec<u8>,
        signature: Data,
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

    use crate::{
        crypto::vrf::dvrf::proof::Proof,
        network::transport::libp2p_transport::protocols::gossipsub::Payload,
    };

    const MESSAGE_ID: &str = "MESSAGE_ID";
    const PUBLIC_KEY: &[u8] = b"PUBLIC_KEY";
    const PROOF: &[u8] = b"PROOF";
    const OUTPUT: &[u8] = b"OUTPUT";
    const RANDOM: [u8; 32] = [1; 32];

    fn create_message_id() -> MessageId {
        MessageId::from(MESSAGE_ID)
    }

    fn create_public_key() -> Vec<u8> {
        PUBLIC_KEY.to_vec()
    }

    fn create_proof() -> Proof {
        Proof::new(OUTPUT.to_vec(), PROOF.to_vec())
    }

    #[test]
    fn test_create_vrf_proof() {
        let message_id = create_message_id();
        let public_key = create_public_key();
        let proof = create_proof().proof().to_vec();
        let expected = Payload::VrfProof {
            message_id: message_id.clone(),
            public_key: public_key.clone(),
            proof: proof.clone(),
        };

        let result =
            Payload::create_vrf_proof(message_id.clone(), public_key.clone(), proof.clone());

        assert_eq!(
            result, expected,
            "Expected: {:?}, got: {:?}",
            expected, result
        );
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
