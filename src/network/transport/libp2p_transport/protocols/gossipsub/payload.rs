use libp2p::gossipsub::MessageId;
use serde::{Deserialize, Serialize};

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
    Raw(Vec<u8>), // For testing
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
}

impl TryFrom<Payload> for Vec<u8> {
    type Error = String;

    fn try_from(payload: Payload) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&payload).map_err(|e| e.to_string())
    }
}

impl TryInto<Payload> for Vec<u8> {
    type Error = String;

    fn try_into(self) -> Result<Payload, Self::Error> {
        serde_json::from_slice(&self).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use libp2p::gossipsub::MessageId;

    use crate::{
        crypto::vrf::dvrf::proof::Proof, network::transport::libp2p_transport::protocols::gossipsub::Payload,
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
