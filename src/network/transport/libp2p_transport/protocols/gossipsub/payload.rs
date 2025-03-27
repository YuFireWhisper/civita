use libp2p::{gossipsub::MessageId, PeerId};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::dkg::classic::signer::Signature, extract_variant,
    network::transport::libp2p_transport::message::Message,
};

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
    DkgSignResponse(Signature),
    DkgSignFinal(Signature),
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

    pub fn get_dkg_vss(msg: Message) -> Option<(PeerId, Vec<u8>)> {
        extract_variant!(
            msg,
            Message::Gossipsub(gossipsub_msg) => gossipsub_msg.payload,
            Payload::DkgVSS(v) => (gossipsub_msg.source, v)
        )
    }

    pub fn get_dkg_sign(msg: Message) -> Option<(MessageId, PeerId, Vec<u8>)> {
        extract_variant!(
            msg,
            Message::Gossipsub(gossipsub_msg) => gossipsub_msg.payload,
            Payload::DkgSign(v) => (gossipsub_msg.message_id, gossipsub_msg.source, v)
        )
    }

    pub fn get_dkg_sign_response(msg: Message) -> Option<(PeerId, Signature)> {
        extract_variant!(
            msg,
            Message::Gossipsub(gossipsub_msg) => gossipsub_msg.payload,
            Payload::DkgSignResponse(v) => (gossipsub_msg.source, v)
        )
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
        network::transport::libp2p_transport::{
            message::Message,
            protocols::gossipsub::{self, message::mock_message::create_message, Payload},
        },
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

    fn create_network_msg(msg: gossipsub::Message) -> Message {
        Message::Gossipsub(msg)
    }

    fn create_gossipsub_msg(payload: Payload) -> gossipsub::Message {
        let mut msg = create_message();
        msg.payload = payload;
        msg
    }

    fn create_dkg_vss_payload() -> Payload {
        Payload::DkgVSS(OUTPUT.to_vec())
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

    #[test]
    fn return_vec_for_dkg_vss() {
        let payload = create_dkg_vss_payload();
        let gossipsub_msg = create_gossipsub_msg(payload);
        let peer = gossipsub_msg.source;
        let network_msg = create_network_msg(gossipsub_msg);

        let result = Payload::get_dkg_vss(network_msg);

        assert_eq!(result, Some((peer, OUTPUT.to_vec())));
    }
}
