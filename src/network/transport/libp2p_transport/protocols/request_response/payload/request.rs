use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{
    extract_variant,
    network::transport::libp2p_transport::{
        message::Message, protocols::request_response::Payload,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    DkgScalar(Vec<u8>),
    Raw(Vec<u8>), // For testing
}

impl Request {
    pub fn get_dkg_scalar(msg: Message) -> Option<(PeerId, Vec<u8>)> {
        extract_variant!(
            msg,
            Message::RequestResponse(req_resp_msg) => &req_resp_msg.payload,
            Payload::Request(Request::DkgScalar(v)) => (req_resp_msg.peer, v.clone())
        )
    }
}

impl TryInto<Vec<u8>> for Request {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for Request {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;

    use crate::network::transport::libp2p_transport::{
        message::Message,
        protocols::request_response::{self, payload::Request},
    };

    const MESSAGE: &str = "MESSAGE";

    fn create_network_msg(msg: request_response::Message) -> Message {
        Message::RequestResponse(msg)
    }

    fn create_req_resp_msg(
        peer: PeerId,
        payload: request_response::Payload,
    ) -> request_response::Message {
        request_response::Message { peer, payload }
    }

    fn create_req_resp_payload() -> request_response::Payload {
        let req = Request::DkgScalar(MESSAGE.as_bytes().to_vec());
        request_response::Payload::Request(req)
    }

    #[test]
    fn returns_vec_for_dkg_share() {
        let payload = create_req_resp_payload();
        let peer = PeerId::random();
        let req_resp_msg = create_req_resp_msg(peer, payload);
        let network_msg = create_network_msg(req_resp_msg);

        let result = Request::get_dkg_scalar(network_msg);

        assert_eq!(result, Some((peer, MESSAGE.as_bytes().to_vec())));
    }
}
