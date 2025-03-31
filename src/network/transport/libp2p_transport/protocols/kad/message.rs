use serde::{Deserialize, Serialize};

use crate::{crypto::dkg::Data, network::transport::libp2p_transport::protocols::kad::Payload};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Message {
    payload: Payload,
    signature: Data,
}

impl Message {
    pub fn new(payload: Payload, signature: Data) -> Self {
        Self { payload, signature }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::dkg::classic::signature::SignatureBytes;

    use super::*;

    const PAYLOAD: &[u8] = &[1, 2, 3];

    fn create_payload() -> Payload {
        Payload::Raw(PAYLOAD.to_vec())
    }

    #[test]
    fn test_new() {
        let payload = create_payload();
        let signature = SignatureBytes::random();
        let data = Data::Classic(signature);

        let result = Message::new(payload.clone(), data.clone());

        assert_eq!(result.payload, payload);
        assert_eq!(result.signature, data);
    }
}
