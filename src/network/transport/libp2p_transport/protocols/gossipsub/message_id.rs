use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::Xxh3;

use crate::identity::resident_id::ResidentId;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Encode, Decode)]
#[derive(PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
pub struct MessageId(u64);

impl MessageId {
    pub fn new(resident: ResidentId, sequence_number: u64) -> Self {
        let mut hasher = Xxh3::new();
        hasher.update(resident.as_bytes());
        hasher.update(&sequence_number.to_le_bytes());

        Self(hasher.digest())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        identity::resident_id::ResidentId,
        network::transport::libp2p_transport::protocols::gossipsub::message_id::MessageId,
    };

    #[test]
    fn id_should_not_equal() {
        let resident1 = ResidentId::random();
        let resident2 = ResidentId::random();

        let message_id1 = MessageId::new(resident1, 1);
        let message_id2 = MessageId::new(resident2, 1);

        assert_ne!(message_id1, message_id2);
    }
}
