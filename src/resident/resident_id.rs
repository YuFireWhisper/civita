use std::str::FromStr;

use libp2p::PeerId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResidentId(pub PeerId);

impl ResidentId {
    pub fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    pub fn random() -> Self {
        Self(PeerId::random())
    }
}

impl Serialize for ResidentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let peer_id_string = self.0.to_string();
        serializer.serialize_str(&peer_id_string)
    }
}

impl<'de> Deserialize<'de> for ResidentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let peer_id_string = String::deserialize(deserializer)?;
        let peer_id = PeerId::from_str(&peer_id_string)
            .map_err(|e| serde::de::Error::custom(format!("Invalid PeerId string: {}", e)))?;

        Ok(ResidentId(peer_id))
    }
}

#[cfg(test)]
mod tests {
    use crate::resident::resident_id::ResidentId;
    use libp2p::PeerId;
    use serde_json;
    use std::collections::HashSet;

    #[test]
    fn test_new() {
        let peer_id = PeerId::random();
        let resident_id = ResidentId::new(peer_id);
        assert_eq!(resident_id.0, peer_id, "ResidentId should store the PeerId");
    }

    #[test]
    fn test_random() {
        const NUM_IDS: usize = 10;

        let mut resident_ids = HashSet::new();
        for _ in 0..NUM_IDS {
            resident_ids.insert(ResidentId::random());
        }

        assert_eq!(
            resident_ids.len(),
            NUM_IDS,
            "ResidentId::random() should generate unique IDs"
        );
    }

    #[test]
    fn test_serialize_deserialize() {
        let original = ResidentId::random();

        let serialized = serde_json::to_string(&original).expect("Failed to serialize ResidentId");

        let deserialized: ResidentId =
            serde_json::from_str(&serialized).expect("Failed to deserialize ResidentId");

        assert_eq!(
            original, deserialized,
            "Deserialized value should equal original"
        );
    }
}
