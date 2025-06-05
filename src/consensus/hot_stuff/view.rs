use std::collections::HashSet;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

use crate::{
    consensus::THRESHOLD_MEMBERS,
    constants::HashArray,
    crypto::keypair::{PublicKey, ResidentSignature},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to deserialize View: {0}")]
    Deserialize(#[from] bincode::error::DecodeError),
}

#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum State {
    Prepare,
    PreCommit,
    Commit,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub public_key: PublicKey,
    pub signature: ResidentSignature,
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct View {
    pub number: u64,
    pub leader: PeerId,
    pub timeout: Duration,

    pub proposals: HashSet<Vec<u8>>,
    pub root_hash: HashArray,
    pub parent_ref: HashArray,

    #[serde(serialize_with = "serialize_qcs", deserialize_with = "deserialize_qcs")]
    pub qcs: [QuorumCertificate; THRESHOLD_MEMBERS],
    pub state: State,
    pub height: u64,
}

impl QuorumCertificate {
    #[cfg(test)]
    pub fn random() -> Self {
        use crate::crypto::keypair;

        const MSG: &[u8] = b"test message";

        let (sk, pk) = keypair::generate_keypair(keypair::KeyType::Secp256k1);

        Self {
            public_key: pk,
            signature: sk.sign(MSG).expect("Failed to sign message"),
        }
    }
}

impl View {
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("Failed to serialize View")
    }
}

fn serialize_qcs<S>(
    qcs: &[QuorumCertificate; THRESHOLD_MEMBERS],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    qcs.serialize(serializer)
}

fn deserialize_qcs<'de, D>(
    deserializer: D,
) -> std::result::Result<[QuorumCertificate; THRESHOLD_MEMBERS], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vec = Vec::<QuorumCertificate>::deserialize(deserializer)?;

    if vec.len() != THRESHOLD_MEMBERS {
        return Err(serde::de::Error::custom(format!(
            "Expected {} elements, got {}",
            THRESHOLD_MEMBERS,
            vec.len()
        )));
    }

    vec.try_into()
        .map_err(|_| serde::de::Error::custom("Failed to convert to array"))
}

impl From<View> for Vec<u8> {
    fn from(view: View) -> Self {
        (&view).into()
    }
}

impl From<&View> for Vec<u8> {
    fn from(view: &View) -> Self {
        bincode::serde::encode_to_vec(view, bincode::config::standard())
            .expect("Failed to serialize View")
    }
}

impl TryFrom<Vec<u8>> for View {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for View {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(d, _)| d)
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_serialization() {
        let view = View {
            number: 1,
            leader: PeerId::random(),
            timeout: Duration::from_secs(5),
            proposals: HashSet::from([vec![1, 2, 3]]),
            root_hash: HashArray::from([3; 32]),
            parent_ref: HashArray::from([2; 32]),
            qcs: std::array::from_fn::<_, THRESHOLD_MEMBERS, _>(|_| QuorumCertificate::random()),
            state: State::Prepare,
            height: 1,
        };

        let serialized = view.to_bytes();
        let deserialized: View = serialized.try_into().expect("Failed to deserialize View");

        assert_eq!(view.number, deserialized.number);
        assert_eq!(view.leader, deserialized.leader);
        assert_eq!(view.timeout, deserialized.timeout);

        assert_eq!(view.proposals, deserialized.proposals);
        assert_eq!(view.root_hash, deserialized.root_hash);
        assert_eq!(view.parent_ref, deserialized.parent_ref);

        assert_eq!(view.qcs, deserialized.qcs);
        assert_eq!(view.state, deserialized.state);
        assert_eq!(view.height, deserialized.height);
    }
}
