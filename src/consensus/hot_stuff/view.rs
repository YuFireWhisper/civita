use std::collections::HashSet;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

use crate::{
    constants::HashArray,
    crypto::keypair::{PublicKey, ResidentSignature, SecretKey},
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

    pub qcs: Vec<QuorumCertificate>,
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
    pub fn generate_qc(&self, sk: &SecretKey) -> QuorumCertificate {
        let input = self.generate_input();
        let signature = sk.sign(input).expect("Failed to sign input");

        QuorumCertificate {
            public_key: sk.to_public_key(),
            signature,
        }
    }

    pub fn verify_qc(&self) -> bool {
        let input = self.generate_input();

        self.qcs
            .iter()
            .all(|qc| qc.public_key.verify_signature(input, &qc.signature))
    }

    fn generate_input(&self) -> HashArray {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.number.to_le_bytes());
        hasher.update(&self.leader.as_ref().to_bytes());
        hasher.finalize().into()
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("Failed to serialize View")
    }
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
    use crate::crypto::keypair::{self, KeyType};

    use super::*;

    fn generate_random_view() -> View {
        View {
            number: 1,
            leader: PeerId::random(),
            timeout: Duration::from_secs(5),
            proposals: HashSet::from([vec![1, 2, 3]]),
            root_hash: HashArray::from([3; 32]),
            parent_ref: HashArray::from([2; 32]),
            qcs: vec![QuorumCertificate::random()],
            state: State::Prepare,
            height: 1,
        }
    }

    #[test]
    fn correct_serialization() {
        let view = generate_random_view();

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

    #[test]
    fn generate_qc_and_verify() {
        let mut view = generate_random_view();

        let (sk, _) = keypair::generate_keypair(KeyType::Secp256k1);

        let qc = view.generate_qc(&sk);
        view.qcs = vec![qc];

        assert!(view.verify_qc(), "QC verification failed");
    }

    #[test]
    fn false_when_qc_invalid() {
        let mut view = generate_random_view();

        let (sk, _) = keypair::generate_keypair(KeyType::Secp256k1);
        let qc = view.generate_qc(&sk);
        view.qcs = vec![qc];

        if let Some(qc) = view.qcs.first_mut() {
            qc.signature = ResidentSignature::random();
        }

        assert!(!view.verify_qc(), "QC verification should have failed");
    }
}
