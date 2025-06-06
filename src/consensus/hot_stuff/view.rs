use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tokio::time::Duration;

use crate::{consensus::randomizer::DrawResult, constants::HashArray, crypto::keypair::PublicKey};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to deserialize View: {0}")]
    Deserialize(#[from] bincode::error::DecodeError),
}

#[derive(Clone)]
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
    pub view_number: u64,
    pub root_hash: HashArray,
    pub state: State,

    pub leader_pk: PublicKey,
    pub leader_result: DrawResult,

    pub validators: HashMap<PublicKey, DrawResult>,
}

#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct View {
    pub number: u64,
    pub timeout: Duration,

    pub leader_pk: PublicKey,
    pub leader_result: DrawResult,

    pub root_hash: HashArray,
    pub total_stakes: u32,
    pub proposals: HashSet<Vec<u8>>,

    pub parent_hash: HashArray,
    pub parent_qcs: QuorumCertificate,

    pub state: State,
    pub height: u64,
}

impl State {
    pub fn to_u8(&self) -> u8 {
        self.into()
    }
}

impl View {
    pub fn generate_draw_seed(&self) -> HashArray {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.number.to_le_bytes());
        hasher.update(&self.root_hash);
        hasher.update(&[self.state.to_u8()]);
        hasher.update(self.leader_pk.as_bytes());
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

impl From<&State> for u8 {
    fn from(state: &State) -> Self {
        match state {
            State::Prepare => 0,
            State::PreCommit => 1,
            State::Commit => 2,
        }
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
    use crate::{
        constants::HASH_ARRAY_LENGTH,
        crypto::keypair::{self, KeyType, SecretKey},
    };

    use super::*;

    const VIEW_NUMBER: u64 = 1;
    const ROOT_HASH: HashArray = [1; HASH_ARRAY_LENGTH];
    const STATE: State = State::Prepare;

    fn generate_qc(pk: PublicKey, leader_result: DrawResult) -> QuorumCertificate {
        QuorumCertificate {
            view_number: VIEW_NUMBER,
            root_hash: ROOT_HASH,
            state: STATE,

            leader_pk: pk,
            leader_result,

            validators: HashMap::new(),
        }
    }

    fn generate_draw_result(sk: &SecretKey, msg: &[u8], weight: u32) -> DrawResult {
        let proof = sk.prove(msg).expect("Failed to generate proof");
        DrawResult { proof, weight }
    }

    fn generate_random_view() -> View {
        const TIMEOUT: Duration = Duration::from_secs(5);
        const MSG: &[u8] = b"test message";
        const WEIGHT: u32 = 1000;
        const TOTAL_STAKES: u32 = 1000;
        const PROPOSAL: [u8; 3] = [1, 2, 3];
        const PARENT_HASH: HashArray = [2; HASH_ARRAY_LENGTH];
        const HEIGHT: u64 = 1;

        let (sk, pk) = keypair::generate_keypair(KeyType::Secp256k1);

        let parent_qc = generate_qc(pk.clone(), generate_draw_result(&sk, MSG, WEIGHT));

        View {
            number: VIEW_NUMBER,
            timeout: TIMEOUT,

            leader_pk: pk,
            leader_result: generate_draw_result(&sk, MSG, WEIGHT),

            root_hash: ROOT_HASH,
            total_stakes: TOTAL_STAKES,
            proposals: HashSet::from([PROPOSAL.to_vec()]),

            parent_hash: PARENT_HASH,
            parent_qcs: parent_qc,

            state: STATE,
            height: HEIGHT,
        }
    }

    #[test]
    fn correct_serialization() {
        let view = generate_random_view();

        let serialized = view.to_bytes();
        let deserialized: View = serialized.try_into().expect("Failed to deserialize View");

        assert_eq!(view, deserialized);
    }
}
