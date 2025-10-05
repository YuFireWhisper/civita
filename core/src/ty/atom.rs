use std::sync::OnceLock;

use derivative::Derivative;
use multihash_derive::MultihashDigest;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

use crate::{crypto::Multihash, traits::Config, ty::Command};

pub type Height = u32;
pub type Timestamp = u64;

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derivative(Default(bound = ""))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Config", deserialize = "T: Config"))]
pub struct Atom<T: Config> {
    pub parent: Multihash,
    pub height: Height,
    pub nonce: Vec<u8>,
    pub random: u64,
    pub timestamp: Timestamp,
    pub difficulty: u64,
    pub peaks: Vec<(u64, Multihash)>,
    pub cmd: Option<Command<T>>,
    pub atoms: Vec<Multihash>,

    #[serde(skip)]
    cache: OnceLock<Multihash>,
}

impl<T: Config> Atom<T> {
    pub fn with_parent(mut self, parent: Multihash) -> Self {
        self.parent = parent;
        self
    }

    pub fn with_height(mut self, height: Height) -> Self {
        self.height = height;
        self
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_random(mut self, random: u64) -> Self {
        self.random = random;
        self
    }

    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_timestamp_now(mut self) -> Self {
        self.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self
    }

    pub fn with_difficulty(mut self, difficulty: u64) -> Self {
        self.difficulty = difficulty;
        self
    }

    pub fn with_peaks(mut self, peaks: Vec<(u64, Multihash)>) -> Self {
        self.peaks = peaks;
        self
    }

    pub fn with_command(mut self, cmd: Option<Command<T>>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_atoms(mut self, atoms: Vec<Multihash>) -> Self {
        self.atoms = atoms;
        self
    }

    pub fn solve(mut self) -> Self {
        let input = self.vdf_input();
        let nonce = WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .solve(&input, self.difficulty)
            .expect("VDF should work");
        self.nonce = nonce;
        self
    }

    fn vdf_input(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_into_std_write};

        let mut buf = Vec::new();
        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.peaks, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();

        buf
    }

    pub fn hash(&self) -> Multihash {
        use bincode::{config, serde::encode_to_vec};
        *self
            .cache
            .get_or_init(|| T::HASHER.digest(&encode_to_vec(self, config::standard()).unwrap()))
    }

    pub fn verify_nonce(&self, difficulty: u64) -> bool {
        if self.difficulty != difficulty {
            return false;
        }

        let input = self.vdf_input();

        // TODO: verify maybe panics, consider forking vdf crate to return Result
        WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .verify(&input, difficulty, &self.nonce)
            .is_ok()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)
    }
}
