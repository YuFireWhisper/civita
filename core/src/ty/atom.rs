use std::sync::OnceLock;

use derivative::Derivative;
use multihash_derive::MultihashDigest;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

use crate::{crypto::Multihash, traits::Config, ty::Command, utils::mmr::State};

pub type Height = u32;
pub type Random = u32;
pub type Difficulty = u64;
pub type Timestamp = u64;
pub type Nonce = Vec<u8>;

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Config", deserialize = "T: Config"))]
pub struct Pruned<T: Config> {
    pub random: Random,
    pub timestamp: Timestamp,
    pub cmd: Option<Command<T>>,
    pub nonce: Nonce,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derivative(Default(bound = ""))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Config", deserialize = "T: Config"))]
pub struct Atom<T: Config> {
    pub parent: Multihash,
    pub height: Height,
    pub random: Random,
    pub difficulty: Difficulty,
    pub state: State,
    pub timestamp: Timestamp,
    pub cmd: Option<Command<T>>,
    pub nonce: Nonce,
    pub atoms: Vec<Pruned<T>>,

    #[serde(skip)]
    cache: OnceLock<Multihash>,
}

impl<T: Config> Pruned<T> {
    pub fn from_atom(atom: Atom<T>) -> Self {
        Self {
            random: atom.random,
            timestamp: atom.timestamp,
            cmd: atom.cmd,
            nonce: atom.nonce,
        }
    }
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

    pub fn with_nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_random(mut self, random: Random) -> Self {
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

    pub fn with_difficulty(mut self, difficulty: Difficulty) -> Self {
        self.difficulty = difficulty;
        self
    }

    pub fn with_state(mut self, state: State) -> Self {
        self.state = state;
        self
    }

    pub fn with_command(mut self, cmd: Option<Command<T>>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_atoms(mut self, atoms: Vec<Pruned<T>>) -> Self {
        self.atoms = atoms;
        self
    }

    pub fn solve(mut self) -> Self {
        let input = self.vdf_input();
        let nonce = WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .solve(&input, self.difficulty)
            .unwrap();
        self.nonce = nonce;
        self
    }

    fn vdf_input(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_into_std_write};

        let mut buf = Vec::new();

        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.state, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();

        if self.atoms.len() >= T::BLOCK_THRESHOLD as usize {
            encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();
        }

        buf
    }

    pub fn hash(&self) -> Multihash {
        *self
            .cache
            .get_or_init(|| T::HASHER.digest(&self.vdf_input()))
    }

    pub fn verify_nonce(&self) -> bool {
        use bincode::{config, serde::encode_into_std_write};

        let vdf = WesolowskiVDFParams(T::VDF_PARAM).new();
        let difficulty = self.difficulty;

        let mut buf = Vec::new();

        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.state, &mut buf, config::standard()).unwrap();

        if self.atoms.len() < T::BLOCK_THRESHOLD as usize {
            encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
            encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
            encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
            return vdf.verify(&buf, difficulty, &self.nonce).is_ok();
        }

        for atom in &self.atoms {
            let mut input = buf.clone();

            encode_into_std_write(atom.random, &mut input, config::standard()).unwrap();
            encode_into_std_write(atom.timestamp, &mut input, config::standard()).unwrap();
            encode_into_std_write(&atom.cmd, &mut input, config::standard()).unwrap();

            if vdf.verify(&input, difficulty, &atom.nonce).is_err() {
                return false;
            }
        }

        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();

        vdf.verify(&buf, difficulty, &self.nonce).is_ok()
    }

    pub fn atoms_hashes(&self) -> Vec<Multihash> {
        use bincode::{config, serde::encode_into_std_write};

        let mut hashes = Vec::with_capacity(self.atoms.len());

        let mut buf = Vec::new();
        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.state, &mut buf, config::standard()).unwrap();

        for atom in &self.atoms {
            let mut input = buf.clone();

            encode_into_std_write(atom.random, &mut input, config::standard()).unwrap();
            encode_into_std_write(atom.timestamp, &mut input, config::standard()).unwrap();
            encode_into_std_write(&atom.cmd, &mut input, config::standard()).unwrap();

            hashes.push(T::HASHER.digest(&input));
        }

        hashes
    }

    pub fn validate_atoms_threshold(&self) -> bool {
        self.atoms.is_empty() || self.atoms.len() >= T::BLOCK_THRESHOLD as usize
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)
    }
}
