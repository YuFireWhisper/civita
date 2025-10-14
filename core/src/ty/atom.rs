use std::sync::OnceLock;

use bincode::{error::DecodeError, serde::encode_into_std_write};
use multihash_derive::MultihashDigest;
use serde::{Deserialize, Serialize};
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

use crate::{
    chain_config::ChainConfig, crypto::Multihash, ty::Command, utils::mmr::State, BINCODE_CONFIG,
};

pub type Height = u32;
pub type Random = u32;
pub type Difficulty = u64;
pub type Timestamp = u64;
pub type Nonce = Vec<u8>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Pruned {
    pub nonce: Nonce,
    pub random: Random,
    pub timestamp: Timestamp,
    pub cmd: Option<Command>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Atom {
    pub parent: Multihash,
    pub height: Height,
    pub difficulty: Difficulty,
    pub state: State,
    pub chain_config: ChainConfig,

    pub nonce: Nonce,
    pub random: Random,
    pub timestamp: Timestamp,
    pub cmd: Option<Command>,

    pub atoms: Vec<Pruned>,

    #[serde(skip)]
    common_input: OnceLock<Vec<u8>>,

    #[serde(skip)]
    id: OnceLock<Multihash>,

    #[serde(skip)]
    atom_ids: OnceLock<Vec<Multihash>>,
}

impl Pruned {
    pub fn from_atom(atom: Atom) -> Self {
        Self {
            random: atom.random,
            timestamp: atom.timestamp,
            cmd: atom.cmd,
            nonce: atom.nonce,
        }
    }

    pub fn spec_input(&self, include_nonce: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        if include_nonce {
            encode_into_std_write(&self.nonce, &mut buf, BINCODE_CONFIG).unwrap();
        }
        encode_into_std_write(self.random, &mut buf, BINCODE_CONFIG).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, BINCODE_CONFIG).unwrap();
        encode_into_std_write(
            self.cmd.as_ref().map(|c| c.to_no_outputs_atom_id_bytes()),
            &mut buf,
            BINCODE_CONFIG,
        )
        .unwrap();

        buf
    }
}

impl Atom {
    pub fn new(chain_config: ChainConfig) -> Self {
        Self {
            parent: Default::default(),
            height: 0,
            difficulty: 0,
            state: Default::default(),
            chain_config,

            nonce: Default::default(),
            random: 0,
            timestamp: 0,
            cmd: None,

            atoms: Vec::new(),

            common_input: OnceLock::new(),
            id: OnceLock::new(),
            atom_ids: OnceLock::new(),
        }
    }

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

    pub fn with_chain_config(mut self, chain_config: ChainConfig) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_command(mut self, cmd: Option<Command>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_atoms(mut self, atoms: Vec<Pruned>) -> Self {
        self.atoms = atoms;
        self
    }

    pub fn solve(mut self) -> Self {
        let vdf = WesolowskiVDFParams(self.chain_config.vdf_param).new();
        let input = self.compute_input(false);
        self.nonce = vdf.solve(&input, self.difficulty).unwrap();

        let id = self.id();

        if let Some(cmd) = &mut self.cmd {
            cmd.outputs.iter_mut().for_each(|t| {
                t.atom_id = id;
            });
        }

        self
    }

    fn compute_input(&self, include_nonce: bool) -> Vec<u8> {
        let mut buf = self.spec_input(include_nonce);
        buf.extend_from_slice(self.common_input());
        buf
    }

    fn spec_input(&self, include_nonce: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        if include_nonce {
            encode_into_std_write(&self.nonce, &mut buf, BINCODE_CONFIG).unwrap();
        }

        encode_into_std_write(self.random, &mut buf, BINCODE_CONFIG).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, BINCODE_CONFIG).unwrap();
        encode_into_std_write(
            self.cmd.as_ref().map(|c| c.to_no_outputs_atom_id_bytes()),
            &mut buf,
            BINCODE_CONFIG,
        )
        .unwrap();

        buf
    }

    fn common_input(&self) -> &[u8] {
        self.common_input.get_or_init(|| {
            let mut buf = Vec::new();
            encode_into_std_write(self.parent, &mut buf, BINCODE_CONFIG).unwrap();
            encode_into_std_write(self.height, &mut buf, BINCODE_CONFIG).unwrap();
            encode_into_std_write(self.difficulty, &mut buf, BINCODE_CONFIG).unwrap();
            encode_into_std_write(&self.state, &mut buf, BINCODE_CONFIG).unwrap();
            encode_into_std_write(&self.chain_config, &mut buf, BINCODE_CONFIG).unwrap();
            buf
        })
    }

    pub fn id(&self) -> Multihash {
        *self
            .id
            .get_or_init(|| self.chain_config.hasher.digest(&self.compute_input(true)))
    }

    pub fn atoms_ids(&self) -> &[Multihash] {
        self.atom_ids.get_or_init(|| {
            self.atoms
                .iter()
                .map(|a| {
                    self.chain_config
                        .hasher
                        .digest(&self.compute_atoms_input(a, true))
                })
                .collect()
        })
    }

    fn compute_atoms_input(&self, atom: &Pruned, include_nonce: bool) -> Vec<u8> {
        let mut buf = atom.spec_input(include_nonce);
        buf.extend_from_slice(self.common_input());
        buf
    }

    pub fn verify_nonce(&self) -> bool {
        let vdf = WesolowskiVDFParams(self.chain_config.vdf_param).new();
        let input = self.compute_input(false);

        vdf.verify(&input, self.difficulty, &self.nonce).is_ok()
            && self.atoms.iter().all(|atom| {
                vdf.verify(
                    &self.compute_atoms_input(atom, false),
                    self.difficulty,
                    &atom.nonce,
                )
                .is_ok()
            })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        bincode::serde::decode_from_slice(data, BINCODE_CONFIG).map(|(msg, _)| msg)
    }
}
