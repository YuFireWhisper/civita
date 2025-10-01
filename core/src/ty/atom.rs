use std::sync::OnceLock;

use derivative::Derivative;
use multihash_derive::MultihashDigest;
use tokio::task::JoinHandle;
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

pub struct AtomBuilder<T: Config> {
    parent: Multihash,
    height: Height,
    nonce: Option<Vec<u8>>,
    random: Option<u64>,
    timestamp: Option<Timestamp>,
    difficulty: u64,
    peaks: Vec<(u64, Multihash)>,
    cmd: Option<Command<T>>,
    atoms: Vec<Multihash>,
}

impl<T: Config> Atom<T> {
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

    fn solve_and_set_nonce(&mut self) {
        let input = self.vdf_input();
        let nonce = WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .solve(&input, self.difficulty)
            .expect("VDF should work");
        self.nonce = nonce;
    }
}

impl<T: Config> AtomBuilder<T> {
    pub fn new(
        parent: Multihash,
        height: u32,
        difficulty: u64,
        peaks: Vec<(u64, Multihash)>,
    ) -> Self {
        Self {
            parent,
            height,
            nonce: None,
            random: None,
            timestamp: None,
            difficulty,
            peaks,
            cmd: None,
            atoms: vec![],
        }
    }

    pub fn with_random(mut self, random: u64) -> Self {
        self.random = Some(random);
        self
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
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

    pub fn build(self) -> JoinHandle<Atom<T>> {
        let random = self.random.unwrap_or_else(rand::random);
        let timestamp = self.timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        if let Some(nonce) = self.nonce {
            return tokio::spawn(async move {
                Atom {
                    parent: self.parent,
                    height: self.height,
                    nonce,
                    random,
                    timestamp,
                    difficulty: self.difficulty,
                    peaks: self.peaks,
                    cmd: self.cmd,
                    atoms: self.atoms,
                    cache: OnceLock::new(),
                }
            });
        }

        tokio::spawn(async move {
            let mut atom = Atom {
                parent: self.parent,
                height: self.height,
                nonce: vec![],
                random,
                timestamp,
                difficulty: self.difficulty,
                peaks: self.peaks.clone(),
                cmd: self.cmd.clone(),
                atoms: self.atoms.clone(),
                cache: OnceLock::new(),
            };
            atom.solve_and_set_nonce();
            atom
        })
    }

    pub fn build_sync(self) -> Atom<T> {
        let random = self.random.unwrap_or_else(rand::random);
        let timestamp = self.timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        if let Some(nonce) = self.nonce {
            return Atom {
                parent: self.parent,
                height: self.height,
                nonce,
                random,
                timestamp,
                difficulty: self.difficulty,
                peaks: self.peaks,
                cmd: self.cmd,
                atoms: self.atoms,
                cache: OnceLock::new(),
            };
        }

        let mut atom = Atom {
            parent: self.parent,
            height: self.height,
            nonce: vec![],
            random,
            timestamp,
            difficulty: self.difficulty,
            peaks: self.peaks,
            cmd: self.cmd,
            atoms: self.atoms,
            cache: OnceLock::new(),
        };
        atom.solve_and_set_nonce();
        atom
    }
}
