use std::sync::OnceLock;

use multihash_derive::MultihashDigest;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

use crate::{config::Config, crypto::Multihash};

type Height = u32;
type Timestamp = u64;

#[derive(Clone)]
#[derive(Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Atom<T: Config> {
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: Height,
    pub nonce: Vec<u8>,
    pub random: u64,
    pub timestamp: Timestamp,
    pub cmd: Option<T::Command>,
    pub atoms: Vec<Multihash>,

    #[serde(skip)]
    cache: OnceLock<Multihash>,
}

pub struct AtomBuilder<T: Config> {
    parent: Multihash,
    checkpoint: Multihash,
    height: Height,
    nonce: Option<Vec<u8>>,
    random: Option<u64>,
    timestamp: Option<Timestamp>,
    cmd: Option<T::Command>,
    atoms: Vec<Multihash>,
}

impl<T: Config> Atom<T> {
    pub fn hash(&self) -> Multihash {
        use bincode::{config, serde::encode_to_vec};
        *self
            .cache
            .get_or_init(|| T::HASHER.digest(&encode_to_vec(&self, config::standard()).unwrap()))
    }

    pub fn verify_nonce(&self, difficulty: u64) -> bool {
        use bincode::{config, serde::encode_into_std_write};

        let mut buf = Vec::new();
        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.checkpoint, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();

        // TODO: verify maybe panics, consider forking vdf crate to return Result
        WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .verify(&buf, difficulty, &self.nonce)
            .is_ok()
    }
}

impl<T: Config> AtomBuilder<T> {
    pub fn new(parent: Multihash, checkpoint: Multihash, height: u32) -> Self {
        Self {
            parent,
            checkpoint,
            height,
            nonce: None,
            random: None,
            timestamp: None,
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

    pub fn with_command(mut self, cmd: Option<T::Command>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_atoms(mut self, atoms: Vec<Multihash>) -> Self {
        self.atoms = atoms;
        self
    }

    pub fn build(self, difficulty: u64) -> JoinHandle<Atom<T>> {
        use bincode::{config, serde::encode_into_std_write};

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
                    checkpoint: self.checkpoint,
                    height: self.height,
                    nonce,
                    random,
                    timestamp,
                    cmd: self.cmd,
                    atoms: self.atoms,
                    cache: OnceLock::new(),
                }
            });
        }

        tokio::spawn(async move {
            let mut buf = Vec::new();

            encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
            encode_into_std_write(self.checkpoint, &mut buf, config::standard()).unwrap();
            encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
            encode_into_std_write(random, &mut buf, config::standard()).unwrap();
            encode_into_std_write(timestamp, &mut buf, config::standard()).unwrap();
            encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
            encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();

            let nonce = WesolowskiVDFParams(T::VDF_PARAM)
                .new()
                .solve(&buf, difficulty)
                .expect("VDF should work");

            Atom {
                parent: self.parent,
                checkpoint: self.checkpoint,
                height: self.height,
                nonce,
                random,
                timestamp,
                cmd: self.cmd,
                atoms: self.atoms,
                cache: OnceLock::new(),
            }
        })
    }

    pub fn build_sync(self, difficulty: u64) -> Atom<T> {
        use bincode::{config, serde::encode_into_std_write};

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
                checkpoint: self.checkpoint,
                height: self.height,
                nonce,
                random,
                timestamp,
                cmd: self.cmd,
                atoms: self.atoms,
                cache: OnceLock::new(),
            };
        }

        let mut buf = Vec::new();

        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.checkpoint, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();

        let nonce = WesolowskiVDFParams(T::VDF_PARAM)
            .new()
            .solve(&buf, difficulty)
            .expect("VDF should work");

        Atom {
            parent: self.parent,
            checkpoint: self.checkpoint,
            height: self.height,
            nonce,
            random,
            timestamp,
            cmd: self.cmd,
            atoms: self.atoms,
            cache: OnceLock::new(),
        }
    }
}
