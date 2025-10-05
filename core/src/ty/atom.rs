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

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)
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

        tokio::task::spawn_blocking(move || {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libp2p::PeerId;
    use serde::{Deserialize, Serialize};

    use crate::{
        consensus::graph::Proofs,
        crypto::Hasher,
        traits::ScriptPubKey,
        ty::{Input, Token},
        utils::mmr::Mmr,
    };

    use super::*;

    const PEER1: [u8; 39] = [
        0, 37, 8, 2, 18, 33, 3, 37, 231, 146, 221, 228, 232, 82, 157, 2, 152, 38, 140, 247, 207, 5,
        201, 79, 98, 185, 119, 244, 169, 196, 94, 184, 85, 238, 234, 254, 136, 6, 81,
    ];
    const PEER2: [u8; 39] = [
        0, 37, 8, 2, 18, 33, 3, 215, 10, 51, 166, 159, 134, 74, 248, 169, 95, 230, 245, 12, 116,
        122, 68, 95, 157, 233, 179, 114, 84, 200, 57, 227, 138, 230, 88, 254, 185, 162, 42,
    ];

    const DATA: &[u8] = &[
        34, 7, 32, 188, 220, 241, 66, 245, 26, 129, 44, 130, 78, 59, 50, 33, 43, 39, 106, 236, 108,
        255, 1, 151, 155, 197, 103, 53, 150, 7, 182, 183, 23, 111, 93, 1, 251, 4, 1, 0, 98, 19, 43,
        47, 86, 161, 121, 90, 210, 55, 67, 162, 99, 252, 114, 119, 52, 84, 112, 179, 23, 138, 93,
        24, 177, 175, 193, 168, 17, 31, 252, 146, 122, 91, 178, 245, 5, 245, 57, 188, 77, 2, 164,
        236, 190, 175, 111, 93, 157, 199, 208, 189, 198, 23, 238, 180, 89, 214, 215, 150, 164, 199,
        110, 38, 0, 63, 45, 159, 169, 49, 227, 130, 230, 55, 185, 239, 151, 220, 84, 57, 156, 182,
        7, 223, 217, 130, 159, 58, 73, 248, 22, 187, 176, 243, 185, 221, 198, 93, 124, 141, 126,
        232, 62, 17, 79, 230, 82, 121, 204, 208, 194, 94, 134, 41, 239, 168, 181, 119, 74, 226,
        180, 249, 187, 134, 72, 217, 129, 133, 193, 0, 83, 120, 69, 12, 6, 12, 136, 156, 27, 167,
        235, 58, 32, 42, 94, 42, 90, 141, 37, 190, 114, 220, 6, 5, 211, 81, 110, 174, 30, 33, 201,
        121, 66, 235, 79, 113, 47, 187, 162, 41, 72, 139, 150, 227, 128, 223, 54, 68, 31, 220, 56,
        195, 154, 201, 100, 204, 71, 73, 40, 252, 221, 210, 25, 105, 0, 51, 225, 3, 153, 43, 117,
        131, 222, 250, 117, 24, 39, 137, 120, 195, 100, 154, 58, 181, 138, 62, 253, 97, 40, 207,
        51, 9, 131, 14, 63, 170, 207, 134, 189, 71, 24, 168, 96, 186, 240, 161, 147, 89, 5, 99,
        182, 59, 163, 217, 0, 169, 111, 250, 237, 174, 216, 45, 229, 56, 78, 71, 154, 21, 127, 253,
        82, 239, 108, 162, 238, 136, 219, 225, 252, 32, 183, 224, 104, 251, 212, 48, 0, 1, 0, 1, 1,
        38, 0, 36, 8, 1, 18, 32, 180, 162, 212, 74, 95, 90, 210, 161, 144, 158, 3, 212, 45, 146,
        221, 52, 54, 57, 246, 245, 78, 128, 156, 236, 154, 136, 77, 210, 205, 143, 28, 243, 1, 1,
        38, 0, 36, 8, 1, 18, 32, 180, 162, 212, 74, 95, 90, 210, 161, 144, 158, 3, 212, 45, 146,
        221, 52, 54, 57, 246, 245, 78, 128, 156, 236, 154, 136, 77, 210, 205, 143, 28, 243, 20, 34,
        7, 32, 251, 74, 114, 73, 40, 147, 199, 233, 17, 165, 220, 48, 35, 7, 114, 94, 221, 77, 53,
        233, 144, 28, 218, 35, 227, 188, 114, 97, 7, 206, 154, 83, 34, 7, 32, 117, 213, 109, 140,
        147, 206, 83, 78, 244, 41, 24, 163, 61, 44, 109, 63, 1, 218, 1, 44, 212, 150, 227, 119,
        140, 194, 47, 87, 254, 42, 250, 53, 34, 7, 32, 213, 15, 161, 45, 157, 90, 69, 93, 130, 186,
        48, 234, 210, 76, 67, 55, 208, 26, 168, 199, 101, 181, 64, 226, 179, 161, 212, 193, 44,
        182, 46, 236, 34, 7, 32, 191, 125, 101, 249, 24, 178, 170, 100, 167, 91, 193, 142, 188,
        144, 159, 100, 101, 13, 203, 114, 133, 43, 45, 90, 211, 9, 75, 201, 140, 22, 77, 220, 34,
        7, 32, 144, 248, 241, 167, 216, 95, 83, 10, 190, 184, 165, 46, 202, 98, 151, 54, 132, 65,
        42, 208, 245, 254, 78, 126, 42, 138, 210, 242, 160, 221, 76, 240, 34, 7, 32, 254, 211, 221,
        57, 177, 159, 162, 248, 34, 29, 18, 171, 247, 237, 189, 247, 82, 147, 216, 150, 69, 0, 237,
        58, 55, 130, 47, 162, 166, 45, 82, 142, 34, 7, 32, 96, 170, 246, 146, 108, 74, 255, 93,
        102, 30, 199, 173, 103, 31, 160, 54, 57, 4, 210, 27, 20, 149, 79, 45, 188, 50, 54, 186,
        254, 63, 225, 25, 34, 7, 32, 179, 195, 10, 49, 90, 101, 122, 120, 29, 140, 159, 216, 252,
        185, 140, 9, 116, 161, 147, 216, 185, 43, 62, 143, 238, 134, 56, 63, 215, 170, 96, 249, 34,
        7, 32, 101, 179, 90, 133, 202, 225, 28, 140, 179, 162, 163, 163, 61, 164, 213, 212, 94,
        105, 46, 200, 55, 131, 77, 115, 147, 107, 58, 128, 155, 234, 30, 255, 34, 7, 32, 25, 157,
        175, 10, 113, 203, 0, 110, 244, 149, 164, 206, 162, 25, 20, 21, 212, 90, 255, 240, 140, 99,
        83, 99, 211, 241, 11, 130, 210, 190, 212, 137, 34, 7, 32, 134, 48, 12, 217, 201, 52, 186,
        41, 86, 249, 139, 113, 118, 166, 134, 231, 196, 13, 205, 241, 134, 153, 202, 8, 117, 234,
        220, 107, 124, 141, 215, 15, 34, 7, 32, 189, 213, 17, 108, 136, 31, 222, 252, 8, 111, 249,
        169, 188, 193, 22, 81, 61, 65, 197, 131, 18, 143, 20, 15, 189, 252, 70, 138, 26, 130, 0,
        189, 34, 7, 32, 108, 153, 67, 74, 88, 242, 76, 203, 36, 4, 210, 131, 25, 225, 204, 211,
        212, 92, 217, 145, 81, 104, 13, 13, 102, 51, 162, 245, 53, 214, 232, 23, 34, 7, 32, 157,
        14, 236, 52, 222, 87, 205, 98, 90, 203, 244, 37, 60, 52, 160, 122, 208, 210, 123, 97, 247,
        87, 85, 34, 219, 13, 143, 13, 153, 7, 52, 34, 34, 7, 32, 163, 57, 199, 151, 234, 2, 36,
        106, 109, 215, 57, 95, 139, 184, 120, 121, 41, 234, 109, 66, 113, 159, 20, 23, 93, 63, 71,
        198, 97, 199, 176, 247, 34, 7, 32, 28, 18, 49, 130, 24, 89, 26, 127, 184, 156, 246, 62,
        125, 128, 81, 213, 109, 80, 83, 125, 38, 53, 2, 168, 250, 181, 165, 220, 142, 246, 102,
        102, 34, 7, 32, 202, 39, 204, 87, 174, 105, 210, 49, 84, 254, 48, 249, 166, 8, 162, 246, 6,
        174, 188, 64, 239, 178, 70, 41, 208, 253, 243, 255, 139, 124, 198, 201, 34, 7, 32, 237,
        110, 127, 104, 116, 144, 39, 154, 114, 250, 172, 217, 164, 96, 121, 73, 159, 100, 156, 40,
        111, 208, 84, 217, 107, 151, 177, 4, 34, 214, 249, 14, 34, 7, 32, 60, 215, 113, 89, 243,
        80, 172, 107, 9, 101, 112, 233, 188, 204, 235, 152, 179, 113, 152, 9, 115, 82, 13, 44, 135,
        170, 120, 94, 229, 119, 88, 105, 34, 7, 32, 142, 222, 155, 15, 254, 194, 183, 158, 250,
        110, 145, 25, 238, 114, 229, 44, 109, 4, 207, 162, 156, 29, 46, 84, 182, 70, 196, 1, 213,
        7, 109, 230,
    ];

    struct TestConfig;

    #[derive(Clone, Copy)]
    #[derive(Serialize, Deserialize)]
    struct ScriptPk(PeerId);

    impl Config for TestConfig {
        type Value = u32;
        type ScriptPk = ScriptPk;
        type ScriptSig = PeerId;
        type OffChainInput = u32;

        const HASHER: Hasher = Hasher::Sha2_256;
        const VDF_PARAM: u16 = 1024;
        const BLOCK_THRESHOLD: u32 = 2;
        const CONFIRMATION_DEPTH: u32 = 1;
        const MAINTENANCE_WINDOW: u32 = 3;
        const TARGET_BLOCK_TIME_SEC: u64 = 10;
        const MAX_VDF_DIFFICULTY_ADJUSTMENT: f64 = 1.0;
        const GENESIS_HEIGHT: u32 = 0;
        const GENESIS_VAF_DIFFICULTY: u64 = 1;
        const MAX_BLOCKS_PER_SYNC: u32 = 10;

        fn genesis_command() -> Option<Command<Self>> {
            let tokens = vec![Token::new(
                10,
                ScriptPk(PeerId::from_bytes(&PEER1).unwrap()),
            )];
            Some(Command::new(0, vec![], tokens))
        }

        fn validate_command(cmd: &Command<Self>) -> bool {
            cmd.code == 0
        }
    }

    impl ScriptPubKey for ScriptPk {
        type ScriptSig = PeerId;

        fn verify(&self, script_sig: &Self::ScriptSig) -> bool {
            &self.0 == script_sig
        }

        fn is_related(&self, peer_id: PeerId) -> bool {
            self.0 == peer_id
        }

        fn related_peers(&self) -> Vec<PeerId> {
            vec![self.0]
        }
    }

    fn genesis_atom() -> (Atom<TestConfig>, Proofs<TestConfig>) {
        use bincode::{
            config,
            serde::{encode_into_std_write, encode_to_vec},
        };

        let mut mmr = Mmr::default();
        let mut tokens = Vec::new();

        if let Some(cmd) = TestConfig::genesis_command() {
            let first_input = encode_to_vec(Multihash::default(), config::standard()).unwrap();
            cmd.outputs.into_iter().enumerate().for_each(|(i, t)| {
                let mut buf = first_input.clone();
                encode_into_std_write(i as u32, &mut buf, config::standard()).unwrap();
                let id = TestConfig::HASHER.digest(&buf);
                let idx = mmr.append(id);
                tokens.push((id, (t, idx)));
            });
            mmr.commit();
        }

        let mut proofs = HashMap::new();
        tokens.into_iter().for_each(|(id, (t, idx))| {
            proofs.insert(id, (t, mmr.prove(idx).unwrap()));
        });

        let atom = AtomBuilder::new(
            Multihash::default(),
            TestConfig::GENESIS_HEIGHT,
            TestConfig::GENESIS_VAF_DIFFICULTY,
            mmr.peak_hashes(),
        )
        .with_command(TestConfig::genesis_command())
        .with_random(0)
        .with_timestamp(0)
        .with_nonce(vec![])
        .build_sync();

        (atom, proofs)
    }

    fn generate_command() -> Command<TestConfig> {
        let (_, proofs) = genesis_atom();
        let (token_id, (token, proof)) = proofs.into_iter().next().unwrap();
        let sig = PeerId::from_bytes(&PEER1).unwrap();
        let new_pk = ScriptPk(PeerId::from_bytes(&PEER2).unwrap());
        let inputs = vec![Input::OnChain(token, token_id, proof, sig)];
        let outputs = vec![Token::new(5, new_pk)];
        Command::new(0, inputs, outputs)
    }

    #[test]
    fn encode_decode() {
        // let atom = genesis_atom().0;
        // let data = atom.to_bytes();
        let decoded = Atom::<TestConfig>::from_bytes(DATA).unwrap();
        // assert_eq!(atom.hash(), decoded.hash());
    }
}
