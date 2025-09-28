use crate::{crypto::Multihash, ty::token::Token, utils::mmr::MmrProof};

pub type Height = u32;
pub type Timestamp = u64;

#[derive(Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub code: u8,
    pub inputs: Vec<(Token, MmrProof, Vec<u8>)>,
    pub created: Vec<Token>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Atom {
    pub hash: Multihash,
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: Height,
    pub nonce: Vec<u8>,
    pub random: u64,
    pub timestamp: Timestamp,
    pub cmd: Option<Command>,
    pub atoms: Vec<Multihash>,
}

impl Atom {
    pub fn hash_input(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_into_std_write};

        let mut buf = Vec::new();
        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.checkpoint, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.nonce, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();
        buf
    }

    pub fn vdf_input(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_into_std_write};

        let mut buf = Vec::new();
        encode_into_std_write(self.parent, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.checkpoint, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.height, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.timestamp, &mut buf, config::standard()).unwrap();
        encode_into_std_write(self.random, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.cmd, &mut buf, config::standard()).unwrap();
        encode_into_std_write(&self.atoms, &mut buf, config::standard()).unwrap();
        buf
    }
}
