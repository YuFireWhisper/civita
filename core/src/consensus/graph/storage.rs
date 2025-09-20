use std::collections::{BTreeMap, HashMap, VecDeque};

use bincode::error::DecodeError;
use libp2p::PeerId;

use crate::{
    consensus::{
        graph::{self, Config, Graph},
        validator::Validator,
    },
    crypto::Multihash,
    ty::{
        atom::{Atom, Height},
        token::Token,
    },
    utils::mmr::Mmr,
};

#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
pub enum StorageMode {
    General(PeerId),
    Archive(u32),
}

pub struct Storage {
    pub difficulty: u64,
    pub mmr: Mmr<Token>,
    pub atoms: BTreeMap<Height, HashMap<Multihash, Vec<u8>>>,
    pub others: VecDeque<(Vec<u8>, Vec<u8>)>,
    pub mode: StorageMode,
}

impl StorageMode {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        match self {
            StorageMode::General(_) => 1,
            StorageMode::Archive(l) => *l,
        }
    }
}

impl Storage {
    pub fn push_atom(&mut self, atom: &Atom) {
        use bincode::{config, serde::encode_to_vec};

        self.atoms
            .entry(atom.height)
            .or_default()
            .insert(atom.hash, encode_to_vec(atom, config::standard()).unwrap());
    }

    pub fn finalize(&mut self, hashes: &[Multihash], difficulty: u64, mmr: Mmr<Token>) {
        use bincode::{config, serde::encode_into_std_write};

        if self.mode.len() != 1 {
            let mut buf_1 = Vec::new();
            encode_into_std_write(self.difficulty, &mut buf_1, config::standard()).unwrap();
            encode_into_std_write(&self.mmr, &mut buf_1, config::standard()).unwrap();

            let mut buf_2 = Vec::new();
            encode_into_std_write(hashes.len() as u32 - 1, &mut buf_2, config::standard()).unwrap();
            hashes.iter().take(hashes.len() - 1).for_each(|h| {
                let atom = self.atoms.pop_first().unwrap().1.remove(h).unwrap();
                encode_into_std_write(&atom, &mut buf_2, config::standard()).unwrap();
            });

            self.others.push_back((buf_1, buf_2));

            if self.mode.len() != 0 && self.others.len() > (self.mode.len() - 1) as usize {
                self.others.pop_front();
            }
        } else {
            for _ in 0..hashes.len() - 1 {
                self.atoms.pop_first();
            }
        }

        self.difficulty = difficulty;
        self.mmr = mmr;

        let map = self.atoms.iter_mut().next().unwrap().1;
        let hash = *hashes.last().unwrap();
        let atom = map.remove(&hash).unwrap();
        *map = HashMap::from([(hash, atom)]);
    }

    pub fn export<I>(&self, idxs: Option<I>) -> Option<Vec<u8>>
    where
        I: IntoIterator<Item = Multihash>,
    {
        use bincode::{config, serde::encode_into_std_write};

        // | difficulty: u64 | mmr: Mmr<Token> |
        // | other_len: u32 | other_1: Vec<u8> | ... | other_n: Vec<u8> |
        // | atom_len: u32 | atom_1: Vec<u8> | ... | atom_n: Vec<u8> |

        let mut buf = Vec::new();

        match idxs {
            Some(idxs) => {
                let mmr = self.mmr.to_pruned(idxs)?;
                let len = self.atoms.len() as u32;
                encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
                encode_into_std_write(&mmr, &mut buf, config::standard()).unwrap();
                encode_into_std_write(0u32, &mut buf, config::standard()).unwrap();
                encode_into_std_write(len, &mut buf, config::standard()).unwrap();
                self.atoms.values().flatten().for_each(|(_, v)| {
                    encode_into_std_write(v, &mut buf, config::standard()).unwrap();
                });
            }
            None => {
                if self.others.is_empty() {
                    let len = self.atoms.len() as u32;
                    encode_into_std_write(self.difficulty, &mut buf, config::standard()).unwrap();
                    encode_into_std_write(&self.mmr, &mut buf, config::standard()).unwrap();
                    encode_into_std_write(0u32, &mut buf, config::standard()).unwrap();
                    encode_into_std_write(len, &mut buf, config::standard()).unwrap();
                    self.atoms.values().flatten().for_each(|(_, v)| {
                        encode_into_std_write(v, &mut buf, config::standard()).unwrap();
                    });
                } else {
                    let other_len = self.others.len() as u32;
                    let len = self.atoms.len() as u32;
                    buf.extend_from_slice(&self.others.front().unwrap().0);
                    encode_into_std_write(other_len, &mut buf, config::standard()).unwrap();
                    self.others.iter().for_each(|v| {
                        encode_into_std_write(&v.1, &mut buf, config::standard()).unwrap();
                    });
                    encode_into_std_write(len, &mut buf, config::standard()).unwrap();
                    self.atoms.values().flatten().for_each(|(_, v)| {
                        encode_into_std_write(v, &mut buf, config::standard()).unwrap();
                    });
                }
            }
        }

        Some(buf)
    }

    pub fn import<V: Validator>(mut data: &[u8], config: Config) -> Result<Graph<V>, graph::Error> {
        use bincode::{
            config,
            serde::{decode_from_slice, decode_from_std_read},
        };

        let difficulty = decode_from_std_read(&mut data, config::standard())?;
        let mmr = decode_from_std_read(&mut data, config::standard())?;
        let mut atoms = VecDeque::new();

        {
            let len: u32 = decode_from_std_read(&mut data, config::standard())?;
            if let StorageMode::General(_) = config.storage_mode {
                if len != 0 {
                    return Err(graph::Error::Decode(DecodeError::Other(
                        "Non-zero other length in General mode",
                    )));
                }
            }

            for _ in 0..len {
                let bytes: Vec<u8> = decode_from_std_read(&mut data, config::standard())?;
                let mut data = bytes.as_slice();

                let len: u32 = decode_from_std_read(&mut data, config::standard())?;
                for _ in 0..len {
                    let bytes: Vec<u8> = decode_from_std_read(&mut data, config::standard())?;
                    let atom: Atom = decode_from_slice(&bytes, config::standard())?.0;
                    atoms.push_back(atom);
                }
            }
        }

        {
            let len: u32 = decode_from_std_read(&mut data, config::standard())?;
            if len == 0 {
                return Err(graph::Error::Decode(DecodeError::Other(
                    "Atom length is zero",
                )));
            }

            for _ in 0..len {
                let bytes: Vec<u8> = decode_from_std_read(&mut data, config::standard())?;
                let atom: Atom = decode_from_slice(&bytes, config::standard())?.0;
                atoms.push_back(atom);
            }
        }

        Graph::new(atoms.pop_front().unwrap(), difficulty, mmr, atoms, config)
    }
}
