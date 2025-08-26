use std::sync::OnceLock;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{hasher::Hasher, Multihash},
    utils::trie::keys::{hex_to_vec, vec_to_hex},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Full {
    pub children: Box<[Node; 17]>,

    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Short {
    #[serialize(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    pub key: Vec<u8>, // Hex
    pub val: Box<Node>,

    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Value {
    pub value: Vec<u8>,

    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Derivative)]
#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub enum Node {
    #[default]
    Empty,
    Full(Full),
    Short(Short),
    Hash(Multihash),
    Value(Value),
}

impl Full {
    pub fn hash(&self) -> Multihash {
        *self
            .hash_cache
            .get_or_init(|| Hasher::digest(&self.to_vec()))
    }

    pub fn hash_children(&self) {
        if self.hash_cache.get().is_some() {
            return; // Already hashed
        }

        self.children.iter().for_each(|child| {
            child.hash_children();
        });
    }

    pub fn clear_caches(&mut self) {
        self.hash_cache = OnceLock::new();
    }
}

impl Short {
    pub fn new<T: Into<Box<Node>>>(key: Vec<u8>, val: T) -> Self {
        let val = val.into();

        Short {
            key,
            val,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash(&self) -> Multihash {
        *self
            .hash_cache
            .get_or_init(|| Hasher::digest(&self.to_vec()))
    }

    pub fn hash_children(&self) {
        if self.hash_cache.get().is_none() {
            self.val.hash_children();
        }
    }

    pub fn clear_cache(&mut self) {
        self.hash_cache = OnceLock::new();
    }
}

impl Value {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash(&self) -> Multihash {
        *self
            .hash_cache
            .get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}

impl Node {
    pub fn new_short<T: Into<Box<Node>>>(key: Vec<u8>, val: T) -> Self {
        Node::Short(Short::new(key, val))
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    pub fn is_short(&self) -> bool {
        matches!(self, Node::Short(_))
    }

    pub fn hash(&self) -> Multihash {
        match self {
            Node::Full(full) => full.hash(),
            Node::Short(short) => short.hash(),
            Node::Value(value) => value.hash(),
            Node::Hash(hash) => *hash,
            Node::Empty => Multihash::default(),
        }
    }

    pub fn hash_children(&self) {
        match self {
            Node::Full(full) => full.hash_children(),
            Node::Short(short) => short.hash_children(),
            Node::Hash(_) | Node::Value(_) | Node::Empty => {}
        }
    }

    pub fn as_full_mut(&mut self) -> Option<&mut Full> {
        if let Node::Full(full) = self {
            Some(full)
        } else {
            None
        }
    }

    pub fn as_short(&self) -> Option<&Short> {
        if let Node::Short(short) = self {
            Some(short)
        } else {
            None
        }
    }
}

fn serialize_key<W: std::io::Write>(key: &[u8], writer: &mut W) {
    (key.len() as u32).to_writer(writer);

    if key.len() % 2 == 1 {
        let mut padded_key = vec![0];
        padded_key.extend_from_slice(key);
        hex_to_vec(&padded_key).to_writer(writer);
    } else {
        hex_to_vec(key).to_writer(writer);
    }
}

fn deserialize_key<R: std::io::Read>(reader: &mut R) -> Result<Vec<u8>, civita_serialize::Error> {
    let original_len = u32::from_reader(reader)? as usize;
    let bytes = Vec::from_reader(reader)?;
    let mut hex_nibbles = vec_to_hex(bytes);

    if original_len % 2 == 1 {
        hex_nibbles.remove(0);
    }

    Ok(hex_nibbles)
}
