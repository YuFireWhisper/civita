use std::sync::OnceLock;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::{
    crypto::{Hasher, Multihash},
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
    pub hash_cache: OnceLock<Multihash>,
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
    pub hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Value {
    pub val: Vec<u8>,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

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
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn hash_children<H: Hasher>(&self) {
        if self.hash_cache.get().is_some() {
            return; // Already hashed
        }

        self.children.iter().for_each(|child| {
            child.hash_children::<H>();
        });
    }
}

impl Short {
    pub fn new<T: Into<Box<Node>>>(key: Vec<u8>, val: T) -> Self {
        Short {
            key,
            val: val.into(),
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn hash_children<H: Hasher>(&self) {
        if self.hash_cache.get().is_some() {
            return; // Already hashed
        }
        self.val.hash_children::<H>();
    }
}

impl Value {
    pub fn new(val: Vec<u8>) -> Self {
        Value {
            val,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.val))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.val
    }
}

impl Node {
    pub fn new_short<T: Into<Node>>(key: Vec<u8>, val: T) -> Self {
        Node::Short(Short::new(key, val.into()))
    }

    pub fn new_value(val: Vec<u8>) -> Self {
        Node::Value(Value::new(val))
    }

    pub fn from_full(full: Full) -> Self {
        Node::Full(full)
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    pub fn is_value(&self) -> bool {
        matches!(self, Node::Value(_))
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        match self {
            Node::Full(full) => full.hash::<H>(),
            Node::Short(short) => short.hash::<H>(),
            Node::Value(value) => value.hash::<H>(),
            Node::Hash(hash) => *hash,
            Node::Empty => Multihash::default(),
        }
    }

    pub fn hash_children<H: Hasher>(&self) {
        match self {
            Node::Full(full) => full.hash_children::<H>(),
            Node::Short(short) => short.hash_children::<H>(),
            Node::Hash(_) | Node::Value(_) | Node::Empty => {}
        }
    }
}

fn serialize_key<W: std::io::Write>(key: &[u8], writer: &mut W) {
    hex_to_vec(key).to_writer(writer);
}

fn deserialize_key<R: std::io::Read>(reader: &mut R) -> Result<Vec<u8>, civita_serialize::Error> {
    Vec::from_reader(reader).map(vec_to_hex)
}

impl From<Full> for Node {
    fn from(full: Full) -> Self {
        Node::Full(full)
    }
}
