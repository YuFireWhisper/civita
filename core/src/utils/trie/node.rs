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

    pub fn merge_with(&mut self, other: &Full) -> bool {
        let mut changed = false;

        self.children
            .iter_mut()
            .zip(other.children.iter())
            .for_each(|(a, b)| {
                if a.merge_with(b) {
                    changed = true;
                }
            });

        if changed {
            self.hash_cache = OnceLock::new();
        }

        changed
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

    pub fn merge_with(&mut self, other: &Short) -> bool {
        if self.key != other.key {
            return false;
        }

        let changed = self.val.merge_with(&other.val);

        if changed {
            self.hash_cache = OnceLock::new();
        }

        changed
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

    /// Merge this node with another node
    /// Returns true if any changes were made
    pub fn merge_with(&mut self, other: &Node) -> bool {
        if matches!(self, Node::Hash(_)) {
            *self = other.clone();
            return true;
        }

        match (self, other) {
            (Node::Full(a), Node::Full(b)) => a.merge_with(b),
            (Node::Short(a), Node::Short(b)) => a.merge_with(b),
            (Node::Value(a), Node::Value(b)) => a.val == b.val,
            (_, Node::Hash(_)) => false,
            _ => false,
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

impl From<Full> for Node {
    fn from(full: Full) -> Self {
        Node::Full(full)
    }
}
