use std::sync::OnceLock;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash},
    utils::{
        trie::keys::{hex_to_vec, vec_to_hex},
        Record,
    },
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Full<T: Record> {
    pub children: Box<[Node<T>; 17]>,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,

    #[serialize(skip)]
    weight_cache: OnceLock<T::Weight>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Short<T: Record> {
    #[serialize(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    pub key: Vec<u8>, // Hex
    pub val: Box<Node<T>>,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Value<T> {
    pub record: T,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Derivative)]
#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub enum Node<T: Record> {
    #[default]
    Empty,
    Full(Full<T>),
    Short(Short<T>),
    Hash(Multihash),
    Value(Value<T>),
}

impl<T: Record> Full<T> {
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

    pub fn clear_caches(&mut self) {
        self.hash_cache = OnceLock::new();
        self.weight_cache = OnceLock::new();
    }

    pub fn weight(&self) -> T::Weight {
        *self
            .weight_cache
            .get_or_init(|| self.children.iter().map(|child| child.weight()).sum())
    }
}

impl<T: Record> Short<T> {
    pub fn new<U: Into<Box<Node<T>>>>(key: Vec<u8>, val: U) -> Self {
        let val = val.into();

        Short {
            key,
            val,
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

    pub fn clear_cache(&mut self) {
        self.hash_cache = OnceLock::new();
    }
}

impl<T: Record> Value<T> {
    pub fn new(record: T) -> Self {
        Self {
            record,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self
            .hash_cache
            .get_or_init(|| H::hash(&self.record.to_vec()))
    }

    pub fn weight(&self) -> T::Weight {
        self.record.weight()
    }
}

impl<T: Record> Node<T> {
    pub fn new_short<U: Into<Box<Node<T>>>>(key: Vec<u8>, val: U) -> Self {
        Node::Short(Short::new(key, val))
    }

    pub fn new_value(record: T) -> Self {
        Node::Value(Value::new(record))
    }

    pub fn from_full(full: Full<T>) -> Self {
        Node::Full(full)
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    pub fn weight(&self) -> T::Weight {
        match self {
            Node::Full(full) => full.weight(),
            Node::Short(short) => short.val.weight(),
            Node::Value(value) => value.weight(),
            Node::Hash(_) | Node::Empty => T::Weight::default(),
        }
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

    pub fn as_short_mut(&mut self) -> Option<&mut Short<T>> {
        if let Node::Short(short) = self {
            Some(short)
        } else {
            None
        }
    }

    pub fn as_full_mut(&mut self) -> Option<&mut Full<T>> {
        if let Node::Full(full) = self {
            Some(full)
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

impl<T: Record> From<Full<T>> for Node<T> {
    fn from(full: Full<T>) -> Self {
        Node::Full(full)
    }
}

impl<T: Record> Default for Full<T> {
    fn default() -> Self {
        let children = std::array::from_fn(|_| Node::Empty);
        let children = Box::new(children);

        Full {
            children,
            hash_cache: OnceLock::new(),
            weight_cache: OnceLock::new(),
        }
    }
}
