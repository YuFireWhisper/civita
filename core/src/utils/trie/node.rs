use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::{
    crypto::Multihash,
    utils::trie::keys::{hex_to_vec, vec_to_hex},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Flags {
    pub hash: Option<Multihash>,
    pub is_dirty: bool,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Full {
    pub children: Box<[Node; 17]>,
    pub flags: Flags,
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
    pub flags: Flags,
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
    Value(Vec<u8>),
}

impl Full {
    pub fn new<T: Into<Box<[Node; 17]>>>(children: T) -> Self {
        Full {
            children: children.into(),
            flags: Flags::default(),
        }
    }

    pub fn cache(&self) -> Option<&Multihash> {
        if self.flags.is_dirty {
            None
        } else {
            self.flags.hash.as_ref()
        }
    }

    pub fn cache_into(self) -> Option<Multihash> {
        if self.flags.is_dirty {
            None
        } else {
            self.flags.hash
        }
    }
}

impl Short {
    pub fn new<T: Into<Box<Node>>>(key: Vec<u8>, val: T) -> Self {
        Short {
            key,
            val: val.into(),
            flags: Flags::default(),
        }
    }

    pub fn cache(&self) -> Option<&Multihash> {
        if self.flags.is_dirty {
            None
        } else {
            self.flags.hash.as_ref()
        }
    }

    pub fn cache_into(self) -> Option<Multihash> {
        if self.flags.is_dirty {
            None
        } else {
            self.flags.hash
        }
    }
}

impl Node {
    pub fn new_full(node: Full) -> Self {
        Node::Full(node)
    }

    pub fn new_short(node: Short) -> Self {
        Node::Short(node)
    }

    pub fn into_full(self) -> Full {
        match self {
            Node::Full(full) => full,
            _ => panic!("Node is not a Full node"),
        }
    }

    pub fn into_short(self) -> Short {
        match self {
            Node::Short(short) => short,
            _ => panic!("Node is not a Short node"),
        }
    }

    pub fn into_hash(self) -> Multihash {
        match self {
            Node::Hash(hash) => hash,
            _ => panic!("Node is not a Hash node"),
        }
    }

    pub fn into_value(self) -> Vec<u8> {
        match self {
            Node::Value(value) => value,
            _ => panic!("Node is not a Value node"),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    pub fn is_full(&self) -> bool {
        matches!(self, Node::Full { .. })
    }

    pub fn is_short(&self) -> bool {
        matches!(self, Node::Short { .. })
    }

    pub fn is_hash(&self) -> bool {
        matches!(self, Node::Hash(_))
    }

    pub fn is_value(&self) -> bool {
        matches!(self, Node::Value(_))
    }

    pub fn cache(&self) -> Option<&Multihash> {
        match self {
            Node::Full(full) => full.cache(),
            Node::Short(short) => short.cache(),
            _ => None,
        }
    }

    pub fn cache_into(self) -> Option<Multihash> {
        match self {
            Node::Full(full) => full.cache_into(),
            Node::Short(short) => short.cache_into(),
            _ => None,
        }
    }
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            hash: None,
            is_dirty: true,
        }
    }
}

fn serialize_key<W: std::io::Write>(key: &[u8], writer: &mut W) {
    hex_to_vec(key).to_writer(writer);
}

fn deserialize_key<R: std::io::Read>(reader: &mut R) -> Result<Vec<u8>, civita_serialize::Error> {
    Vec::from_reader(reader).map(vec_to_hex)
}
