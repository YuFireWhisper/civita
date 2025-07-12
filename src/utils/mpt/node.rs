use crate::{
    crypto::Multihash,
    traits::{serializable, Serializable},
    utils::mpt::keys::{hex_to_vec, vec_to_hex},
};

pub(super) const EMPTY_TAG: u8 = 0x00;
pub(super) const FULL_TAG: u8 = 0x01;
pub(super) const SHORT_TAG: u8 = 0x02;
pub(super) const HASH_TAG: u8 = 0x03;
pub(super) const VALUE_TAG: u8 = 0x04;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Flags {
    pub hash: Option<Multihash>,
    pub is_dirty: bool,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
pub struct Full {
    pub children: Box<[Node; 17]>,
    pub flags: Flags,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Short {
    pub key: Vec<u8>, // Hex
    pub val: Box<Node>,
    pub flags: Flags,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
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

impl Serializable for Full {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let mut children = std::array::from_fn(|_| Node::Empty);

        for child in children.iter_mut() {
            *child = Node::from_reader(reader)?;
        }

        Ok(Full {
            children: children.into(),
            flags: Flags::default(),
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        FULL_TAG.to_writer(writer);
        self.children
            .iter()
            .for_each(|child| child.to_writer(writer));
    }
}

impl Serializable for Short {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let len = u8::from_reader(reader)?;
        let mut vec = vec![0u8; len as usize];
        reader.read_exact(&mut vec)?;

        let key = vec_to_hex(vec);

        Ok(Short {
            key,
            val: Box::new(Node::from_reader(reader)?),
            flags: Flags::default(),
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        SHORT_TAG.to_writer(writer);

        let vec = hex_to_vec(&self.key);
        let len = vec.len() as u8;

        len.to_writer(writer);
        writer.write_all(&vec).expect("Failed to write key");

        self.val.to_writer(writer);
    }
}

impl Serializable for Node {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let tag = u8::from_reader(reader)?;

        match tag {
            EMPTY_TAG => Ok(Node::Empty),
            FULL_TAG => {
                let full = Full::from_reader(reader)?;
                Ok(Node::Full(full))
            }
            SHORT_TAG => {
                let short = Short::from_reader(reader)?;
                Ok(Node::Short(short))
            }
            HASH_TAG => {
                let hash = Multihash::from_reader(reader)?;
                Ok(Node::Hash(hash))
            }
            VALUE_TAG => {
                let value = Vec::from_reader(reader)?;
                Ok(Node::Value(value))
            }
            _ => Err(serializable::Error(format!("Unknown tag: {tag}"))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        match self {
            Node::Empty => EMPTY_TAG.to_writer(writer),
            Node::Full(full) => {
                // full will write its own tag
                full.to_writer(writer);
            }
            Node::Short(short) => {
                // short will write its own tag
                short.to_writer(writer);
            }
            Node::Hash(hash) => {
                HASH_TAG.to_writer(writer);
                hash.to_writer(writer);
            }
            Node::Value(value) => {
                VALUE_TAG.to_writer(writer);
                value.to_writer(writer);
            }
        }
    }
}
