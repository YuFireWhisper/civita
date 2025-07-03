use std::collections::BTreeMap;

use crate::{
    crypto::{Hasher, Multihash},
    traits::{serializable, ConstantSize, Serializable},
    utils::mpt::Nibble,
};

const LEAF_PREFIX: u8 = 0x00;
const EXTENSION_PREFIX: u8 = 0x01;
const BRANCH_PREFIX: u8 = 0x02;

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub struct Leaf<V> {
    pub path: Vec<Nibble>,
    pub value: V,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub struct Extension {
    pub path: Vec<Nibble>,
    pub child: Multihash,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub struct Branch<V> {
    pub children: BTreeMap<Nibble, Multihash>,
    pub value: Option<V>,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub enum Node<V> {
    Empty,
    Leaf(Leaf<V>),
    Extension(Extension),
    Branch(Branch<V>),
}

impl<V> Node<V> {
    pub fn new_leaf(remained: Vec<Nibble>, value: V) -> Self {
        Node::Leaf(Leaf {
            path: remained,
            value,
        })
    }

    pub fn new_extension(prefix: Vec<Nibble>, next: Multihash) -> Self {
        Node::Extension(Extension {
            path: prefix,
            child: next,
        })
    }

    pub fn new_branch(children: BTreeMap<Nibble, Multihash>, value: Option<V>) -> Self {
        Node::Branch(Branch { children, value })
    }
}

impl<V: Serializable> Node<V> {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        match self {
            Node::Empty => H::hash(&[]),
            _ => H::hash(&self.to_vec().expect("Node serialization should not fail")),
        }
    }
}

impl<V: Serializable> Serializable for Node<V> {
    fn serialized_size(&self) -> usize {
        let prefix_size = u8::SIZE;

        match self {
            Node::Empty => prefix_size,
            Node::Leaf(leaf) => {
                prefix_size + leaf.path.serialized_size() + leaf.value.serialized_size()
            }
            Node::Extension(ext) => {
                prefix_size + ext.path.serialized_size() + ext.child.serialized_size()
            }
            Node::Branch(branch) => {
                prefix_size + branch.children.serialized_size() + branch.value.serialized_size()
            }
        }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let prefix = u8::from_reader(reader)?;

        match prefix {
            LEAF_PREFIX => {
                let remained = Vec::<Nibble>::from_reader(reader)?;
                let value = V::from_reader(reader)?;
                Ok(Node::Leaf(Leaf {
                    path: remained,
                    value,
                }))
            }
            EXTENSION_PREFIX => {
                let prefix = Vec::<Nibble>::from_reader(reader)?;
                let next = Multihash::from_reader(reader)?;
                Ok(Node::Extension(Extension {
                    path: prefix,
                    child: next,
                }))
            }
            BRANCH_PREFIX => {
                let children = BTreeMap::<Nibble, Multihash>::from_reader(reader)?;
                let value = Option::<V>::from_reader(reader)?;
                Ok(Node::Branch(Branch { children, value }))
            }
            _ => Err(serializable::Error(format!(
                "Unknown node prefix: {}",
                prefix
            ))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        let prefix = match self {
            Node::Empty => LEAF_PREFIX,
            Node::Leaf(_) => LEAF_PREFIX,
            Node::Extension(_) => EXTENSION_PREFIX,
            Node::Branch(_) => BRANCH_PREFIX,
        };

        prefix.to_writer(writer)?;

        match self {
            Node::Empty => {}
            Node::Leaf(leaf) => {
                leaf.path.to_writer(writer)?;
                leaf.value.to_writer(writer)?;
            }
            Node::Extension(ext) => {
                ext.path.to_writer(writer)?;
                ext.child.to_writer(writer)?;
            }
            Node::Branch(branch) => {
                branch.children.to_writer(writer)?;
                branch.value.to_writer(writer)?;
            }
        }

        Ok(())
    }
}
