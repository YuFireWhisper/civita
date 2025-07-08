use crate::{
    crypto::{Hasher, Multihash},
    traits::serializable::{self, ConstantSize, Serializable},
    utils::mpt::{Nibble, Path},
};

const EMPTY_PREFIX: u8 = 0x00;
const LEAF_PREFIX: u8 = 0x01;
const EXTENSION_PREFIX: u8 = 0x02;
const BRANCH_PREFIX: u8 = 0x03;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
pub enum Node {
    #[default]
    Empty,
    Leaf {
        path: Path,
        value: Multihash,
    },
    Extension {
        path: Path,
        child: Multihash,
    },
    Branch {
        children: Box<[Option<Multihash>; 16]>,
        value: Option<Multihash>,
    },
}

impl Node {
    pub fn new_leaf(path: Path, value: Multihash) -> Self {
        Node::Leaf { path, value }
    }

    pub fn new_extension(path: Path, child: Multihash) -> Self {
        Node::Extension { path, child }
    }

    pub fn new_branch(children: Box<[Option<Multihash>; 16]>, value: Option<Multihash>) -> Self {
        Node::Branch { children, value }
    }

    pub fn new_branch_from_other(&self, value: Option<Multihash>) -> Self {
        match self {
            Node::Branch { children, .. } => Node::Branch {
                children: children.clone(),
                value,
            },
            _ => panic!("Cannot create branch from non-branch node"),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        match self {
            Node::Empty => H::hash(&[]),
            _ => H::hash(&self.to_vec().expect("Node serialization should not fail")),
        }
    }
}

impl Serializable for Node {
    fn serialized_size(&self) -> usize {
        Nibble::SIZE
            + match self {
                Node::Empty => Nibble::SIZE,
                Node::Leaf { path, value } => path.serialized_size() + value.serialized_size(),
                Node::Extension { path, child } => path.serialized_size() + child.serialized_size(),
                Node::Branch { children, value } => {
                    children
                        .iter()
                        .map(|c| c.as_ref().map_or(0, |c| c.serialized_size()))
                        .sum::<usize>()
                        + value.serialized_size()
                }
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let prefix = u8::from_reader(reader)?;

        match prefix {
            EMPTY_PREFIX => Ok(Node::Empty),
            LEAF_PREFIX => Ok(Node::Leaf {
                path: Vec::from_reader(reader)?,
                value: Multihash::from_reader(reader)?,
            }),
            EXTENSION_PREFIX => Ok(Node::Extension {
                path: Vec::from_reader(reader)?,
                child: Multihash::from_reader(reader)?,
            }),
            BRANCH_PREFIX => {
                let mut children: [Option<Multihash>; 16] = std::array::from_fn(|_| None);
                children.iter_mut().try_for_each(|child| {
                    *child = Option::from_reader(reader)?;
                    Ok::<(), serializable::Error>(())
                })?;
                let value = Option::from_reader(reader)?;
                Ok(Node::Branch {
                    children: children.into(),
                    value,
                })
            }
            _ => Err(serializable::Error(format!(
                "Unknown node prefix: {prefix}"
            ))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        match self {
            Node::Empty => {
                EMPTY_PREFIX.to_writer(writer)?;
            }
            Node::Leaf { path, value } => {
                LEAF_PREFIX.to_writer(writer)?;
                path.to_writer(writer)?;
                value.to_writer(writer)?;
            }
            Node::Extension { path, child } => {
                EXTENSION_PREFIX.to_writer(writer)?;
                path.to_writer(writer)?;
                child.to_writer(writer)?;
            }
            Node::Branch { children, value } => {
                BRANCH_PREFIX.to_writer(writer)?;
                for child in children.iter() {
                    child.to_writer(writer)?;
                }
                value.to_writer(writer)?;
            }
        }
        Ok(())
    }
}
