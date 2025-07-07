use crate::{
    crypto::{Hasher, Multihash},
    traits::{serializable, ConstantSize, Serializable},
    utils::mpt::{Nibble, Path},
};

const EMPTY_PREFIX: u8 = 0x00;
const LEAF_PREFIX: u8 = 0x01;
const EXTENSION_PREFIX: u8 = 0x02;
const BRANCH_PREFIX: u8 = 0x03;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Node<T> {
    Empty,
    Leaf {
        path: Path,
        value: T,
    },
    Extension {
        path: Path,
        child: Multihash,
    },
    Branch {
        children: Box<[Option<Multihash>; 16]>,
        value: Option<T>,
    },
}

impl<T> Node<T>
where
    T: Serializable,
{
    pub fn hash<H: Hasher>(&self) -> Multihash {
        match self {
            Node::Empty => H::hash(&[]),
            _ => H::hash(&self.to_vec().expect("Node serialization should not fail")),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }
}

impl<T: Serializable> Serializable for Node<T> {
    fn serialized_size(&self) -> usize {
        match self {
            Node::Empty => Nibble::SIZE,
            Node::Leaf { path, value } => {
                Nibble::SIZE + path.serialized_size() + value.serialized_size()
            }
            Node::Extension { path, child } => {
                Nibble::SIZE + path.serialized_size() + child.serialized_size()
            }
            Node::Branch { children, value } => {
                Nibble::SIZE
                    + children.iter().map(|c| c.serialized_size()).sum::<usize>()
                    + value.serialized_size()
            }
        }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let prefix = u8::from_reader(reader)?;

        match prefix {
            LEAF_PREFIX => Ok(Node::Leaf {
                path: Vec::from_reader(reader)?,
                value: T::from_reader(reader)?,
            }),
            EXTENSION_PREFIX => Ok(Node::Extension {
                path: Vec::from_reader(reader)?,
                child: Multihash::from_reader(reader)?,
            }),
            BRANCH_PREFIX => Ok(Node::Branch {
                children: {
                    let mut children = [None; 16];
                    children.iter_mut().try_for_each(|child| {
                        *child = Some(Multihash::from_reader(reader)?);
                        Ok::<_, serializable::Error>(())
                    })?;
                    Box::new(children)
                },
                value: T::from_reader(reader).ok(),
            }),
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
