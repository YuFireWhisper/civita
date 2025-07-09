use crate::{
    crypto::{Hasher, Multihash},
    traits::{serializable, Serializable},
    utils::mpt::{bytes_to_nibbles, node::Node},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Proof {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    nodes: Vec<Node>,
}

impl Proof {
    pub fn new_existence(key: Vec<u8>, value: Vec<u8>, nodes: Vec<Node>) -> Self {
        Proof {
            key,
            value: Some(value),
            nodes,
        }
    }

    pub fn new_non_existence(key: Vec<u8>, nodes: Vec<Node>) -> Self {
        Proof {
            key,
            value: None,
            nodes,
        }
    }

    pub fn is_existence(&self) -> bool {
        self.value.is_some()
    }

    pub fn is_non_existence(&self) -> bool {
        self.value.is_none()
    }

    pub fn verify<H: Hasher>(&self, root_hash: &Multihash) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let path = bytes_to_nibbles(&self.key);
        let mut cur_path = path.as_slice();
        let mut cur_hash = root_hash;

        if self.nodes.len() == 1 {
            return self.nodes[0].hash::<H>() == *cur_hash;
        }

        for (i, node) in self.nodes.iter().enumerate() {
            if node.hash::<H>() != *cur_hash {
                return false;
            }

            match &node {
                Node::Empty => {
                    return false;
                }
                Node::Leaf { path, value } => {
                    if i != self.nodes.len() - 1 {
                        return false;
                    }

                    if path != cur_path {
                        return self.is_non_existence();
                    }

                    if let Some(expected_value) = &self.value {
                        let stored_hash = H::hash(expected_value);
                        return value == &stored_hash;
                    } else {
                        return false;
                    }
                }

                Node::Extension { path, child } => {
                    if !cur_path.starts_with(path) {
                        return self.is_non_existence();
                    }

                    cur_path = &cur_path[path.len()..];
                    cur_hash = child;
                }
                Node::Branch { children, value } => {
                    if cur_path.is_empty() {
                        match (&self.value, value) {
                            (Some(expected_value), Some(stored_value)) => {
                                let stored_hash = H::hash(expected_value);
                                return stored_value == &stored_hash && i == self.nodes.len() - 1;
                            }
                            (None, None) => {
                                return i == self.nodes.len() - 1;
                            }
                            _ => return false,
                        }
                    }

                    let idx = cur_path[0] as usize;

                    if idx >= 16 {
                        return false;
                    }

                    if let Some(child) = &children[idx] {
                        cur_path = &cur_path[1..];
                        cur_hash = child;
                    } else {
                        return self.is_non_existence();
                    }
                }
            }
        }

        false
    }

    pub fn verify_existence<H: Hasher>(&self, root_hash: &Multihash, key: &[u8]) -> bool {
        self.key == key && self.is_existence() && self.verify::<H>(root_hash)
    }

    pub fn verify_non_existence<H: Hasher>(&self, root_hash: &Multihash, key: &[u8]) -> bool {
        self.key == key && self.is_non_existence() && self.verify::<H>(root_hash)
    }

    pub fn verify_with_key<H: Hasher>(&self, root_hash: &Multihash, key: &[u8]) -> bool {
        self.key == key && self.verify::<H>(root_hash)
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> Option<&Vec<u8>> {
        self.value.as_ref()
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn nodes_into(self) -> Vec<Node> {
        self.nodes
    }
}

impl Serializable for Proof {
    fn serialized_size(&self) -> usize {
        self.key.serialized_size() + self.value.serialized_size() + self.nodes.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            key: Vec::from_reader(reader)?,
            value: Option::from_reader(reader)?,
            nodes: Vec::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.key.to_writer(writer)?;
        self.value.to_writer(writer)?;
        self.nodes.to_writer(writer)?;
        Ok(())
    }
}
