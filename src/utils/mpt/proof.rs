use crate::{
    crypto::{Hasher, Multihash},
    utils::mpt::node::Node,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct ExistenceProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub nodes: Vec<Node>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct NonExistenceProof {
    pub key: Vec<u8>,
    pub nodes: Vec<Node>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Proof {
    Existence(ExistenceProof),
    NonExistence(NonExistenceProof),
}

impl ExistenceProof {
    pub fn verify<H: Hasher>(&self, root_hash: &Multihash) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let mut cur_path = self.key.as_slice();
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

                    let value_hash = H::hash(&self.value);

                    return path == cur_path && value == &value_hash;
                }

                Node::Extension { path, child } => {
                    if !cur_path.starts_with(path) {
                        return false;
                    }

                    cur_path = &cur_path[path.len()..];
                    cur_hash = child;
                }
                Node::Branch { children, value } => {
                    if cur_path.is_empty() {
                        return value.as_ref().is_some_and(|v| v == &H::hash(&self.value))
                            && i == self.nodes.len() - 1;
                    }

                    let idx = cur_path[0] as usize;

                    if idx >= 16 {
                        return false;
                    }

                    if let Some(child) = &children[idx] {
                        cur_path = &cur_path[1..];
                        cur_hash = child;
                    } else {
                        return false;
                    }
                }
            }
        }

        false
    }
}

impl NonExistenceProof {
    pub fn verify<H: Hasher>(&self, root_hash: &Multihash) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let mut cur_path = self.key.as_slice();
        let mut cur_hash = root_hash;

        if self.nodes.len() == 1 {
            return self.nodes[0].hash::<H>() == *cur_hash;
        }

        for node in &self.nodes {
            if node.hash::<H>() != *cur_hash {
                return false;
            }

            match &node {
                Node::Empty => {
                    return false;
                }
                Node::Leaf { path, .. } => {
                    return path != cur_path;
                }
                Node::Extension { path, child } => {
                    if !cur_path.starts_with(path) {
                        return false;
                    }

                    cur_path = &cur_path[path.len()..];
                    cur_hash = child;
                }
                Node::Branch { children, value } => {
                    if cur_path.is_empty() {
                        return value.is_none();
                    }

                    let idx = cur_path[0] as usize;

                    if idx >= 16 {
                        return false;
                    }

                    if let Some(child) = &children[idx] {
                        cur_path = &cur_path[1..];
                        cur_hash = child;
                    }
                }
            }
        }

        false
    }
}

impl Proof {
    pub fn new_existence(key: Vec<u8>, value: Vec<u8>, nodes: Vec<Node>) -> Self {
        Proof::Existence(ExistenceProof { key, value, nodes })
    }

    pub fn new_non_existence(key: Vec<u8>, nodes: Vec<Node>) -> Self {
        Proof::NonExistence(NonExistenceProof { key, nodes })
    }

    pub fn verify<H: Hasher>(&self, root_hash: &Multihash) -> bool {
        match self {
            Proof::Existence(p) => p.verify::<H>(root_hash),
            Proof::NonExistence(p) => p.verify::<H>(root_hash),
        }
    }

    pub fn key(&self) -> &[u8] {
        match self {
            Proof::Existence(p) => &p.key,
            Proof::NonExistence(p) => &p.key,
        }
    }

    pub fn nodes(&self) -> &[Node] {
        match self {
            Proof::Existence(p) => &p.nodes,
            Proof::NonExistence(p) => &p.nodes,
        }
    }

    pub fn nodes_into(self) -> Vec<Node> {
        match self {
            Proof::Existence(p) => p.nodes,
            Proof::NonExistence(p) => p.nodes,
        }
    }
}
