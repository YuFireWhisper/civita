use crate::{
    crypto::{Hasher, Multihash},
    traits::Serializable,
    utils::mpt::{
        node::Node,
        proof::{ExistenceProof, NonExistenceProof},
    },
};
use std::collections::HashMap;

mod node;
pub mod proof;

pub use proof::Proof;

pub type Nibble = u8; // 0-15
pub type Path = Vec<Nibble>;
type Result<T, E> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid proof")]
    InvalidProof,

    #[error("Key not found")]
    KeyNotFound,

    #[error("Invalid node structure")]
    InvalidNode,

    #[error("Partial mode operation not supported")]
    PartialModeUnsupported,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum StorageMode {
    Partial,
    Full,
}

pub struct MerklePatriciaTrie<T> {
    root_hash: Multihash,
    storage: HashMap<Multihash, Node<T>>,
    mode: StorageMode,
}

impl<T> MerklePatriciaTrie<T>
where
    T: Clone + Eq + Serializable + Send + Sync + 'static,
{
    pub fn new(mode: StorageMode) -> Self {
        Self {
            root_hash: Multihash::default(),
            storage: HashMap::new(),
            mode,
        }
    }

    pub fn from_proof<H: Hasher>(proof: Proof<T>) -> Result<Self, Error> {
        let mut storage = HashMap::new();
        let mut root_hash = Multihash::default();

        for node in proof.proof_nodes() {
            let hash = node.hash::<H>();
            storage.insert(hash, node.clone());
        }

        if let Some(first_node) = proof.proof_nodes().first() {
            root_hash = first_node.hash::<H>();
        }

        Ok(Self {
            root_hash,
            storage,
            mode: StorageMode::Partial,
        })
    }

    pub fn root_hash(&self) -> Multihash {
        self.root_hash
    }

    pub fn insert<H: Hasher>(&mut self, key: &[u8], value: T) -> Result<(), Error> {
        match self.mode {
            StorageMode::Partial => Err(Error::PartialModeUnsupported),
            StorageMode::Full => {
                let path = bytes_to_nibbles(key);
                let new_root = self.insert_recursive::<H>(&path, value, &self.root_hash.clone())?;
                self.root_hash = new_root;
                Ok(())
            }
        }
    }

    fn insert_recursive<H: Hasher>(
        &mut self,
        path: &[Nibble],
        value: T,
        current_hash: &Multihash,
    ) -> Result<Multihash, Error> {
        let current_node = self
            .storage
            .get(current_hash)
            .cloned()
            .unwrap_or(Node::Empty);

        let new_node = match current_node {
            Node::Empty => Node::Leaf {
                path: path.to_vec(),
                value,
            },
            Node::Leaf {
                path: leaf_path,
                value: leaf_value,
            } => {
                if leaf_path == path {
                    Node::Leaf {
                        path: leaf_path,
                        value,
                    }
                } else {
                    return self.handle_leaf_collision::<H>(leaf_path, leaf_value, path, value);
                }
            }
            Node::Extension {
                path: ext_path,
                child,
            } => {
                return self.handle_extension_insert::<H>(ext_path, child, path, value);
            }
            Node::Branch {
                mut children,
                value: mut branch_value,
            } => {
                if path.is_empty() {
                    branch_value = Some(value);
                    Node::Branch {
                        children,
                        value: branch_value,
                    }
                } else {
                    let idx = path[0] as usize;
                    let child_hash = children[idx].unwrap_or_default();
                    let new_child_hash =
                        self.insert_recursive::<H>(&path[1..], value, &child_hash)?;
                    children[idx] = Some(new_child_hash);
                    Node::Branch {
                        children,
                        value: branch_value,
                    }
                }
            }
        };

        let new_hash = new_node.hash::<H>();
        self.storage.insert(new_hash, new_node);
        Ok(new_hash)
    }

    fn handle_leaf_collision<H: Hasher>(
        &mut self,
        leaf_path: Path,
        leaf_value: T,
        new_path: &[Nibble],
        new_value: T,
    ) -> Result<Multihash, Error> {
        let common_prefix = common_prefix(&leaf_path, new_path);
        let common_len = common_prefix.len();

        if common_len == 0 {
            let mut children = [None; 16];

            let leaf_remaining = &leaf_path[1..];
            let new_remaining = &new_path[1..];

            let leaf_node = if leaf_remaining.is_empty() {
                Node::Leaf {
                    path: vec![],
                    value: leaf_value,
                }
            } else {
                Node::Leaf {
                    path: leaf_remaining.to_vec(),
                    value: leaf_value,
                }
            };

            let new_node = if new_remaining.is_empty() {
                Node::Leaf {
                    path: vec![],
                    value: new_value,
                }
            } else {
                Node::Leaf {
                    path: new_remaining.to_vec(),
                    value: new_value,
                }
            };

            let leaf_hash = leaf_node.hash::<H>();
            let new_hash = new_node.hash::<H>();

            self.storage.insert(leaf_hash, leaf_node);
            self.storage.insert(new_hash, new_node);

            children[leaf_path[0] as usize] = Some(leaf_hash);
            children[new_path[0] as usize] = Some(new_hash);

            let branch = Node::Branch {
                children: Box::new(children),
                value: None,
            };
            let branch_hash = branch.hash::<H>();
            self.storage.insert(branch_hash, branch);
            Ok(branch_hash)
        } else {
            let branch_hash = self.create_divergent_branch::<H>(
                &leaf_path[common_len..],
                leaf_value,
                &new_path[common_len..],
                new_value,
            )?;

            let extension = Node::Extension {
                path: common_prefix,
                child: branch_hash,
            };
            let ext_hash = extension.hash::<H>();
            self.storage.insert(ext_hash, extension);
            Ok(ext_hash)
        }
    }

    fn create_divergent_branch<H: Hasher>(
        &mut self,
        leaf_remaining: &[Nibble],
        leaf_value: T,
        new_remaining: &[Nibble],
        new_value: T,
    ) -> Result<Multihash, Error> {
        let mut children = [None; 16];

        let leaf_node = if leaf_remaining.len() == 1 {
            Node::Leaf {
                path: vec![],
                value: leaf_value,
            }
        } else {
            Node::Leaf {
                path: leaf_remaining[1..].to_vec(),
                value: leaf_value,
            }
        };

        let new_node = if new_remaining.len() == 1 {
            Node::Leaf {
                path: vec![],
                value: new_value,
            }
        } else {
            Node::Leaf {
                path: new_remaining[1..].to_vec(),
                value: new_value,
            }
        };

        let leaf_hash = leaf_node.hash::<H>();
        let new_hash = new_node.hash::<H>();

        self.storage.insert(leaf_hash, leaf_node);
        self.storage.insert(new_hash, new_node);

        children[leaf_remaining[0] as usize] = Some(leaf_hash);
        children[new_remaining[0] as usize] = Some(new_hash);

        let branch = Node::Branch {
            children: Box::new(children),
            value: None,
        };
        let branch_hash = branch.hash::<H>();
        self.storage.insert(branch_hash, branch);
        Ok(branch_hash)
    }

    fn handle_extension_insert<H: Hasher>(
        &mut self,
        ext_path: Path,
        child: Multihash,
        path: &[Nibble],
        value: T,
    ) -> Result<Multihash, Error> {
        let common_prefix = common_prefix(&ext_path, path);
        let common_len = common_prefix.len();

        if common_len == ext_path.len() {
            let remaining_path = &path[ext_path.len()..];
            let new_child = self.insert_recursive::<H>(remaining_path, value, &child)?;
            let new_extension = Node::Extension {
                path: ext_path,
                child: new_child,
            };
            let new_hash = new_extension.hash::<H>();
            self.storage.insert(new_hash, new_extension);
            Ok(new_hash)
        } else {
            let branch_hash = self.create_extension_branch::<H>(
                &ext_path[common_len..],
                child,
                &path[common_len..],
                value,
            )?;

            if common_len == 0 {
                Ok(branch_hash)
            } else {
                let new_extension = Node::Extension {
                    path: common_prefix,
                    child: branch_hash,
                };
                let new_hash = new_extension.hash::<H>();
                self.storage.insert(new_hash, new_extension);
                Ok(new_hash)
            }
        }
    }

    fn create_extension_branch<H: Hasher>(
        &mut self,
        ext_remaining: &[Nibble],
        old_child: Multihash,
        new_remaining: &[Nibble],
        new_value: T,
    ) -> Result<Multihash, Error> {
        let mut children = [None; 16];

        let old_node = if ext_remaining.len() == 1 {
            Node::Extension {
                path: vec![],
                child: old_child,
            }
        } else {
            Node::Extension {
                path: ext_remaining[1..].to_vec(),
                child: old_child,
            }
        };

        let new_node = if new_remaining.len() == 1 {
            Node::Leaf {
                path: vec![],
                value: new_value,
            }
        } else {
            Node::Leaf {
                path: new_remaining[1..].to_vec(),
                value: new_value,
            }
        };

        let old_hash = old_node.hash::<H>();
        let new_hash = new_node.hash::<H>();

        self.storage.insert(old_hash, old_node);
        self.storage.insert(new_hash, new_node);

        children[ext_remaining[0] as usize] = Some(old_hash);
        children[new_remaining[0] as usize] = Some(new_hash);

        let branch = Node::Branch {
            children: Box::new(children),
            value: None,
        };
        let branch_hash = branch.hash::<H>();
        self.storage.insert(branch_hash, branch);
        Ok(branch_hash)
    }

    pub fn get(&self, key: &[u8]) -> Option<T> {
        let path = bytes_to_nibbles(key);
        self.get_recursive(&path, &self.root_hash)
    }

    fn get_recursive(&self, path: &[Nibble], current_hash: &Multihash) -> Option<T> {
        let node = self.storage.get(current_hash)?;

        match node {
            Node::Empty => None,
            Node::Leaf {
                path: leaf_path,
                value,
            } => {
                if leaf_path == path {
                    Some(value.clone())
                } else {
                    None
                }
            }
            Node::Extension {
                path: ext_path,
                child,
            } => {
                if path.len() >= ext_path.len() && path.starts_with(ext_path) {
                    self.get_recursive(&path[ext_path.len()..], child)
                } else {
                    None
                }
            }
            Node::Branch { children, value } => {
                if path.is_empty() {
                    value.clone()
                } else {
                    let idx = path[0] as usize;
                    if let Some(child_hash) = &children[idx] {
                        self.get_recursive(&path[1..], child_hash)
                    } else {
                        None
                    }
                }
            }
        }
    }

    pub fn generate_proof<H: Hasher>(&self, key: &[u8]) -> Result<Proof<T>, Error> {
        match self.mode {
            StorageMode::Partial => Err(Error::PartialModeUnsupported),
            StorageMode::Full => {
                let path = bytes_to_nibbles(key);
                let mut proof_nodes = Vec::new();

                match self.collect_proof_nodes(&path, &self.root_hash, &mut proof_nodes) {
                    Some(value) => Ok(Proof::Existence(ExistenceProof {
                        key: key.to_vec(),
                        value,
                        proof_nodes,
                    })),
                    None => Ok(Proof::NonExistence(NonExistenceProof {
                        key: key.to_vec(),
                        proof_nodes,
                    })),
                }
            }
        }
    }

    fn collect_proof_nodes(
        &self,
        path: &[Nibble],
        current_hash: &Multihash,
        proof_nodes: &mut Vec<Node<T>>,
    ) -> Option<T> {
        let node = self.storage.get(current_hash)?;
        proof_nodes.push(node.clone());

        match node {
            Node::Empty => None,
            Node::Leaf {
                path: leaf_path,
                value,
            } => {
                if leaf_path == path {
                    Some(value.clone())
                } else {
                    None
                }
            }
            Node::Extension {
                path: ext_path,
                child,
            } => {
                if path.len() >= ext_path.len() && path.starts_with(ext_path) {
                    self.collect_proof_nodes(&path[ext_path.len()..], child, proof_nodes)
                } else {
                    None
                }
            }
            Node::Branch { children, value } => {
                if path.is_empty() {
                    value.clone()
                } else {
                    let idx = path[0] as usize;
                    if let Some(child_hash) = &children[idx] {
                        self.collect_proof_nodes(&path[1..], child_hash, proof_nodes)
                    } else {
                        None
                    }
                }
            }
        }
    }

    pub fn verify_proof<H: Hasher>(&self, proof: &Proof<T>) -> bool {
        match proof {
            Proof::Existence(existence_proof) => self.verify_existence_proof::<H>(existence_proof),
            Proof::NonExistence(non_existence_proof) => {
                self.verify_non_existence_proof::<H>(non_existence_proof)
            }
        }
    }

    fn verify_existence_proof<H: Hasher>(&self, proof: &ExistenceProof<T>) -> bool {
        let path = bytes_to_nibbles(&proof.key);
        let computed_root = self.compute_root_from_proof::<H>(&proof.proof_nodes, &path);

        match computed_root {
            Some(root_hash) => root_hash == self.root_hash,
            None => false,
        }
    }

    fn verify_non_existence_proof<H: Hasher>(&self, proof: &NonExistenceProof<T>) -> bool {
        let path = bytes_to_nibbles(&proof.key);

        if proof.proof_nodes.is_empty() {
            return self.root_hash == Multihash::default();
        }

        let mut node_map = HashMap::new();
        for node in &proof.proof_nodes {
            let hash = node.hash::<H>();
            node_map.insert(hash, node);
        }

        let root_node = proof.proof_nodes.first().unwrap();
        let root_hash = root_node.hash::<H>();

        if root_hash != self.root_hash {
            return false;
        }

        Self::verify_non_existence_path(&node_map, &path, &root_hash)
    }

    fn verify_non_existence_path(
        node_map: &HashMap<Multihash, &Node<T>>,
        path: &[Nibble],
        current_hash: &Multihash,
    ) -> bool {
        let node = match node_map.get(current_hash) {
            Some(node) => node,
            None => return false,
        };

        match node {
            Node::Empty => true,
            Node::Leaf {
                path: leaf_path, ..
            } => leaf_path != path,
            Node::Extension {
                path: ext_path,
                child,
            } => {
                if path.len() >= ext_path.len() && path.starts_with(ext_path) {
                    Self::verify_non_existence_path(node_map, &path[ext_path.len()..], child)
                } else {
                    true
                }
            }
            Node::Branch { children, value } => {
                if path.is_empty() {
                    value.is_none()
                } else {
                    let idx = path[0] as usize;
                    match &children[idx] {
                        Some(child_hash) => {
                            Self::verify_non_existence_path(node_map, &path[1..], child_hash)
                        }
                        None => true,
                    }
                }
            }
        }
    }

    fn compute_root_from_proof<H: Hasher>(
        &self,
        proof_nodes: &[Node<T>],
        target_path: &[Nibble],
    ) -> Option<Multihash> {
        if proof_nodes.is_empty() {
            return None;
        }

        let mut node_map = HashMap::new();
        for node in proof_nodes {
            let hash = node.hash::<H>();
            node_map.insert(hash, node);
        }

        let root_node = proof_nodes.first()?;
        let root_hash = root_node.hash::<H>();

        Self::verify_path_consistency(&node_map, target_path, &root_hash)?;

        Some(root_hash)
    }

    fn verify_path_consistency(
        node_map: &HashMap<Multihash, &Node<T>>,
        path: &[Nibble],
        current_hash: &Multihash,
    ) -> Option<()> {
        let node = node_map.get(current_hash)?;

        match node {
            Node::Empty => Some(()),
            Node::Leaf {
                path: leaf_path, ..
            } => {
                if leaf_path == path {
                    Some(())
                } else {
                    None
                }
            }
            Node::Extension {
                path: ext_path,
                child,
            } => {
                if path.len() >= ext_path.len() && path.starts_with(ext_path) {
                    Self::verify_path_consistency(node_map, &path[ext_path.len()..], child)
                } else {
                    None
                }
            }
            Node::Branch { children, .. } => {
                if path.is_empty() {
                    Some(())
                } else {
                    let idx = path[0] as usize;
                    if let Some(child_hash) = &children[idx] {
                        Self::verify_path_consistency(node_map, &path[1..], child_hash)
                    } else {
                        None
                    }
                }
            }
        }
    }
}

fn bytes_to_nibbles(bytes: &[u8]) -> Path {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        nibbles.push((byte >> 4) & 0xF);
        nibbles.push(byte & 0xF);
    }
    nibbles
}

fn common_prefix(a: &[Nibble], b: &[Nibble]) -> Path {
    a.iter()
        .zip(b.iter())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| *x)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn successful_insert_and_get() {
        let mut mpt = MerklePatriciaTrie::new(StorageMode::Full);

        mpt.insert::<Sha256>(b"key1", "value1".to_string()).unwrap();
        mpt.insert::<Sha256>(b"key2", "value2".to_string()).unwrap();

        assert_eq!(mpt.get(b"key1"), Some("value1".to_string()));
        assert_eq!(mpt.get(b"key2"), Some("value2".to_string()));
        assert_eq!(mpt.get(b"key3"), None);
    }

    #[test]
    fn proof_generation_and_verification() {
        let mut mpt = MerklePatriciaTrie::new(StorageMode::Full);

        mpt.insert::<Sha256>(b"key1", "value1".to_string()).unwrap();
        mpt.insert::<Sha256>(b"key2", "value2".to_string()).unwrap();

        let proof = mpt.generate_proof::<Sha256>(b"key1").unwrap();
        let non_existence_proof = mpt.generate_proof::<Sha256>(b"key3").unwrap();

        assert!(mpt.verify_proof::<Sha256>(&proof));
        assert!(mpt.verify_proof::<Sha256>(&non_existence_proof));
    }

    #[test]
    fn return_false_when_proof_is_invalid() {
        let mut mpt = MerklePatriciaTrie::new(StorageMode::Full);
        mpt.insert::<Sha256>(b"key1", "value1".to_string()).unwrap();
        let proof = mpt.generate_proof::<Sha256>(b"key1").unwrap();

        let mut other_mpt = MerklePatriciaTrie::new(StorageMode::Full);
        other_mpt
            .insert::<Sha256>(b"key2", "value2".to_string())
            .unwrap();
        let other_proof = other_mpt.generate_proof::<Sha256>(b"key2").unwrap();

        assert!(mpt.verify_proof::<Sha256>(&proof));
        assert!(!mpt.verify_proof::<Sha256>(&other_proof));

        assert!(other_mpt.verify_proof::<Sha256>(&other_proof));
        assert!(!other_mpt.verify_proof::<Sha256>(&proof));
    }

    #[test]
    fn partial_mode_from_proof() {
        let mut full_mpt = MerklePatriciaTrie::new(StorageMode::Full);
        full_mpt
            .insert::<Sha256>(b"key1", "value1".to_string())
            .unwrap();

        let proof = full_mpt.generate_proof::<Sha256>(b"key1").unwrap();
        let partial_mpt = MerklePatriciaTrie::from_proof::<Sha256>(proof.clone()).unwrap();

        assert_eq!(partial_mpt.get(b"key1"), Some("value1".to_string()));
        assert!(partial_mpt.verify_proof::<Sha256>(&proof));
    }
}
