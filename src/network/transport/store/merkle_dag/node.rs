use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, Serialize};

use crate::network::transport::store::merkle_dag::{BanchingFactor, HashArray};

const INDEX_SIZE: usize = std::mem::size_of::<BanchingFactor>();
const HASH_SIZE: usize = std::mem::size_of::<HashArray>();
const BASE_SIZE: usize = INDEX_SIZE + HASH_SIZE;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(PartialEq, Eq)]
pub struct Node {
    hash: RefCell<Option<HashArray>>,
    children: HashMap<BanchingFactor, Node>,
}

impl Node {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_hash(hash: HashArray) -> Self {
        Self {
            hash: RefCell::new(Some(hash)),
            ..Default::default()
        }
    }

    pub fn new_with_children(children: HashMap<BanchingFactor, Node>) -> Self {
        Self {
            children,
            ..Default::default()
        }
    }

    pub fn insert(&mut self, index: BanchingFactor, node: Node) -> Option<Node> {
        self.hash.replace(None);
        self.children.insert(index, node)
    }

    pub fn insert_with_iter(&mut self, iter: impl IntoIterator<Item = (BanchingFactor, Node)>) {
        iter.into_iter().for_each(|(index, child)| {
            self.insert(index, child);
        });
    }

    pub fn insert_with_hash(&mut self, index: BanchingFactor, hash: HashArray) -> Option<Node> {
        let child = Node::new_with_hash(hash);
        self.insert(index, child)
    }

    pub fn update_hash(&self) {
        if self.children.is_empty() {
            return;
        }

        self.children.values().for_each(|child| {
            if child.hash.borrow().is_none() {
                child.update_hash();
            }
        });

        let bytes = self.to_vec();
        let hash = blake3::hash(&bytes);

        self.hash.replace(Some(hash.into()));
    }

    pub fn hash(&self) -> HashArray {
        self.hash.borrow_mut().unwrap_or_else(|| {
            let vec = self.to_vec();
            blake3::hash(&vec).into()
        })
    }

    pub fn clear_hash(&self) {
        self.hash.replace(None);
    }

    pub fn child(&self, index: &BanchingFactor) -> Option<&Node> {
        self.children.get(index)
    }

    pub fn child_mut(&mut self, index: &BanchingFactor) -> Option<&mut Node> {
        self.children.get_mut(index)
    }

    pub fn children(&self) -> &HashMap<BanchingFactor, Node> {
        &self.children
    }

    pub fn children_mut(&mut self) -> &mut HashMap<BanchingFactor, Node> {
        &mut self.children
    }

    pub fn children_take(&mut self) -> HashMap<BanchingFactor, Node> {
        std::mem::take(&mut self.children)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        Self::try_from(slice)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }
}

impl From<Node> for Vec<u8> {
    fn from(node: Node) -> Self {
        (&node).into()
    }
}

impl From<&Node> for Vec<u8> {
    fn from(node: &Node) -> Self {
        bincode::serde::encode_to_vec(node, bincode::config::standard())
            .expect("Failed to serialize node")
    }
}

impl TryFrom<Vec<u8>> for Node {
    type Error = bincode::error::DecodeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Node {
    type Error = bincode::error::DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).map(|(node, _)| node)
    }
}

impl Serialize for Node {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut pairs: Vec<(&BanchingFactor, &Node)> = self.children.iter().collect();
        pairs.sort_by_key(|(key, _)| *key);

        let mut bytes = Vec::with_capacity(pairs.len() * BASE_SIZE);

        for (index, child) in pairs {
            let mut index_bytes = [0u8; INDEX_SIZE];
            index_bytes.copy_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(&index_bytes);
            bytes.extend_from_slice(&child.hash());
        }

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        if bytes.len() % BASE_SIZE != 0 {
            return Err(serde::de::Error::custom("Invalid byte length"));
        }

        let mut children = HashMap::with_capacity(bytes.len() / BASE_SIZE);

        for chunk in bytes.chunks_exact(BASE_SIZE) {
            let index_bytes = std::array::from_fn(|i| chunk[i]);
            let index = BanchingFactor::from_be_bytes(index_bytes);
            let child_hash: HashArray = chunk[INDEX_SIZE..]
                .try_into()
                .map_err(|_| serde::de::Error::custom("Failed to convert slice to array"))?;
            let child = Node::new_with_hash(child_hash);
            children.insert(index, child);
        }

        Ok(Node {
            children,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_node_is_empty() {
        let node = Node::new();

        assert!(node.hash.borrow().is_none());
        assert_eq!(node.children.len(), 0);
    }

    #[test]
    fn insert_adds_child() {
        const INDEX: BanchingFactor = 5;

        let mut node = Node::new();
        let hash = [1u8; 32];
        let child = Node::new_with_hash(hash);

        let result = node.insert(INDEX, child.clone());

        assert!(result.is_none());
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.child(&INDEX), Some(&child));
    }

    #[test]
    fn insert_replaces_existing_child() {
        const INDEX: BanchingFactor = 5;

        let mut node = Node::new();
        let old_hash = [1u8; 32];
        let new_hash = [2u8; 32];

        let old_child = Node::new_with_hash(old_hash);
        let new_child = Node::new_with_hash(new_hash);

        node.insert(INDEX, old_child);

        let result = node.insert(INDEX, new_child.clone());

        assert!(result.is_some());
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.child(&INDEX), Some(&new_child));
    }

    #[test]
    fn same_behavior_for_insert_with_hash() {
        const INDEX: BanchingFactor = 5;

        let mut node1 = Node::new();
        let mut node2 = Node::new();

        let hash = [1u8; 32];

        node1.insert_with_hash(INDEX, hash);
        node2.insert(INDEX, Node::new_with_hash(hash));

        assert_eq!(node1, node2);
    }

    #[test]
    fn hash_returns_consistent_value() {
        const INDEX_1: BanchingFactor = 1;

        let mut node = Node::new();
        node.insert_with_hash(INDEX_1, [1u8; 32]);
        node.insert_with_hash(INDEX_1, [2u8; 32]);

        node.update_hash();

        let hash1 = node.hash();
        let hash2 = node.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn child_returns_correct_value() {
        const INDEX: BanchingFactor = 7;

        let mut node = Node::new();
        let hash = [3u8; 32];
        node.insert_with_hash(INDEX, hash);

        let child = node.child(&INDEX);

        assert!(child.is_some());
        assert_eq!(child.unwrap().hash, Some(hash).into());
    }

    #[test]
    fn child_nonexistent_returns_none() {
        let node = Node::new();
        assert_eq!(node.child(&42), None);
    }

    #[test]
    fn serialization_roundtrip_preserves_data() {
        const INDEX_1: BanchingFactor = 1;
        const INDEX_2: BanchingFactor = 5;

        let mut original = Node::new();
        original.insert_with_hash(INDEX_1, [1u8; 32]);
        original.insert_with_hash(INDEX_2, [5u8; 32]);

        let bytes = original.to_vec();
        let deserialized = Node::from_slice(&bytes).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn serialization_empty_node_works() {
        let original = Node::new();
        let bytes = original.to_vec();
        let deserialized = Node::from_slice(&bytes).unwrap();

        assert_eq!(deserialized.children.len(), 0);
    }

    #[test]
    fn serialization_ordering_is_consistent() {
        const INDEX_1: BanchingFactor = 1;
        const INDEX_2: BanchingFactor = 2;

        let mut node1 = Node::new();

        node1.insert_with_hash(INDEX_1, [1u8; 32]);
        node1.insert_with_hash(INDEX_2, [2u8; 32]);

        let mut node2 = Node::new();
        node2.insert_with_hash(INDEX_2, [2u8; 32]);
        node2.insert_with_hash(INDEX_1, [1u8; 32]);

        assert_eq!(node1.to_vec(), node2.to_vec());
    }

    #[test]
    fn invalid_data_deserialize_fails() {
        let invalid_bytes = vec![1, 2, 3];
        let result = Node::from_slice(&invalid_bytes);
        assert!(result.is_err());
    }
}
