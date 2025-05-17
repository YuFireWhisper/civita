use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, Serialize};

#[derive(Debug)]
#[derive(Default)]
pub struct Node {
    children: HashMap<u8, [u8; 32]>,
    hash_cache: RefCell<Option<[u8; 32]>>,
}

impl Node {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, index: u8, value: [u8; 32]) -> Option<[u8; 32]> {
        self.hash_cache.borrow_mut().take();
        self.children.insert(index, value)
    }

    pub fn hash(&self) -> [u8; 32] {
        if let Some(hash) = self.hash_cache.borrow().as_ref() {
            return *hash;
        }

        let bytes = self.to_vec();
        let hash = blake3::hash(&bytes).into();

        // Store the hash in the cache
        *self.hash_cache.borrow_mut() = Some(hash);

        hash
    }

    pub fn child(&self, index: &u8) -> Option<&[u8; 32]> {
        self.children.get(index)
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
        use serde::ser::Error;

        let mut keys: Vec<u8> = self.children.keys().copied().collect();
        keys.sort();

        let mut bytes = Vec::with_capacity(keys.len() * 33);

        for &index in &keys {
            bytes.push(index);
            let child = self
                .children
                .get(&index)
                .ok_or_else(|| S::Error::custom("Missing child"))?;
            bytes.extend_from_slice(child);
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

        // 1 byte for index + 32 bytes for child
        if bytes.len() % 33 != 0 {
            return Err(serde::de::Error::custom("Invalid byte length"));
        }

        let mut children = HashMap::with_capacity(bytes.len() / 33);

        for chunk in bytes.chunks_exact(33) {
            let index = chunk[0];
            let child: [u8; 32] = chunk[1..]
                .try_into()
                .map_err(|_| serde::de::Error::custom("Failed to convert slice to array"))?;
            children.insert(index, child);
        }

        Ok(Node {
            children,
            hash_cache: RefCell::new(None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_node_is_empty() {
        let node = Node::new();
        assert_eq!(node.children.len(), 0);
        assert!(node.hash_cache.borrow().is_none());
    }

    #[test]
    fn insert_adds_child() {
        let mut node = Node::new();
        let value = [1u8; 32];
        let result = node.insert(5, value);

        assert!(result.is_none());
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children.get(&5), Some(&value));
    }

    #[test]
    fn insert_replaces_existing_child() {
        let mut node = Node::new();
        let old_value = [1u8; 32];
        let new_value = [2u8; 32];

        node.insert(5, old_value);
        let result = node.insert(5, new_value);

        assert_eq!(result, Some(old_value));
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children.get(&5), Some(&new_value));
    }

    #[test]
    fn insert_invalidates_hash_cache() {
        let mut node = Node::new();

        let _ = node.hash();
        assert!(node.hash_cache.borrow().is_some());

        node.insert(5, [1u8; 32]);
        assert!(node.hash_cache.borrow().is_none());
    }

    #[test]
    fn hash_returns_consistent_value() {
        let mut node = Node::new();
        node.insert(1, [1u8; 32]);
        node.insert(2, [2u8; 32]);

        let hash1 = node.hash();
        let hash2 = node.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_uses_cached_value() {
        let mut node = Node::new();
        node.insert(1, [1u8; 32]);

        let hash1 = node.hash();
        assert!(node.hash_cache.borrow().is_some());

        let hash2 = node.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn child_returns_correct_value() {
        let mut node = Node::new();
        let value = [3u8; 32];
        node.insert(7, value);

        assert_eq!(node.child(&7), Some(&value));
    }

    #[test]
    fn child_nonexistent_returns_none() {
        let node = Node::new();
        assert_eq!(node.child(&42), None);
    }

    #[test]
    fn serialization_roundtrip_preserves_data() {
        let mut original = Node::new();
        original.insert(1, [1u8; 32]);
        original.insert(5, [5u8; 32]);

        let bytes = original.to_vec();
        let deserialized = Node::from_slice(&bytes).unwrap();

        assert_eq!(original.children.len(), deserialized.children.len());
        assert_eq!(original.child(&1), deserialized.child(&1));
        assert_eq!(original.child(&5), deserialized.child(&5));
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
        let mut node1 = Node::new();
        node1.insert(1, [1u8; 32]);
        node1.insert(2, [2u8; 32]);

        let mut node2 = Node::new();
        node2.insert(2, [2u8; 32]);
        node2.insert(1, [1u8; 32]);

        assert_eq!(node1.to_vec(), node2.to_vec());
    }

    #[test]
    fn invalid_data_deserialize_fails() {
        let invalid_bytes = vec![1, 2, 3];
        let result = Node::from_slice(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn tryfrom_vec_works() {
        let mut original = Node::new();
        original.insert(42, [42u8; 32]);

        let bytes = original.to_vec();
        let deserialized = Node::try_from(bytes).unwrap();

        assert_eq!(original.child(&42), deserialized.child(&42));
    }

    #[test]
    fn from_into_vec_works() {
        let mut node = Node::new();
        node.insert(10, [10u8; 32]);

        let vec1: Vec<u8> = (&node).into();
        let vec2: Vec<u8> = node.into();

        assert_eq!(vec1, vec2);
    }
}
