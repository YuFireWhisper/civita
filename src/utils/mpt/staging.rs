use std::collections::HashMap;

use crate::{
    crypto::traits::hasher::Multihash,
    utils::mpt::{node::Node, Storage},
};

#[derive(Debug)]
#[derive(Clone)]
enum StagedNode<V> {
    Clean(Node<V>),
    Dirty(Node<V>),
}

impl<V> StagedNode<V> {
    fn node(&self) -> &Node<V> {
        match self {
            StagedNode::Clean(node) | StagedNode::Dirty(node) => node,
        }
    }

    fn is_dirty(&self) -> bool {
        matches!(self, StagedNode::Dirty(_))
    }
}

pub struct Staging<V, S: Storage<V>> {
    storage: S,
    staging: HashMap<Multihash, StagedNode<V>>,
}

impl<V, S> Staging<V, S>
where
    V: Clone,
    S: Storage<V>,
{
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            staging: HashMap::new(),
        }
    }

    pub fn put(&mut self, key: Multihash, value: Node<V>) {
        self.staging.insert(key, StagedNode::Dirty(value));
    }

    pub async fn get(&mut self, key: &Multihash) -> Result<Option<Node<V>>, S::Error> {
        if let Some(staged_node) = self.staging.get(key) {
            return Ok(Some(staged_node.node().clone()));
        }

        match self.storage.get(key).await? {
            Some(node) => {
                self.staging.insert(*key, StagedNode::Clean(node.clone()));
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    pub async fn commit(&mut self) -> Result<(), S::Error> {
        let dirty_entries: Vec<_> = self
            .staging
            .iter()
            .filter(|(_, staged_node)| staged_node.is_dirty())
            .map(|(key, staged_node)| (*key, staged_node.node().clone()))
            .collect();

        if dirty_entries.is_empty() {
            return Ok(());
        }

        for (key, node) in dirty_entries {
            self.storage.put(&key, &node).await?;
        }

        for staged_node in self.staging.values_mut() {
            if staged_node.is_dirty() {
                if let StagedNode::Dirty(node) = staged_node {
                    *staged_node = StagedNode::Clean(node.clone());
                }
            }
        }

        Ok(())
    }

    pub fn rollback(&mut self) {
        self.staging
            .retain(|_, staged_node| !staged_node.is_dirty());
    }

    pub fn clear_cache(&mut self) {
        self.staging.clear();
    }

    pub fn has_uncommitted_changes(&self) -> bool {
        self.staging
            .values()
            .any(|staged_node| staged_node.is_dirty())
    }

    pub fn uncommitted_count(&self) -> usize {
        self.staging
            .values()
            .filter(|staged_node| staged_node.is_dirty())
            .count()
    }

    pub fn cached_count(&self) -> usize {
        self.staging.len()
    }

    pub fn dirty_keys(&self) -> impl Iterator<Item = &Multihash> {
        self.staging
            .iter()
            .filter(|(_, staged_node)| staged_node.is_dirty())
            .map(|(key, _)| key)
    }
}
