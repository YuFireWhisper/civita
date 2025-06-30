use std::collections::BTreeMap;

use crate::{
    crypto::{traits::hasher::Multihash, Hasher},
    network::transport,
    traits::Serializable,
    utils::mpt::{
        node::{Branch, Extension, Leaf, Node},
        staging::Staging,
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

mod node;
mod staging;

type Nibble = u8;

#[async_trait::async_trait]
pub trait Storage<V> {
    type Error;

    async fn put(&self, key: &Multihash, value: &Node<V>) -> Result<(), Self::Error>;
    async fn get(&self, key: &Multihash) -> Result<Option<Node<V>>, Self::Error>;
}

pub struct Mpt<V, S: Storage<V> = Transport> {
    root_hash: Option<Multihash>,
    original_root: Option<Multihash>,
    staging: Staging<V, S>,
}

impl<V: Serializable + Clone, S: Storage<V>> Mpt<V, S> {
    pub fn new(storage: S) -> Self {
        Self {
            root_hash: None,
            original_root: None,
            staging: Staging::new(storage),
        }
    }

    pub fn with_root(storage: S, root_hash: Multihash) -> Self {
        Self {
            root_hash: Some(root_hash),
            original_root: Some(root_hash),
            staging: Staging::new(storage),
        }
    }

    pub async fn insert<H: Hasher>(&mut self, key: &[u8], value: V) -> Result<(), S::Error> {
        let root = self.get_root_node().await?;
        let new_root = self.insert_recursive::<H>(root, key, value).await?;

        let new_root_hash = new_root.hash::<H>();
        self.staging.put(new_root_hash, new_root);

        self.root_hash = Some(new_root_hash);

        Ok(())
    }

    async fn get_root_node(&mut self) -> Result<Node<V>, S::Error> {
        match &self.root_hash {
            Some(hash) => Ok(self.staging.get(hash).await?.unwrap_or(Node::Empty)),
            None => Ok(Node::Empty),
        }
    }

    async fn insert_recursive<H: Hasher>(
        &mut self,
        node: Node<V>,
        key: &[Nibble],
        value: V,
    ) -> Result<Node<V>, S::Error> {
        match node {
            Node::Empty => Ok(self.create_leaf_node(key, value)),
            Node::Leaf(leaf) => Box::pin(self.insert_leaf::<H>(leaf, key, value)).await,
            Node::Extension(ext) => Box::pin(self.insert_extension::<H>(ext, key, value)).await,
            Node::Branch(branch) => Box::pin(self.insert_branch::<H>(branch, key, value)).await,
        }
    }

    fn create_leaf_node(&self, key: &[Nibble], value: V) -> Node<V> {
        Node::Leaf(Leaf {
            path: key.to_vec(),
            value,
        })
    }

    async fn insert_leaf<H: Hasher>(
        &mut self,
        leaf: Leaf<V>,
        key: &[Nibble],
        value: V,
    ) -> Result<Node<V>, S::Error> {
        let common = Self::common_prefix(&leaf.path, key);

        if common.len() == leaf.path.len() && common.len() == key.len() {
            return Ok(Node::new_leaf(leaf.path.clone(), value));
        }

        if common.len() == leaf.path.len() {
            let remaining = &key[common.len()..];

            let child = self
                .insert_recursive::<H>(Node::Empty, &remaining[1..], value)
                .await?;
            let child_hash = child.hash::<H>();

            self.staging.put(child_hash, child);

            let children = BTreeMap::from([(remaining[0], child_hash)]);

            return Ok(Node::new_branch(children, Some(leaf.value.clone())));
        }

        self.split_leaf::<H>(&leaf.path, leaf.value.clone(), key, value, common.len())
            .await
    }

    fn common_prefix(a: &[Nibble], b: &[Nibble]) -> Vec<Nibble> {
        let mut common = Vec::new();
        for (x, y) in a.iter().zip(b.iter()) {
            if x == y {
                common.push(*x);
            } else {
                break;
            }
        }
        common
    }

    async fn split_leaf<H: Hasher>(
        &mut self,
        leaf_key: &[Nibble],
        leaf_value: V,
        new_key: &[Nibble],
        new_value: V,
        common_len: usize,
    ) -> Result<Node<V>, S::Error> {
        let remaining_leaf_key = &leaf_key[common_len..];
        let remaining_new_key = &new_key[common_len..];

        let mut children = BTreeMap::new();

        let leaf_child = if remaining_leaf_key.len() == 1 {
            Node::new_leaf(vec![], leaf_value)
        } else {
            Node::new_leaf(remaining_leaf_key[1..].to_vec(), leaf_value)
        };

        let leaf_child_hash = leaf_child.hash::<H>();
        self.staging.put(leaf_child_hash, leaf_child);

        children.insert(remaining_leaf_key[0], leaf_child_hash);

        let new_child = if remaining_new_key.len() == 1 {
            Node::new_leaf(vec![], new_value)
        } else {
            Node::new_leaf(remaining_new_key[1..].to_vec(), new_value)
        };

        let new_child_hash = new_child.hash::<H>();
        self.staging.put(new_child_hash, new_child);

        children.insert(remaining_new_key[0], new_child_hash);

        let branch = Node::new_branch(children, None);

        if common_len == 0 {
            return Ok(branch);
        }

        let branch_hash = branch.hash::<H>();
        self.staging.put(branch_hash, branch);

        Ok(Node::new_extension(
            leaf_key[..common_len].to_vec(),
            branch_hash,
        ))
    }

    async fn insert_extension<H: Hasher>(
        &mut self,
        ext: Extension,
        key: &[Nibble],
        value: V,
    ) -> Result<Node<V>, S::Error> {
        let common = Self::common_prefix(&ext.path, key);

        if common.len() == ext.path.len() {
            let remaining = &key[common.len()..];

            let child = self.staging.get(&ext.child).await?.unwrap_or(Node::Empty);
            let new_child = self.insert_recursive::<H>(child, remaining, value).await?;

            let new_child_hash = new_child.hash::<H>();
            self.staging.put(new_child_hash, new_child);

            Ok(Node::new_extension(ext.path.clone(), new_child_hash))
        } else {
            self.split_extension::<H>(&ext.path, ext.child, key, value, common.len())
                .await
        }
    }

    async fn split_extension<H: Hasher>(
        &mut self,
        ext_key: &[Nibble],
        ext_next: Multihash,
        new_key: &[Nibble],
        new_value: V,
        common_len: usize,
    ) -> Result<Node<V>, S::Error> {
        let ext_remaining = &ext_key[common_len..];
        let new_remaining = &new_key[common_len..];

        let mut children = BTreeMap::new();

        let ext_child = if ext_remaining.len() == 1 {
            ext_next
        } else {
            let new_ext = Node::new_extension(ext_remaining[1..].to_vec(), ext_next);
            let ext_child_hash = new_ext.hash::<H>();
            self.staging.put(ext_child_hash, new_ext);
            ext_child_hash
        };

        children.insert(ext_remaining[0], ext_child);

        let new_child = self
            .insert_recursive::<H>(Node::Empty, &new_remaining[1..], new_value)
            .await?;

        let new_child_hash = new_child.hash::<H>();
        self.staging.put(new_child_hash, new_child);

        children.insert(new_remaining[0], new_child_hash);

        let branch = Node::new_branch(children, None);

        if common_len == 0 {
            return Ok(branch);
        }

        let branch_hash = branch.hash::<H>();
        self.staging.put(branch_hash, branch);

        Ok(Node::new_extension(
            ext_key[..common_len].to_vec(),
            branch_hash,
        ))
    }

    async fn insert_branch<H: Hasher>(
        &mut self,
        mut branch: Branch<V>,
        key: &[Nibble],
        value: V,
    ) -> Result<Node<V>, S::Error> {
        if key.is_empty() {
            branch.value = Some(value);
        } else {
            let idx = key[0];

            let child = match branch.children.get(&idx) {
                Some(child_hash) => self.staging.get(child_hash).await?.unwrap_or(Node::Empty),
                None => Node::Empty,
            };
            let new_child = self.insert_recursive::<H>(child, &key[1..], value).await?;

            let new_child_hash = new_child.hash::<H>();
            self.staging.put(new_child_hash, new_child);

            branch.children.insert(idx, new_child_hash);
        }

        Ok(Node::new_branch(branch.children, branch.value.clone()))
    }

    pub async fn get(&mut self, key: &[Nibble]) -> Result<Option<V>, S::Error> {
        if let Some(root_hash) = &self.root_hash {
            let root_node = self.staging.get(root_hash).await?.unwrap_or(Node::Empty);
            self.get_node(&root_node, key).await
        } else {
            Ok(None)
        }
    }

    async fn get_node(&mut self, node: &Node<V>, key: &[Nibble]) -> Result<Option<V>, S::Error> {
        match node {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                if leaf.path == key {
                    Ok(Some(leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Extension(ext) => {
                if key.starts_with(&ext.path) {
                    let child = self.staging.get(&ext.child).await?.unwrap_or(Node::Empty);
                    return Box::pin(self.get_node(&child, &key[ext.path.len()..])).await;
                }

                return Ok(None);
            }
            Node::Branch(branch) => {
                if key.is_empty() {
                    return Ok(branch.value.clone());
                }

                let idx = key[0];

                if let Some(child_hash) = branch.children.get(&idx) {
                    let child = self.staging.get(child_hash).await?.unwrap_or(Node::Empty);
                    return Box::pin(self.get_node(&child, &key[1..])).await;
                }

                Ok(None)
            }
        }
    }

    pub async fn commit(&mut self) -> Result<(), S::Error> {
        self.staging.commit().await?;
        self.original_root = self.root_hash.clone();

        Ok(())
    }

    pub fn rollback(&mut self) {
        self.staging.rollback();
        self.root_hash = self.original_root.clone();
    }

    pub fn has_uncommitted_changes(&self) -> bool {
        self.staging.has_uncommitted_changes()
    }

    pub fn uncommitted_count(&self) -> usize {
        self.staging.uncommitted_count()
    }

    pub fn root_hash(&self) -> Option<Multihash> {
        self.root_hash
    }
}

#[async_trait::async_trait]
impl<V: Serializable + Clone + Sync + 'static> Storage<V> for Transport {
    type Error = transport::Error;

    async fn put(&self, key: &Multihash, value: &Node<V>) -> Result<(), Self::Error> {
        self.put_with_key(key, value.to_vec().expect("Failed to serialize Node"))
            .await
    }

    async fn get(&self, key: &Multihash) -> Result<Option<Node<V>>, Self::Error> {
        self.get::<Node<V>>(key).await
    }
}
