use std::{collections::BTreeMap, sync::Arc};

use bytemuck::cast_slice;

use crate::{
    crypto::{Hasher, Multihash},
    network::{
        traits::{storage, Storage},
        transport::Kad,
        CacheStorage,
    },
    traits::Serializable,
    utils::mpt::node::{Branch, Extension, Leaf, Node},
};

mod node;

type Nibble = u16;
type Result<T, E = storage::Error> = std::result::Result<T, E>;

pub struct Mpt<T, S: Storage = Arc<Kad>> {
    root_hash: Option<Multihash>,
    original_root: Option<Multihash>,
    storage: CacheStorage<Node<T>, S>,
}

impl<T, S> Mpt<T, S>
where
    T: Clone + Serializable + Send + Sync + 'static,
    S: Storage,
{
    pub fn new(storage: S) -> Self {
        Self {
            root_hash: None,
            original_root: None,
            storage: CacheStorage::new(storage),
        }
    }

    pub fn with_root(storage: S, root_hash: Multihash) -> Self {
        Self {
            root_hash: Some(root_hash),
            original_root: Some(root_hash),
            storage: CacheStorage::new(storage),
        }
    }

    pub async fn insert<H: Hasher>(&mut self, path: &[u8], value: T) -> Result<()> {
        let path = cast_slice(path);

        let root = self.get_root_node().await?;
        let root = self.insert_rec::<H>(root, path, value).await?;

        let hash = self.hash_and_insert::<H>(root)?;

        self.root_hash = Some(hash);

        Ok(())
    }

    async fn get_root_node(&mut self) -> Result<Node<T>> {
        match self.root_hash {
            Some(hash) => self.get_node(&hash).await,
            None => Ok(Node::Empty),
        }
    }

    async fn get_node(&self, hash: &Multihash) -> Result<Node<T>> {
        self.storage
            .get(hash)
            .await?
            .map_or_else(|| Ok(Node::Empty), |node| Ok(node.clone()))
    }

    async fn insert_rec<H: Hasher>(
        &mut self,
        node: Node<T>,
        path: &[Nibble],
        value: T,
    ) -> Result<Node<T>> {
        match node {
            Node::Empty => Ok(self.create_leaf(path, value)),
            Node::Leaf(leaf) => Box::pin(self.insert_leaf::<H>(leaf, path, value)).await,
            Node::Extension(ext) => Box::pin(self.insert_ext::<H>(ext, path, value)).await,
            Node::Branch(branch) => Box::pin(self.insert_branch::<H>(branch, path, value)).await,
        }
    }

    fn create_leaf(&self, path: &[Nibble], value: T) -> Node<T> {
        Node::Leaf(Leaf {
            path: path.to_vec(),
            value,
        })
    }

    async fn insert_leaf<H: Hasher>(
        &mut self,
        leaf: Leaf<T>,
        path: &[Nibble],
        value: T,
    ) -> Result<Node<T>> {
        let common = Self::common_prefix(&leaf.path, path);

        if common.len() == leaf.path.len() && common.len() == path.len() {
            return Ok(Node::new_leaf(leaf.path, value));
        }

        if common.len() == leaf.path.len() {
            let path = &path[common.len()..];

            let child = self.insert_rec::<H>(Node::Empty, &path[1..], value).await?;
            let hash = self.hash_and_insert::<H>(child)?;

            let children = BTreeMap::from([(path[0], hash)]);

            return Ok(Node::new_branch(children, Some(leaf.value)));
        }

        self.split_leaf::<H>(leaf, path, value, common.len()).await
    }

    fn hash_and_insert<H: Hasher>(&mut self, node: Node<T>) -> Result<Multihash> {
        let hash = node.hash::<H>();
        self.storage.insert(hash, node);
        Ok(hash)
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
        leaf: Leaf<T>,
        path: &[Nibble],
        value: T,
        common_len: usize,
    ) -> Result<Node<T>> {
        let leaf_path = &leaf.path[common_len..];
        let new_path = &path[common_len..];

        let mut children = BTreeMap::new();

        {
            let child = Self::new_leaf_child(leaf_path, leaf.value);
            let hash = self.hash_and_insert::<H>(child)?;
            children.insert(leaf_path[0], hash);
        }

        {
            let child = Self::new_leaf_child(new_path, value);
            let hash = self.hash_and_insert::<H>(child)?;
            children.insert(new_path[0], hash);
        }

        let branch = Node::new_branch(children, None);

        if common_len == 0 {
            return Ok(branch);
        }

        let hash = self.hash_and_insert::<H>(branch)?;

        Ok(Node::new_extension(leaf_path[..common_len].to_vec(), hash))
    }

    fn new_leaf_child(path: &[Nibble], value: T) -> Node<T> {
        if path.len() == 1 {
            Node::new_leaf(vec![], value)
        } else {
            Node::new_leaf(path[1..].to_vec(), value)
        }
    }

    async fn insert_ext<H: Hasher>(
        &mut self,
        ext: Extension,
        path: &[Nibble],
        value: T,
    ) -> Result<Node<T>> {
        let common = Self::common_prefix(&ext.path, path);

        if common.len() == ext.path.len() {
            let path = &path[common.len()..];

            let child = self.get_node(&ext.child).await?;
            let child = self.insert_rec::<H>(child, path, value).await?;
            let hash = self.hash_and_insert::<H>(child)?;

            Ok(Node::new_extension(ext.path, hash))
        } else {
            self.split_ext::<H>(&ext, path, value, common.len()).await
        }
    }

    async fn split_ext<H: Hasher>(
        &mut self,
        ext: &Extension,
        path: &[Nibble],
        value: T,
        common_len: usize,
    ) -> Result<Node<T>> {
        let ext_path = &ext.path[common_len..];
        let new_path = &path[common_len..];

        let mut children = BTreeMap::new();

        {
            let child = if ext_path.len() == 1 {
                ext.child
            } else {
                let ext = Node::new_extension(ext_path[1..].to_vec(), ext.child);
                self.hash_and_insert::<H>(ext)?
            };

            children.insert(ext_path[0], child);
        }

        {
            let child = self
                .insert_rec::<H>(Node::Empty, &new_path[1..], value)
                .await?;
            let hash = self.hash_and_insert::<H>(child)?;
            children.insert(new_path[0], hash);
        }

        let branch = Node::new_branch(children, None);

        if common_len == 0 {
            return Ok(branch);
        }

        let hash = self.hash_and_insert::<H>(branch)?;

        Ok(Node::new_extension(ext_path[..common_len].to_vec(), hash))
    }

    async fn insert_branch<H: Hasher>(
        &mut self,
        mut branch: Branch<T>,
        path: &[Nibble],
        value: T,
    ) -> Result<Node<T>> {
        if path.is_empty() {
            branch.value = Some(value);
        } else {
            let idx = path[0];
            let child = match branch.children.get(&idx) {
                Some(hash) => self.get_node(hash).await?,
                None => Node::Empty,
            };
            let child = self.insert_rec::<H>(child, &path[1..], value).await?;
            let hash = self.hash_and_insert::<H>(child)?;
            branch.children.insert(idx, hash);
        }

        Ok(Node::Branch(branch))
    }

    pub async fn get(&self, path: &[u8]) -> Result<Option<T>> {
        let key = cast_slice(path);

        let Some(hash) = self.root_hash else {
            return Ok(None);
        };

        let root = self.get_node(&hash).await?;
        self.get_rec(&root, key).await
    }

    async fn get_rec(&self, node: &Node<T>, path: &[Nibble]) -> Result<Option<T>> {
        match node {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                if leaf.path == path {
                    Ok(Some(leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Extension(ext) => {
                if path.starts_with(&ext.path) {
                    let path = &path[ext.path.len()..];
                    let child = self.get_node(&ext.child).await?;
                    return Box::pin(self.get_rec(&child, path)).await;
                }

                Ok(None)
            }
            Node::Branch(branch) => {
                if path.is_empty() {
                    return Ok(branch.value.clone());
                }

                let idx = path[0];

                match branch.children.get(&idx) {
                    Some(hash) => {
                        let path = &path[1..];
                        let child = self.get_node(hash).await?;
                        return Box::pin(self.get_rec(&child, path)).await;
                    }
                    None => Ok(None),
                }
            }
        }
    }

    pub async fn commit(&mut self) -> Result<()> {
        self.storage.commit().await?;
        self.original_root = self.root_hash;

        Ok(())
    }

    pub fn rollback(&mut self) {
        self.storage.rollback();
        self.root_hash = self.original_root;
    }

    pub fn root_hash(&self) -> Option<Multihash> {
        self.root_hash
    }
}
