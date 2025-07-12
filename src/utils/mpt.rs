use std::{collections::HashMap, marker::PhantomData};

use crate::{
    crypto::{Hasher, Multihash},
    traits::Serializable,
    utils::mpt::{
        keys::{prefix_len, slice_to_hex},
        node::{Flags, Full, Short},
    },
};

type Result<T, E = Error> = std::result::Result<T, E>;

mod keys;
mod node;
pub mod storage;

pub use node::Node;
pub use storage::{Storage, StorageError};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error("Missing node")]
    MissingNode,
}

pub struct MerklePatriciaTrie<H, S> {
    root: Node,
    storage: S,
    cache: HashMap<Multihash, Node>,
    _marker: PhantomData<H>,
}

impl<H: Hasher, S: Storage> MerklePatriciaTrie<H, S> {
    pub fn empty(storage: S) -> Self {
        MerklePatriciaTrie {
            root: Node::Empty,
            storage,
            cache: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn from_root(root_hash: Multihash, storage: S) -> Self {
        MerklePatriciaTrie {
            root: Node::Hash(root_hash),
            storage,
            cache: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn update(&mut self, key: &[u8], val: Node) -> Result<()> {
        let key_vec = slice_to_hex(key);
        let key = key_vec.as_slice();

        let root = std::mem::take(&mut self.root);
        let (_, root) = self.insert(root, &[], key, val)?;

        self.root = root;

        Ok(())
    }

    fn insert(&self, mut node: Node, prefix: &[u8], key: &[u8], val: Node) -> Result<(bool, Node)> {
        if key.is_empty() {
            if node.is_value() {
                return Ok((node == val, val));
            }
            return Ok((true, val));
        }

        match node {
            Node::Short(ref mut short) => {
                let match_len = prefix_len(prefix, &short.key);

                if match_len == key.len() {
                    let s_val = std::mem::take(&mut short.val);
                    let prefix = &[prefix, &short.key[..match_len]].concat();
                    let key = &key[match_len..];
                    let (is_dirty, nn) = self.insert(*s_val, prefix, key, val)?;

                    if !is_dirty {
                        return Ok((false, node));
                    }

                    short.val = Box::new(nn);
                    short.flags = Flags::default();

                    return Ok((true, node));
                }

                let mut branch = Full::default();

                {
                    let idx = short.key[match_len] as usize;
                    let prefix = &[prefix, &short.key[..match_len]].concat();
                    let key = &short.key[match_len + 1..];
                    branch.children[idx] = self.insert(Node::Empty, prefix, key, val.clone())?.1;
                }

                {
                    let idx = key[match_len] as usize;
                    let prefix = &[prefix, &key[..match_len]].concat();
                    let key = &key[match_len + 1..];
                    branch.children[idx] = self.insert(Node::Empty, prefix, key, val)?.1;
                }

                if match_len == 0 {
                    return Ok((true, Node::new_full(branch)));
                }

                let key = short.key.split_off(match_len);
                let short = Short::new(key, Node::new_full(branch));

                Ok((true, Node::new_short(short)))
            }
            Node::Full(ref mut full) => {
                let idx = key[0] as usize;
                let child = std::mem::take(&mut full.children[idx]);

                let prefix = &[prefix, &key[..1]].concat();
                let key = &key[1..];

                let (is_dirty, nn) = self.insert(child, prefix, key, val)?;

                if !is_dirty {
                    return Ok((false, node));
                }

                full.children[idx] = nn;
                full.flags = Flags::default();

                Ok((true, node))
            }
            Node::Empty => Ok((true, Node::new_short(Short::new(key.to_vec(), val)))),
            Node::Hash(_) => {
                let rn = self.resolve_node(&node)?.ok_or(Error::MissingNode)?;

                let (is_dirty, nn) = self.insert(rn.clone(), prefix, key, val)?;

                if !is_dirty {
                    return Ok((false, rn));
                }

                Ok((true, nn))
            }
            _ => panic!("Unexpected node type in insert: {node:?}"),
        }
    }

    fn resolve_node(&self, node: &Node) -> Result<Option<Node>> {
        let Node::Hash(hash) = node else {
            return Ok(None);
        };

        if let Some(cached_node) = self.cache.get(hash) {
            return Ok(Some(cached_node.clone()));
        }

        if let Some(data) = self.storage.get(hash)? {
            let loaded_node = Node::from_slice(&data).expect("Node bytes should be valid");
            return Ok(Some(loaded_node));
        }

        Err(Error::MissingNode)
    }

    pub fn get(&self, key: &[u8]) -> Option<Node> {
        let key = slice_to_hex(key);
        Self::get_node(&self.root, &key, 0)
    }

    fn get_node(node: &Node, key: &[u8], pos: usize) -> Option<Node> {
        match node {
            Node::Empty => None,
            Node::Short(short) => {
                if key.len() - pos < short.key.len() || key[pos..pos + short.key.len()] != short.key
                {
                    return None;
                }

                Self::get_node(&short.val, key, pos + short.key.len())
            }
            Node::Full(full) => {
                let idx = key[pos] as usize;
                Self::get_node(&full.children[idx], key, pos + 1)
            }
            Node::Hash(_) | Node::Value(_) => Some(node.clone()),
        }
    }

    pub fn commit(&mut self) -> Result<Multihash> {
        if self.root.is_empty() {
            return Ok(Multihash::default());
        }

        if let Some(hash) = self.root.cache() {
            return Ok(*hash);
        }

        let mut root = std::mem::take(&mut self.root);
        let mut pending = HashMap::new();

        Self::commit_node(&mut root, true, &mut pending);

        self.storage
            .batch_put(pending)
            .expect("Failed to batch put pending nodes");

        self.root = root;

        Ok(*self.root.cache().expect("Root node should have a hash"))
    }

    fn commit_node(node: &mut Node, force: bool, pending: &mut HashMap<Multihash, Vec<u8>>) {
        if node.is_empty() || node.is_hash() {
            return;
        }

        match node {
            Node::Short(ref mut short) => {
                Self::commit_node(&mut short.val, false, pending);

                let bytes = short.to_vec().expect("Failed to serialize short node");

                if bytes.len() < 32 && !force {
                    return;
                }

                let hash = H::hash(&bytes);
                pending.insert(hash, bytes);

                short.flags.hash = Some(hash);
                short.flags.is_dirty = false;
            }
            Node::Full(full) => {
                full.children.iter_mut().for_each(|child| {
                    if !child.is_empty() {
                        Self::commit_node(child, false, pending);
                    }
                });

                let bytes = full.to_vec().expect("Failed to serialize full node");

                if bytes.len() < 32 && !force {
                    return;
                }

                let hash = H::hash(&bytes);
                pending.insert(hash, bytes);

                full.flags.hash = Some(hash);
                full.flags.is_dirty = false;
            }
            _ => {}
        }
    }

    pub fn prove(&self, key: &[u8], proof_db: &mut HashMap<Multihash, Vec<u8>>) -> Result<bool> {
        let key_vec = slice_to_hex(key);
        let mut key = key_vec.as_slice();

        let mut prefix = Vec::new();
        let mut nodes = Vec::new();
        let mut cur = self.root.clone();

        while !key.is_empty() && !cur.is_empty() {
            match cur {
                Node::Short(short) => {
                    if prefix_len(key, &short.key) == 0 {
                        cur = Node::Empty;
                    } else {
                        cur = *short.val;
                        prefix.extend_from_slice(short.key.as_ref());
                        key = &key[short.key.len()..];
                    }
                    nodes.push(cur.clone());
                }
                Node::Full(full) => {
                    cur = full.children[key[0] as usize].to_owned();
                    prefix.push(key[0]);
                    key = &key[1..];
                    nodes.push(cur.clone());
                }
                Node::Hash(_) => {
                    let node = self.resolve_node(&cur)?.ok_or(Error::MissingNode)?;
                    cur = node;
                }
                _ => panic!("Unexpected node type in prove: {cur:?}"),
            }
        }

        nodes.push(self.root.clone());

        for n in nodes.iter() {
            let enc = n.to_vec().expect("Failed to serialize node");
            let hash = n.cache().cloned().unwrap_or(H::hash(&enc));
            proof_db.insert(hash, enc);
        }

        Ok(true)
    }

    pub fn verify_proof(&self, key: &[u8], proof_db: &HashMap<Multihash, Vec<u8>>) -> Option<Node> {
        let key_vec = slice_to_hex(key);
        let mut key = key_vec.as_slice();

        let mut expected_hash = self.root.cache().cloned().unwrap_or_else(|| {
            H::hash(&self.root.to_vec().expect("Failed to serialize root node"))
        });

        loop {
            let cur = proof_db.get(&expected_hash)?;
            let node = Node::from_slice(cur).ok()?;

            let (keyrest, cld) = Self::get_child(&node, key)?;

            match cld {
                Node::Empty => return None,
                Node::Hash(hash) => {
                    key = keyrest;
                    expected_hash = hash;
                }
                Node::Value(_) => {
                    return Some(cld);
                }
                _ => {}
            }
        }
    }

    fn get_child<'a>(mut node: &Node, mut key: &'a [u8]) -> Option<(&'a [u8], Node)> {
        loop {
            match node {
                Node::Short(short) => {
                    if key.len() < short.key.len() || key[..short.key.len()] != short.key {
                        return None;
                    }
                    node = &short.val;
                    key = &key[short.key.len()..];
                }

                Node::Full(full) => {
                    let idx = key[0] as usize;
                    node = &full.children[idx];
                    key = &key[1..];
                }
                Node::Hash(_) => {
                    return Some((key, node.clone()));
                }
                Node::Empty => {
                    return Some((key, Node::Empty));
                }
                Node::Value(_) => {
                    return Some((key, node.clone()));
                }
            }
        }
    }
}

impl Storage for HashMap<Multihash, Vec<u8>> {
    fn get(&self, hash: &Multihash) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.get(hash).cloned())
    }

    fn put(&mut self, hash: Multihash, data: Vec<u8>) -> Result<(), StorageError> {
        self.insert(hash, data);
        Ok(())
    }

    fn delete(&mut self, hash: &Multihash) -> Result<(), StorageError> {
        self.remove(hash);
        Ok(())
    }

    fn has(&self, hash: &Multihash) -> Result<bool, StorageError> {
        Ok(self.contains_key(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestHasher = sha2::Sha256;
    type TestMerklePatriciaTrie = MerklePatriciaTrie<TestHasher, HashMap<Multihash, Vec<u8>>>;

    #[test]
    fn insert_and_commit() {
        const KEY: &[u8] = &[1, 2, 3, 4];
        const VALUE: &[u8] = &[5, 6, 7, 8];
        const EXP: &[u8; 32] = &[
            58, 79, 249, 90, 58, 219, 221, 240, 229, 209, 57, 149, 231, 28, 21, 178, 202, 43, 227,
            210, 238, 35, 24, 224, 18, 68, 190, 14, 180, 23, 173, 189,
        ];

        let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());

        mpt.update(KEY, Node::Value(VALUE.to_vec()))
            .expect("Failed to update MPT");

        let hash = mpt.commit().expect("Failed to commit MPT");

        assert_eq!(hash.digest(), EXP);
    }

    #[test]
    fn return_value_if_key_found() {
        const KEY: &[u8] = &[1, 2, 3, 4];
        const VALUE: &[u8] = &[5, 6, 7, 8];

        let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());

        mpt.update(KEY, Node::Value(VALUE.to_vec()))
            .expect("Failed to update MPT");
        mpt.commit().expect("Failed to commit MPT");

        let result = mpt.get(KEY);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), Node::Value(VALUE.to_vec()));
    }

    #[test]
    fn return_none_if_key_not_found() {
        const KEY: &[u8] = &[1, 2, 3, 4];
        const VALUE: &[u8] = &[5, 6, 7, 8];
        const NON_EXISTENT_KEY: &[u8] = &[9, 10, 11];

        let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());

        mpt.update(KEY, Node::Value(VALUE.to_vec()))
            .expect("Failed to update MPT");
        mpt.commit().expect("Failed to commit MPT");

        let result = mpt.get(NON_EXISTENT_KEY);

        assert!(result.is_none());
    }

    #[test]
    fn prove_and_verify() {
        const KEY: &[u8] = &[1, 2, 3, 4];
        const VALUE: &[u8] = &[5, 6, 7, 8];

        let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());

        mpt.update(KEY, Node::Value(VALUE.to_vec()))
            .expect("Failed to update MPT");
        mpt.commit().expect("Failed to commit MPT");

        let mut proof_db = HashMap::new();
        let prove_res = mpt.prove(KEY, &mut proof_db).expect("Failed to prove key");
        let verify_res = mpt.verify_proof(KEY, &proof_db);

        assert!(prove_res);
        assert!(verify_res.is_some());
        assert_eq!(verify_res.unwrap(), Node::Value(VALUE.to_vec()));
    }
}
