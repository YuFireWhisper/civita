use std::{collections::HashMap, marker::PhantomData};

use civita_serialize::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash},
    utils::trie::{
        keys::{prefix_len, slice_to_hex},
        node::{Full, Node},
    },
};

mod keys;
mod node;
mod record;

pub use record::Record;

pub type Weight = u64;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum ProofResult {
    Exists(Record),
    NotExists,
    Invalid,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct Trie<H> {
    root: Node,
    _marker: PhantomData<H>,
}

impl<H: Hasher> Trie<H> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_root(root_hash: Multihash) -> Self {
        Self {
            root: Node::Hash(root_hash),
            _marker: PhantomData,
        }
    }

    pub fn from_root_with_guide(root_hash: Multihash, guide: HashMap<Multihash, Vec<u8>>) -> Self {
        let mut trie = Self {
            root: Node::Hash(root_hash),
            _marker: PhantomData,
        };

        Self::expand_node_from_guide(&mut trie.root, &guide);

        trie
    }

    fn expand_node_from_guide(node: &mut Node, guide: &HashMap<Multihash, Vec<u8>>) {
        match node {
            Node::Hash(hash) => {
                if let Some(data) = guide.get(hash) {
                    if let Ok(resolved_node) = Node::from_slice(data) {
                        *node = resolved_node;
                        Self::expand_node_from_guide(node, guide);
                    }
                }
            }
            Node::Full(full) => {
                for child in full.children.iter_mut() {
                    Self::expand_node_from_guide(child, guide);
                }
            }
            Node::Short(short) => {
                Self::expand_node_from_guide(&mut short.val, guide);
            }
            Node::Value(_) | Node::Empty => {}
        }
    }

    pub fn update(
        &mut self,
        key: &[u8],
        record: Record,
        guile: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool {
        let key_vec = slice_to_hex(key);
        let key = key_vec.as_slice();

        let val = Node::new_value(record);

        Self::insert_node(&mut self.root, &[], key, val, guile)
    }

    pub fn update_many<'a, I, T>(
        &mut self,
        itmes: I,
        guide: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool
    where
        I: IntoIterator<Item = (T, Record)>,
        T: AsRef<[u8]> + 'a,
    {
        itmes
            .into_iter()
            .any(|(key, record)| self.update(key.as_ref(), record, guide))
    }

    /// Returns true if is dirty, false if not.
    fn insert_node(
        node: &mut Node,
        prefix: &[u8],
        key: &[u8],
        val: Node,
        guide: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool {
        if key.is_empty() {
            if node.is_value() && node == &val {
                return false;
            }
            *node = val;
            return true;
        }

        match node {
            Node::Short(short) => {
                let match_len = prefix_len(prefix, &short.key);

                if match_len == short.key.len() {
                    let mut s_val = std::mem::take(&mut short.val);

                    let prefix = &[prefix, &short.key[..match_len]].concat();
                    let key = &key[match_len..];

                    let is_dirty = Self::insert_node(&mut s_val, prefix, key, val, guide);

                    if !is_dirty {
                        return false;
                    }

                    short.clear_cache();

                    return true;
                }

                let mut branch = Full::default();

                {
                    let idx = short.key[match_len] as usize;
                    let prefix = &[prefix, &short.key[..match_len]].concat();
                    let key = &short.key[match_len + 1..];
                    Self::insert_node(
                        &mut branch.children[idx],
                        prefix,
                        key,
                        *short.val.clone(),
                        guide,
                    );
                }

                {
                    let idx = key[match_len] as usize;
                    let prefix = &[prefix, &key[..match_len]].concat();
                    let key = &key[match_len + 1..];
                    Self::insert_node(&mut branch.children[idx], prefix, key, val, guide);
                }

                if match_len == 0 {
                    *node = Node::from_full(branch);
                    return true;
                }

                let key = short.key.split_off(match_len);
                *node = Node::new_short(key, branch);

                true
            }
            Node::Full(ref mut full) => {
                let idx = key[0] as usize;

                let prefix = &[prefix, &key[..1]].concat();
                let key = &key[1..];

                let is_dirty = Self::insert_node(&mut full.children[idx], prefix, key, val, guide);

                if !is_dirty {
                    return false;
                }

                full.clear_caches();

                true
            }
            Node::Empty => {
                *node = Node::new_short(key.to_vec(), val);
                true
            }
            Node::Hash(hash) => {
                let Some(rn) = Self::resolve_from_guide(hash, guide) else {
                    return false;
                };

                *node = rn;

                Self::insert_node(node, prefix, key, val, guide)
            }
            Node::Value(_) => {
                panic!("Unexpected value node in insert_new: {node:?}");
            }
        }
    }

    fn resolve_from_guide(
        hash: &Multihash,
        guide: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> Option<Node> {
        guide
            .and_then(|g| g.get(hash))
            .map(|data| Node::from_slice(data).expect("Node bytes should be valid"))
    }

    pub fn get(&self, key: &[u8]) -> Option<Record> {
        let key = slice_to_hex(key);
        Self::get_node(&self.root, &key, 0)
    }

    fn get_node(node: &Node, key: &[u8], pos: usize) -> Option<Record> {
        match node {
            Node::Empty => None,
            Node::Value(val) => Some(val.record.clone()),
            Node::Short(short) => {
                if !key[pos..].starts_with(&short.key) {
                    return None;
                }
                Self::get_node(&short.val, key, pos + short.key.len())
            }
            Node::Full(full) => Self::get_node(&full.children[key[pos] as usize], key, pos + 1),
            Node::Hash(_) => None,
        }
    }

    pub fn commit(&mut self) -> Multihash {
        self.root.hash_children::<H>();
        self.root.hash::<H>()
    }

    pub fn prove(&self, key: &[u8], proof_db: &mut HashMap<Multihash, Vec<u8>>) -> bool {
        let key_vec = slice_to_hex(key);
        let mut key = key_vec.as_slice();

        let mut changes = Vec::new();
        let mut cur = self.root.clone();

        while !key.is_empty() && !cur.is_empty() {
            if !cur.is_empty() {
                let hash = cur.hash::<H>();

                if let Some(n) = proof_db.remove(&hash) {
                    let mut n = Node::from_slice(&n).expect("Node bytes should be valid");
                    n.merge_with(&cur);
                    cur = n;
                }

                if proof_db.insert(hash, cur.to_vec()).is_none() {
                    changes.push(hash);
                }
            }

            match &cur {
                Node::Short(short) => {
                    if !key.starts_with(&short.key) {
                        break;
                    }
                    key = &key[short.key.len()..];
                    cur = *short.val.clone();
                }
                Node::Full(full) => {
                    cur = full.children[key[0] as usize].to_owned();
                    key = &key[1..];
                }
                Node::Hash(_) => {
                    changes.iter().for_each(|h| {
                        proof_db.remove(h);
                    });
                    return false;
                }
                Node::Value(_) => {
                    panic!("Unexpected value node in proof generation: {cur:?}");
                }
                Node::Empty => {
                    panic!("Unexpected empty node in proof generation");
                }
            };
        }

        true
    }

    pub fn verify_proof(&self, key: &[u8], proof_db: &HashMap<Multihash, Vec<u8>>) -> ProofResult {
        let expected_hash = self.root.hash::<H>();
        verify_proof_with_hash(key, proof_db, expected_hash)
    }

    pub fn reduce_one(&self, key: &[u8]) -> Self {
        let mut proofs = HashMap::new();
        assert!(self.prove(key, &mut proofs), "Failed to prove key");
        Self::from_root_with_guide(self.root.hash::<H>(), proofs)
    }

    pub fn root_hash(&self) -> Multihash {
        self.root.hash::<H>()
    }

    pub fn weight(&self) -> u64 {
        self.root.weight()
    }
}

enum TraversalResult<'a> {
    Continue {
        remaining_key: &'a [u8],
        next_hash: Multihash,
    },
    Found(Record),
    NotFound,
}

pub fn verify_proof_with_hash(
    key: &[u8],
    proof_db: &HashMap<Multihash, Vec<u8>>,
    mut exp_hash: Multihash,
) -> ProofResult {
    let key_vec = slice_to_hex(key);
    let mut key = key_vec.as_slice();

    if exp_hash == Multihash::default() {
        return ProofResult::NotExists;
    }

    loop {
        let Some(cur) = proof_db.get(&exp_hash) else {
            return ProofResult::Invalid;
        };

        let Ok(node) = Node::from_slice(cur) else {
            return ProofResult::Invalid;
        };

        match traverse_node(&node, key) {
            TraversalResult::Continue {
                remaining_key,
                next_hash,
            } => {
                key = remaining_key;
                exp_hash = next_hash;
            }
            TraversalResult::Found(value) => {
                return ProofResult::Exists(value);
            }
            TraversalResult::NotFound => {
                return ProofResult::NotExists;
            }
        }
    }
}

fn traverse_node<'a>(mut node: &Node, mut key: &'a [u8]) -> TraversalResult<'a> {
    loop {
        match node {
            Node::Short(short) => {
                if !key.starts_with(&short.key) {
                    return TraversalResult::NotFound;
                }

                key = &key[short.key.len()..];
                node = &short.val;
            }

            Node::Full(full) => {
                if key.is_empty() {
                    if let Node::Value(val) = &full.children[16] {
                        return TraversalResult::Found(val.record.clone());
                    } else {
                        return TraversalResult::NotFound;
                    }
                } else {
                    let idx = key[0] as usize;
                    key = &key[1..];
                    node = &full.children[idx];
                }
            }

            Node::Value(val) => {
                if key.is_empty() {
                    return TraversalResult::Found(val.record.clone());
                } else {
                    return TraversalResult::NotFound;
                }
            }

            Node::Hash(hash) => {
                return TraversalResult::Continue {
                    remaining_key: key,
                    next_hash: *hash,
                };
            }

            Node::Empty => {
                return TraversalResult::NotFound;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestHasher = sha2::Sha256;
    type TestTrie = Trie<TestHasher>;

    const KEY1: &[u8] = b"key_1";
    const KEY2: &[u8] = b"key_2";
    const KEY3: &[u8] = b"key3";

    #[test]
    fn return_some_if_key_found() {
        let mut mpt = TestTrie::empty();

        let record1 = Record::new(10, b"value1".to_vec());
        let record2 = Record::new(20, b"value2".to_vec());
        let record3 = Record::new(30, b"value3".to_vec());

        mpt.update(KEY1, record1.clone(), None);
        mpt.update(KEY2, record2.clone(), None);
        mpt.update(KEY3, record3.clone(), None);

        let res1 = mpt.get(KEY1);
        let res2 = mpt.get(KEY2);
        let res3 = mpt.get(KEY3);

        assert_eq!(res1.unwrap(), record1);
        assert_eq!(res2.unwrap(), record2);
        assert_eq!(res3.unwrap(), record3);
    }

    #[test]
    fn return_none_if_key_not_found() {
        let mut mpt = TestTrie::empty();

        let record1 = Record::new(10, b"value1".to_vec());
        mpt.update(KEY1, record1, None);

        let res = mpt.get(b"non_existent_key");

        assert!(res.is_none());
    }

    #[test]
    fn correct_total_weight() {
        let mut mpt = TestTrie::empty();

        let record1 = Record::new(10, b"value1".to_vec());
        let record2 = Record::new(20, b"value2".to_vec());
        let record3 = Record::new(30, b"value3".to_vec());

        mpt.update(KEY1, record1, None);
        mpt.update(KEY2, record2, None);
        mpt.update(KEY3, record3, None);
        let _ = mpt.commit();

        assert_eq!(mpt.weight(), 60, "Total weight should be 60");
    }

    #[test]
    fn verify_exists_proof() {
        let mut mpt = TestTrie::empty();

        let record1 = Record::new(10, b"value1".to_vec());
        let record2 = Record::new(20, b"value2".to_vec());
        let record3 = Record::new(30, b"value3".to_vec());

        mpt.update(KEY1, record1.clone(), None);
        mpt.update(KEY2, record2.clone(), None);
        mpt.update(KEY3, record3.clone(), None);
        let _ = mpt.commit();

        let mut proof_db = HashMap::new();

        let prove_res1 = mpt.prove(KEY1, &mut proof_db);
        let prove_res2 = mpt.prove(KEY2, &mut proof_db);
        let prove_res3 = mpt.prove(KEY3, &mut proof_db);

        let verify_res1 = mpt.verify_proof(KEY1, &proof_db);
        let verify_res2 = mpt.verify_proof(KEY2, &proof_db);
        let verify_res3 = mpt.verify_proof(KEY3, &proof_db);

        assert!(prove_res1, "Failed to prove key1");
        assert!(prove_res2, "Failed to prove key2");
        assert!(prove_res3, "Failed to prove key3");

        assert_eq!(verify_res1, ProofResult::Exists(record1));
        assert_eq!(verify_res2, ProofResult::Exists(record2));
        assert_eq!(verify_res3, ProofResult::Exists(record3));
    }

    #[test]
    fn verify_not_exists_proof() {
        let mut mpt = TestTrie::empty();

        let record1 = Record::new(10, b"value1".to_vec());
        mpt.update(KEY1, record1, None);
        let _ = mpt.commit();

        let mut proof_db = HashMap::new();

        let prove_res = mpt.prove(KEY2, &mut proof_db);
        let verify_res = mpt.verify_proof(KEY2, &proof_db);

        assert!(prove_res, "Failed to prove non-existent key");
        assert_eq!(verify_res, ProofResult::NotExists);
    }

    #[test]
    fn verify_invalid_proof() {
        let mpt = TestTrie::from_root(Multihash::wrap(0, &[1; 32]).unwrap());

        let proof_db = HashMap::new();

        let verify_res = mpt.verify_proof(KEY1, &proof_db);

        assert_eq!(verify_res, ProofResult::Invalid);
    }
}
