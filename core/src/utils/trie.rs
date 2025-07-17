use std::{collections::HashMap, marker::PhantomData, sync::OnceLock};

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

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum ProofResult {
    Exists(Vec<u8>),
    NotExists,
    Invalid,
}

#[derive(Derivative)]
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

    pub fn update(
        &mut self,
        key: &[u8],
        val: Vec<u8>,
        guile: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool {
        let key_vec = slice_to_hex(key);
        let key = key_vec.as_slice();

        let val = Node::new_value(val);

        Self::insert_new(&mut self.root, &[], key, val, guile)
    }

    /// Returns true if is dirty, false if not.
    fn insert_new(
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

                    let is_dirty = Self::insert_new(&mut s_val, prefix, key, val, guide);

                    if !is_dirty {
                        return false;
                    }

                    short.hash_cache = OnceLock::new();

                    return true;
                }

                let mut branch = Full::default();

                {
                    let idx = short.key[match_len] as usize;
                    let prefix = &[prefix, &short.key[..match_len]].concat();
                    let key = &short.key[match_len + 1..];
                    Self::insert_new(
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
                    Self::insert_new(&mut branch.children[idx], prefix, key, val, guide);
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

                let is_dirty = Self::insert_new(&mut full.children[idx], prefix, key, val, guide);

                if !is_dirty {
                    return false;
                }

                full.hash_cache = OnceLock::new();

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

                Self::insert_new(node, prefix, key, val, guide)
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

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let key = slice_to_hex(key);
        Self::get_node(&self.root, &key, 0)
    }

    fn get_node(node: &Node, key: &[u8], pos: usize) -> Option<Vec<u8>> {
        match node {
            Node::Empty => None,
            Node::Value(val) => Some(val.as_slice().to_vec()),
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
}

enum TraversalResult<'a> {
    Continue {
        remaining_key: &'a [u8],
        next_hash: Multihash,
    },
    Found(Vec<u8>),
    NotFound,
}

pub fn verify_proof_with_hash(
    key: &[u8],
    proof_db: &HashMap<Multihash, Vec<u8>>,
    mut exp_hash: Multihash,
) -> ProofResult {
    let key_vec = slice_to_hex(key);
    let mut key = key_vec.as_slice();

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
                        return TraversalResult::Found(val.as_slice().to_vec());
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
                    return TraversalResult::Found(val.as_slice().to_vec());
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

    const KEY1: &[u8] = b"key1";
    const VALUE1: &[u8] = b"value1";

    const KEY2: &[u8] = b"key2";
    const VALUE2: &[u8] = b"value2";

    const KEY3: &[u8] = b"key3";
    const VALUE3: &[u8] = b"value3";

    #[test]
    fn return_some_if_key_found() {
        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);
        mpt.update(KEY2, VALUE2.to_vec(), None);
        mpt.update(KEY3, VALUE3.to_vec(), None);

        let res1 = mpt.get(KEY1);
        let res2 = mpt.get(KEY2);
        let res3 = mpt.get(KEY3);

        assert_eq!(res1, Some(VALUE1.to_vec()));
        assert_eq!(res2, Some(VALUE2.to_vec()));
        assert_eq!(res3, Some(VALUE3.to_vec()));
    }

    #[test]
    fn return_none_if_key_not_found() {
        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);
        mpt.update(KEY2, VALUE2.to_vec(), None);
        mpt.update(KEY3, VALUE3.to_vec(), None);

        let res = mpt.get(b"non_existent_key");

        assert!(res.is_none());
    }

    #[test]
    fn corrent_hash_after_commit() {
        let key_hex = slice_to_hex(KEY1);
        let node = Node::new_short(key_hex, Node::new_value(VALUE1.to_vec()));
        let exp = node.hash::<TestHasher>();

        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);

        let root_hash = mpt.commit();

        assert_eq!(root_hash, exp);
    }

    #[test]
    fn verify_exists_proof() {
        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);
        mpt.update(KEY2, VALUE2.to_vec(), None);
        mpt.update(KEY3, VALUE3.to_vec(), None);
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

        assert_eq!(verify_res1, ProofResult::Exists(VALUE1.to_vec()));
        assert_eq!(verify_res2, ProofResult::Exists(VALUE2.to_vec()));
        assert_eq!(verify_res3, ProofResult::Exists(VALUE3.to_vec()));
    }

    #[test]
    fn verify_not_exists_proof() {
        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);
        let _ = mpt.commit();

        let mut proof_db = HashMap::new();

        let prove_res = mpt.prove(KEY2, &mut proof_db);
        let verify_res = mpt.verify_proof(KEY2, &proof_db);

        assert!(prove_res, "Failed to prove non-existent key");
        assert_eq!(verify_res, ProofResult::NotExists);
    }

    #[test]
    fn verify_invalid_proof() {
        let mpt = TestTrie::empty();

        let proof_db = HashMap::new();

        let verify_res = mpt.verify_proof(KEY1, &proof_db);

        assert_eq!(verify_res, ProofResult::Invalid);
    }

    #[test]
    fn prove_with_hash_root() {
        let mut mpt = TestTrie::empty();

        mpt.update(KEY1, VALUE1.to_vec(), None);
        mpt.update(KEY2, VALUE2.to_vec(), None);
        mpt.update(KEY3, VALUE3.to_vec(), None);
        let root_hash = mpt.commit();

        mpt.root = Node::Hash(root_hash);

        let mut proof_db = HashMap::new();
        let prove_res = mpt.prove(KEY1, &mut proof_db);

        assert!(!prove_res);
        assert!(
            proof_db.is_empty(),
            "Proof DB should be empty for hash root"
        );
    }

    //
    // #[test]
    // fn correct_existence_proof() {
    //     let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());
    //
    //     mpt.update(KEY, VALUE.to_vec())
    //         .expect("Failed to update MPT");
    //     mpt.commit().expect("Failed to commit MPT");
    //
    //     let mut proof_db = HashMap::new();
    //     mpt.prove(KEY, &mut proof_db).expect("Failed to prove key");
    //
    //     let verify_res = mpt.verify_proof(KEY, &proof_db);
    //
    //     assert!(verify_res.is_some());
    //     assert_eq!(verify_res.unwrap(), ProofResult::Exists(VALUE.to_vec()));
    // }
    //
    // #[test]
    // fn correct_non_existence_proof() {
    //     const NON_EXISTENT_KEY: &[u8] = &[9, 10, 11];
    //
    //     let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());
    //
    //     mpt.update(KEY, VALUE.to_vec())
    //         .expect("Failed to update MPT");
    //     mpt.commit().expect("Failed to commit MPT");
    //
    //     let mut proof_db = HashMap::new();
    //     mpt.prove(NON_EXISTENT_KEY, &mut proof_db)
    //         .expect("Failed to prove non-existent key");
    //
    //     let verify_res = mpt.verify_proof(NON_EXISTENT_KEY, &proof_db);
    //
    //     assert!(verify_res.is_some());
    //     assert_eq!(verify_res.unwrap(), ProofResult::NotExists);
    // }
    //
    // #[test]
    // fn false_if_incorrect_proof() {
    //     let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());
    //
    //     mpt.update(KEY, VALUE.to_vec())
    //         .expect("Failed to update MPT");
    //     mpt.commit().expect("Failed to commit MPT");
    //
    //     let mut proof_db = HashMap::new();
    //     mpt.prove(KEY, &mut proof_db).expect("Failed to prove key");
    //
    //     let mut proof_db = HashMap::new();
    //     proof_db.insert(Multihash::default(), vec![0; 32]);
    //
    //     let verify_res = mpt.verify_proof(KEY, &proof_db);
    //
    //     assert!(verify_res.is_none());
    // }
    //
    // #[test]
    // fn false_if_incorrect_hash() {
    //     let mut mpt = TestMerklePatriciaTrie::empty(HashMap::new());
    //
    //     mpt.update(KEY, VALUE.to_vec())
    //         .expect("Failed to update MPT");
    //     let _ = mpt.commit().expect("Failed to commit MPT");
    //     let root_hash = Multihash::default(); // Intentionally incorrect hash
    //
    //     let mut proof_db = HashMap::new();
    //     mpt.prove(KEY, &mut proof_db).expect("Failed to prove key");
    //
    //     let verify_res = verify_proof_with_hash(KEY, &proof_db, root_hash);
    //

    //     assert!(verify_res.is_none());
    // }
}
