use std::{collections::HashMap, marker::PhantomData};

use civita_serialize::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash},
    utils::{
        trie::{
            keys::{prefix_len, slice_to_hex},
            node::{Full, Node},
        },
        Operation, Record,
    },
};

mod keys;
mod node;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum ProofResult<T> {
    Exists(T),
    NotExists,
    Invalid,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Debug(bound = "T: std::fmt::Debug"))]
#[derivative(Default(bound = ""))]
pub struct Trie<H, T: Record> {
    pub root: Node<T>,
    #[derivative(Debug = "ignore")]
    _marker: PhantomData<H>,
}

impl<T> ProofResult<T> {
    pub fn is_invalid(&self) -> bool {
        matches!(self, ProofResult::Invalid)
    }
}

impl<H: Hasher, T: Record> Trie<H, T> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_root(root_hash: Multihash) -> Self {
        Self {
            root: Node::Hash(root_hash),
            _marker: PhantomData,
        }
    }

    pub fn expand<'a, I, U>(&mut self, keys: I, guide: &HashMap<Multihash, Vec<u8>>) -> bool
    where
        I: IntoIterator<Item = U>,
        U: AsRef<[u8]> + 'a,
    {
        keys.into_iter()
            .all(|key| self.expand_single_key(key.as_ref(), guide))
    }

    fn expand_single_key(&mut self, key: &[u8], guide: &HashMap<Multihash, Vec<u8>>) -> bool {
        let key_nibble = slice_to_hex(key);
        let mut key_path = key_nibble.as_slice();
        let mut current_node = &mut self.root;

        loop {
            if !Self::try_expand_node(current_node, guide) {
                return false;
            }

            match current_node {
                Node::Empty => {
                    break;
                }
                Node::Value(_) => {
                    break;
                }
                Node::Short(short) => {
                    let match_len = prefix_len(key_path, &short.key);

                    if match_len < short.key.len() {
                        break;
                    }

                    key_path = &key_path[short.key.len()..];
                    current_node = &mut short.val;
                }
                Node::Full(full) => {
                    if key_path.is_empty() {
                        if !Self::try_expand_node(&mut full.children[16], guide) {
                            return false;
                        }
                        break;
                    }

                    let idx = key_path[0] as usize;
                    if idx >= 16 {
                        break;
                    }

                    key_path = &key_path[1..];
                    current_node = &mut full.children[idx];
                }
                Node::Hash(_) => {
                    return false;
                }
            }
        }

        true
    }

    fn try_expand_node(node: &mut Node<T>, guide: &HashMap<Multihash, Vec<u8>>) -> bool {
        match node {
            Node::Hash(hash) => {
                let Some(data) = guide.get(hash) else {
                    return false;
                };

                Node::from_slice(data).is_ok_and(|resolved_node| {
                    *node = resolved_node;
                    true
                })
            }
            _ => true,
        }
    }

    pub fn apply_operations<'a, I, K>(
        &mut self,
        operations: I,
        guide: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool
    where
        I: IntoIterator<Item = (K, T::Operation)>,
        K: AsRef<[u8]> + 'a,
    {
        operations
            .into_iter()
            .any(|(key, op)| self.apply_operation(key.as_ref(), op, guide))
    }

    pub fn apply_operation(
        &mut self,
        key: &[u8],
        operation: T::Operation,
        _guide: Option<&HashMap<Multihash, Vec<u8>>>,
    ) -> bool {
        if operation.is_empty() {
            return false;
        }

        let key_nibble = slice_to_hex(key);
        let mut key_path = key_nibble.as_slice();
        let mut cur_node = &mut self.root;
        let mut dirty = false;

        loop {
            let taken_node = std::mem::take(cur_node);

            match taken_node {
                Node::Empty => {
                    let mut record = T::default();
                    record.try_apply(operation);
                    *cur_node = Node::new_short(key_path.to_vec(), Node::new_value(record));
                    dirty = true;
                    break;
                }
                Node::Value(mut val) => {
                    if key_path.is_empty() {
                        if val.record.try_apply(operation) {
                            dirty = true;
                        }
                        *cur_node = Node::Value(val);
                        break;
                    }

                    let full = {
                        let mut full = Full::default();
                        full.children[16] = Node::Value(val);
                        let idx = key_path[0] as usize;
                        let mut record = T::default();
                        record.try_apply(operation);
                        let short =
                            Node::new_short(key_path[1..].to_vec(), Node::new_value(record));
                        full.children[idx] = short;
                        full
                    };

                    *cur_node = Node::from_full(full);
                    dirty = true;
                    break;
                }
                Node::Short(mut short) => {
                    let match_len = prefix_len(key_path, &short.key);

                    if match_len == short.key.len() {
                        key_path = &key_path[match_len..];
                        short.clear_cache();
                        *cur_node = *short.val;
                        dirty = true;
                        continue;
                    }

                    let mut branch = Full::default();

                    {
                        let idx = short.key[match_len] as usize;
                        let remaining = short.key[match_len + 1..].to_vec();
                        branch.children[idx] = if remaining.is_empty() {
                            *short.val
                        } else {
                            Node::new_short(remaining, *short.val)
                        };
                    }

                    {
                        let mut record = T::default();
                        record.try_apply(operation);

                        let idx = key_path[match_len] as usize;
                        let remaining = key_path[match_len + 1..].to_vec();
                        branch.children[idx] = Node::new_short(remaining, Node::new_value(record));

                        let prefix = &short.key[..match_len];
                        *cur_node = if prefix.is_empty() {
                            Node::from_full(branch)
                        } else {
                            Node::new_short(prefix.to_vec(), Node::from_full(branch))
                        };
                    }

                    dirty = true;
                    break;
                }
                Node::Full(mut full) => {
                    if key_path.is_empty() {
                        if let Node::Value(ref mut val) = &mut full.children[16] {
                            dirty = val.record.try_apply(operation);
                        } else {
                            let mut record = T::default();
                            record.try_apply(operation);
                            full.children[16] = Node::new_value(record);
                            dirty = true;
                        }

                        *cur_node = Node::from_full(full);
                        break;
                    }

                    let idx = key_path[0] as usize;
                    key_path = &key_path[1..];
                    full.clear_caches();
                    *cur_node = Node::Full(full);
                    cur_node = &mut cur_node.as_full_mut().unwrap().children[idx];
                    dirty = true;
                    continue;
                }
                Node::Hash(hash) => {
                    panic!("Unexpected hash node in apply_operation: {hash:?}");
                }
            }
        }

        dirty
    }

    pub fn get(&self, key: &[u8]) -> Option<T> {
        let key = slice_to_hex(key);
        Self::get_node(&self.root, &key, 0)
    }

    fn get_node(node: &Node<T>, key: &[u8], pos: usize) -> Option<T> {
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
        let mut key_path = key_vec.as_slice();
        let mut current_node = &self.root;

        loop {
            if current_node.is_empty() {
                break;
            }

            let hash = current_node.hash::<H>();
            proof_db.insert(hash, current_node.to_vec());

            match current_node {
                Node::Short(short) => {
                    if !key_path.starts_with(&short.key) {
                        break;
                    }
                    key_path = &key_path[short.key.len()..];
                    current_node = &short.val;
                }
                Node::Full(full) => {
                    if key_path.is_empty() {
                        break;
                    }
                    let idx = key_path[0] as usize;
                    current_node = &full.children[idx];
                    key_path = &key_path[1..];
                }
                Node::Value(_) => break,
                Node::Hash(_) => return false,
                Node::Empty => break,
            }
        }
        true
    }

    pub fn retain<I, U>(&mut self, keys: I) -> bool
    where
        I: IntoIterator<Item = U>,
        U: AsRef<[u8]>,
    {
        let mut owned_paths: Vec<Vec<u8>> =
            keys.into_iter().map(|k| slice_to_hex(k.as_ref())).collect();
        owned_paths.sort();
        let paths: Vec<&[u8]> = owned_paths.iter().map(Vec::as_slice).collect();
        Self::prune_node(&mut self.root, &paths, 0)
    }

    fn prune_node(node: &mut Node<T>, paths: &[&[u8]], pos: usize) -> bool {
        use Node::*;

        if paths.is_empty() {
            let h = node.hash::<H>();
            *node = Hash(h);
            return false;
        }

        match node {
            Empty | Value(_) => {
                let keep = paths.iter().any(|p| p.len() == pos);
                if !keep {
                    let h = node.hash::<H>();
                    *node = Hash(h);
                }
                keep
            }
            Hash(_) => false,

            Short(short) => {
                let key = &short.key;
                let klen = key.len();
                let mut matched = Vec::new();
                for &p in paths {
                    if p.len() >= pos + klen && &p[pos..pos + klen] == key.as_slice() {
                        matched.push(p);
                    }
                }
                if matched.is_empty() {
                    let h = node.hash::<H>();
                    *node = Hash(h);
                    return false;
                }
                let keep = Self::prune_node(&mut short.val, &matched, pos + klen);
                if !keep {
                    let h = node.hash::<H>();
                    *node = Hash(h);
                }
                keep
            }

            Full(full) => {
                let mut any_keep = false;
                let mut buckets: [Vec<&[u8]>; 17] = Default::default();
                for &p in paths {
                    let idx = if p.len() == pos { 16 } else { p[pos] as usize };
                    buckets[idx].push(p);
                }

                buckets
                    .iter()
                    .filter(|b| !b.is_empty())
                    .enumerate()
                    .for_each(|(i, bucket)| {
                        let child = &mut full.children[i];
                        let next_pos = if i == 16 { pos } else { pos + 1 };
                        any_keep |= Self::prune_node(child, bucket, next_pos);
                    });

                if !any_keep {
                    let h = node.hash::<H>();
                    *node = Hash(h);
                }

                any_keep
            }
        }
    }

    pub fn verify_proof(
        &self,
        key: &[u8],
        proof_db: &HashMap<Multihash, Vec<u8>>,
    ) -> ProofResult<T> {
        let expected_hash = self.root.hash::<H>();
        verify_proof_with_hash(key, proof_db, expected_hash)
    }

    pub fn generate_guide<'a, I, U>(&self, keys: I) -> Option<HashMap<Multihash, Vec<u8>>>
    where
        I: IntoIterator<Item = U>,
        U: AsRef<[u8]> + 'a,
    {
        let mut guide = HashMap::new();
        if keys
            .into_iter()
            .all(|key| self.prove(key.as_ref(), &mut guide))
        {
            Some(guide)
        } else {
            None
        }
    }

    pub fn root_hash(&self) -> Multihash {
        self.root.hash::<H>()
    }

    pub fn weight(&self) -> T::Weight {
        self.root.weight()
    }
}

enum TraversalResult<'a, T> {
    Continue {
        remaining_key: &'a [u8],
        next_hash: Multihash,
    },
    Found(T),
    NotFound,
}

pub fn verify_proof_with_hash<T: Record>(
    key: &[u8],
    proof_db: &HashMap<Multihash, Vec<u8>>,
    mut exp_hash: Multihash,
) -> ProofResult<T> {
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

fn traverse_node<'a, T: Clone + Record>(
    mut node: &Node<T>,
    mut key: &'a [u8],
) -> TraversalResult<'a, T> {
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
    use civita_serialize_derive::Serialize;

    use super::*;

    type TestHasher = sha2::Sha256;
    type TestTrie = Trie<TestHasher, u64>;

    const KEY1: &[u8] = b"key_1";
    const KEY2: &[u8] = b"key_2";
    const KEY3: &[u8] = b"key3";

    #[derive(Clone)]
    #[derive(Eq, PartialEq)]
    #[derive(Serialize)]
    struct TestOperation;

    impl Record for u64 {
        type Operation = u64;
        type Weight = u64;

        fn try_apply(&mut self, operation: Self::Operation) -> bool {
            *self += operation;
            true
        }

        fn weight(&self) -> Self::Weight {
            *self
        }
    }

    impl Operation for u64 {
        fn is_empty(&self) -> bool {
            false
        }

        fn is_order_dependent(&self, _: &[u8]) -> bool {
            false
        }
    }

    #[test]
    fn return_some_if_key_found() {
        let mut mpt = TestTrie::empty();

        let opt1 = 10;
        let opt2 = 20;
        let opt3 = 30;

        mpt.apply_operation(KEY1, opt1, None);
        mpt.apply_operation(KEY2, opt2, None);
        mpt.apply_operation(KEY3, opt3, None);

        let res1 = mpt.get(KEY1);
        let res2 = mpt.get(KEY2);
        let res3 = mpt.get(KEY3);

        assert_eq!(res1.unwrap(), opt1);
        assert_eq!(res2.unwrap(), opt2);
        assert_eq!(res3.unwrap(), opt3);
    }

    #[test]
    fn return_none_if_key_not_found() {
        let mut mpt = TestTrie::empty();
        mpt.apply_operation(KEY1, 10, None);

        let res = mpt.get(KEY2);

        assert!(res.is_none());
    }

    #[test]
    fn correct_total_weight() {
        let mut mpt = TestTrie::empty();

        let opt1 = 10;
        let opt2 = 20;
        let opt3 = 30;

        let total = opt1 + opt2 + opt3;

        mpt.apply_operation(KEY1, opt1, None);
        mpt.apply_operation(KEY2, opt2, None);
        mpt.apply_operation(KEY3, opt3, None);

        assert_eq!(mpt.weight(), total);
    }

    #[test]
    fn verify_exists_proof() {
        let mut mpt = TestTrie::empty();

        let opt1 = 10;
        let opt2 = 20;
        let opt3 = 30;

        mpt.apply_operation(KEY1, opt1, None);
        mpt.apply_operation(KEY2, opt2, None);
        mpt.apply_operation(KEY3, opt3, None);

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

        assert_eq!(verify_res1, ProofResult::Exists(opt1));
        assert_eq!(verify_res2, ProofResult::Exists(opt2));
        assert_eq!(verify_res3, ProofResult::Exists(opt3));
    }

    #[test]
    fn verify_not_exists_proof() {
        let mut mpt = TestTrie::empty();

        mpt.apply_operation(KEY1, 10, None);

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
