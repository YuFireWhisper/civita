use std::collections::HashMap;

use civita_serialize::Serialize;

use crate::{
    crypto::{hasher::Hasher, Multihash},
    utils::trie::{
        keys::{prefix_len, slice_to_hex},
        node::{Full, Node, Value},
    },
};

mod keys;
mod node;

enum TraverseResult<'a> {
    Exists(Vec<u8>),
    Continue(&'a [u8], Multihash),
    NotFound,
}

#[derive(Debug)]
pub struct InvalidProof;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
pub struct Trie {
    root: Node,
}

impl Trie {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_root_hash(root_hash: Multihash) -> Self {
        if root_hash == Multihash::default() {
            return Self::empty();
        }

        Self {
            root: Node::Hash(root_hash),
        }
    }

    pub fn resolve<'a, I, U>(&mut self, keys: I, guide: &HashMap<Multihash, Vec<u8>>) -> bool
    where
        I: IntoIterator<Item = U>,
        U: AsRef<[u8]> + 'a,
    {
        keys.into_iter()
            .all(|key| self.resolve_single_key(key.as_ref(), guide))
    }

    fn resolve_single_key(&mut self, key: &[u8], guide: &HashMap<Multihash, Vec<u8>>) -> bool {
        let key_nibble = slice_to_hex(key);
        let mut key_path = key_nibble.as_slice();
        let mut current_node = &mut self.root;

        loop {
            if !Self::try_resolve_node(current_node, guide) {
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
                        if !Self::try_resolve_node(&mut full.children[16], guide) {
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

    fn try_resolve_node(node: &mut Node, guide: &HashMap<Multihash, Vec<u8>>) -> bool {
        match node {
            Node::Hash(hash) => {
                let Some(data) = guide.get(hash) else {
                    return false;
                };

                if !Hasher::validate(hash, data) {
                    return false;
                }

                Node::from_slice(data).is_ok_and(|resolved_node| {
                    *node = resolved_node;
                    true
                })
            }
            _ => true,
        }
    }

    pub fn extend<'a, I, K>(&mut self, items: I) -> bool
    where
        I: IntoIterator<Item = (K, Vec<u8>)>,
        K: AsRef<[u8]> + 'a,
    {
        let mut dirty = false;

        items.into_iter().for_each(|(key, value)| {
            if self.insert(key.as_ref(), value) {
                dirty = true;
            }
        });

        dirty
    }

    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> bool {
        let key_nibble = slice_to_hex(key);
        let mut key_path = key_nibble.as_slice();
        let mut cur_node = &mut self.root;
        let mut dirty = false;
        let value = Value::new(value);

        loop {
            let taken_node = std::mem::take(cur_node);

            match taken_node {
                Node::Empty => {
                    *cur_node = Node::new_short(key_path.to_vec(), Node::Value(value));
                    dirty = true;
                    break;
                }
                Node::Value(mut val) => {
                    if key_path.is_empty() {
                        if val != value {
                            val = value;
                            dirty = true;
                        }
                        *cur_node = Node::Value(val);
                        break;
                    }

                    let full = {
                        let mut full = Full::default();
                        full.children[16] = Node::Value(val);
                        let idx = key_path[0] as usize;
                        let short = Node::new_short(key_path[1..].to_vec(), Node::Value(value));
                        full.children[idx] = short;
                        full
                    };

                    *cur_node = Node::Full(full);
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
                        let idx = key_path[match_len] as usize;
                        let remaining = key_path[match_len + 1..].to_vec();
                        branch.children[idx] = Node::new_short(remaining, Node::Value(value));

                        let full = Node::Full(branch);

                        let prefix = &short.key[..match_len];
                        *cur_node = if prefix.is_empty() {
                            full
                        } else {
                            Node::new_short(prefix.to_vec(), full)
                        };
                    }

                    dirty = true;
                    break;
                }
                Node::Full(mut full) => {
                    if key_path.is_empty() {
                        if let Node::Value(ref mut val) = &mut full.children[16] {
                            if *val != value {
                                *val = value;
                                dirty = true;
                            }
                        } else {
                            full.children[16] = Node::Value(value);
                            dirty = true;
                        }

                        *cur_node = Node::Full(full);
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

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let key = slice_to_hex(key);
        Self::get_node(&self.root, &key, 0)
    }

    fn get_node(node: &Node, key: &[u8], pos: usize) -> Option<Vec<u8>> {
        match node {
            Node::Empty => None,
            Node::Value(val) => Some(val.value.clone()),
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
        self.root.hash_children();
        self.root.hash()
    }

    pub fn prove(&self, key: &[u8], proof_db: &mut HashMap<Multihash, Vec<u8>>) -> bool {
        let key_vec = slice_to_hex(key);
        let mut key_path = key_vec.as_slice();
        let mut current_node = &self.root;

        loop {
            if current_node.is_empty() {
                break;
            }

            let hash = current_node.hash();
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

    pub fn retain<I, K>(&mut self, keys: I) -> bool
    where
        I: IntoIterator<Item = K>,
        K: AsRef<[u8]>,
    {
        let mut owned_paths: Vec<Vec<u8>> =
            keys.into_iter().map(|k| slice_to_hex(k.as_ref())).collect();
        owned_paths.sort();
        let paths: Vec<&[u8]> = owned_paths.iter().map(Vec::as_slice).collect();
        Self::prune_node(&mut self.root, &paths, 0)
    }

    fn prune_node(node: &mut Node, paths: &[&[u8]], pos: usize) -> bool {
        use Node::*;

        if paths.is_empty() {
            let h = node.hash();
            *node = Hash(h);
            return false;
        }

        match node {
            Empty | Value(_) => {
                let keep = paths.iter().any(|p| p.len() == pos);
                if !keep {
                    let h = node.hash();
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
                    let h = node.hash();
                    *node = Hash(h);
                    return false;
                }
                let keep = Self::prune_node(&mut short.val, &matched, pos + klen);
                if !keep {
                    let h = node.hash();
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
                    let h = node.hash();
                    *node = Hash(h);
                }

                any_keep
            }
        }
    }

    pub fn verify_proof(
        root_hash: Multihash,
        key: &[u8],
        proof_db: &HashMap<Multihash, Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, InvalidProof> {
        if root_hash == Multihash::default() {
            if proof_db.is_empty() {
                return Ok(None);
            } else {
                return Err(InvalidProof);
            }
        }

        let key_nibble = slice_to_hex(key);
        let mut key_path = key_nibble.as_slice();
        let mut exp = root_hash;

        loop {
            let Some(cur) = proof_db.get(&exp) else {
                return Err(InvalidProof);
            };

            let Ok(node) = Node::from_slice(cur) else {
                return Err(InvalidProof);
            };

            match Self::traverse_node(&node, key_path) {
                TraverseResult::Exists(val) => {
                    return Ok(Some(val));
                }
                TraverseResult::Continue(next_key, next_hash) => {
                    key_path = next_key;
                    exp = next_hash;
                }
                TraverseResult::NotFound => {
                    return Ok(None);
                }
            }
        }
    }

    fn traverse_node<'a>(mut node: &Node, mut key: &'a [u8]) -> TraverseResult<'a> {
        loop {
            match node {
                Node::Short(short) => {
                    if !key.starts_with(&short.key) {
                        return TraverseResult::NotFound;
                    }

                    key = &key[short.key.len()..];
                    node = &short.val;
                }

                Node::Full(full) => {
                    if key.is_empty() {
                        return match &full.children[16] {
                            Node::Value(val) => TraverseResult::Exists(val.value.clone()),
                            Node::Hash(hash) => TraverseResult::Continue(key, *hash),
                            _ => TraverseResult::NotFound,
                        };
                    }

                    let idx = key[0] as usize;
                    key = &key[1..];
                    node = &full.children[idx];
                }

                Node::Value(val) => {
                    return TraverseResult::Exists(val.value.clone());
                }

                Node::Hash(hash) => {
                    return TraverseResult::Continue(key, *hash);
                }

                Node::Empty => {
                    return TraverseResult::NotFound;
                }
            }
        }
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
        self.root.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestTrie = Trie;

    const KEY1: &[u8] = b"key_1";
    const KEY2: &[u8] = b"key_2";
    const KEY3: &[u8] = b"key3_";

    #[test]
    fn return_some_if_key_found() {
        let mut mpt = TestTrie::empty();

        let val1 = vec![1, 2, 3];
        let val2 = vec![4, 5, 6];
        let val3 = vec![7, 8, 9];

        mpt.insert(KEY1, val1.clone());
        mpt.insert(KEY2, val2.clone());
        mpt.insert(KEY3, val3.clone());

        let res1 = mpt.get(KEY1);
        let res2 = mpt.get(KEY2);
        let res3 = mpt.get(KEY3);

        assert_eq!(res1.unwrap(), val1);
        assert_eq!(res2.unwrap(), val2);
        assert_eq!(res3.unwrap(), val3);
    }

    #[test]
    fn return_none_if_key_not_found() {
        let mut mpt = TestTrie::empty();
        mpt.insert(KEY1, vec![]);
        let res = mpt.get(KEY2);
        assert!(res.is_none());
    }
}
