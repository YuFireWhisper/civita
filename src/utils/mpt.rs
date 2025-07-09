use std::{collections::HashMap, marker::PhantomData, mem};

use crate::crypto::{Hasher, Multihash};

mod node;
mod proof;

pub use node::Node;
pub use proof::Proof;

pub type Nibble = u8; // 0-15
pub type Path = Vec<Nibble>;

#[derive(Clone)]
struct PathTrie {
    value: Option<Multihash>,
    children: HashMap<Nibble, PathTrie>,
    is_single_path: bool,
}

pub struct MerklePatriciaTrie<H> {
    root_hash: Multihash,
    staged: PathTrie,
    nodes: HashMap<Multihash, Node>,
    _marker: PhantomData<H>,
}

impl PathTrie {
    pub fn insert(&mut self, path: &[Nibble], value: Multihash) {
        let is_same_path = self.insert_recursive(path, value, 0);

        if self.is_single_path && !is_same_path && self.children.len() > 1 {
            self.is_single_path = false;
        }
    }

    fn insert_recursive(&mut self, path: &[Nibble], value: Multihash, depth: usize) -> bool {
        if depth == path.len() {
            let old = self.value.replace(value);
            return old.is_some();
        }

        let nibble = path[depth];
        let child = self.children.entry(nibble).or_default();
        child.insert_recursive(path, value, depth + 1)
    }

    fn is_single_path(&self) -> bool {
        self.is_single_path
    }

    fn get_single_path(&self) -> Option<(Vec<u8>, Multihash)> {
        if !self.is_single_path() {
            return None;
        }

        if let Some(value) = self.value {
            return Some((vec![], value));
        }

        let (nibble, child) = self.children.iter().next().unwrap();
        let (mut path, value) = child.get_single_path().unwrap();
        path.insert(0, *nibble);
        Some((path, value))
    }

    fn get_value_at_empty_path(&self) -> Option<Multihash> {
        self.value
    }

    fn get_value_at_path(&self, path: &[Nibble]) -> Option<Multihash> {
        if path.is_empty() {
            return self.value;
        }

        let nibble = path[0];
        self.children
            .get(&nibble)
            .and_then(|child| child.get_value_at_path(&path[1..]))
    }

    fn get_subtrie_after_prefix(&self, prefix: &[Nibble]) -> PathTrie {
        if prefix.is_empty() {
            return self.clone();
        }

        let nibble = prefix[0];
        self.children
            .get(&nibble)
            .map_or_else(PathTrie::default, |child| {
                child.get_subtrie_after_prefix(&prefix[1..])
            })
    }

    fn get_subtrie_for_nibble(&self, nibble: Nibble) -> PathTrie {
        self.children.get(&nibble).cloned().unwrap_or_default()
    }

    fn is_empty(&self) -> bool {
        self.value.is_none() && self.children.is_empty()
    }

    fn find_common_prefix_with(&self, path: &[Nibble]) -> Vec<Nibble> {
        let mut common_prefix = Vec::new();
        let mut current = self;

        for &nibble in path {
            if current.children.len() == 1 && current.value.is_none() {
                let (child_nibble, child) = current.children.iter().next().unwrap();
                if *child_nibble == nibble {
                    common_prefix.push(nibble);
                    current = child;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        common_prefix
    }
}

impl<H: Hasher> MerklePatriciaTrie<H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_root(root: Node) -> Self {
        let root_hash = root.hash::<H>();
        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root);

        Self {
            root_hash,
            staged: PathTrie::default(),
            nodes,
            _marker: PhantomData,
        }
    }

    pub fn insert_raw(&mut self, key: &[u8], value: Multihash) {
        let path = bytes_to_nibbles(key);
        self.staged.insert(&path, value);
    }

    pub fn insert(&mut self, proof: Proof, value: Multihash) -> bool {
        if !proof.verify::<H>(&self.root_hash) {
            return false;
        }

        self.insert_uncheck(proof, value);

        true
    }

    pub fn insert_uncheck(&mut self, proof: Proof, value: Multihash) {
        let path = bytes_to_nibbles(proof.key());
        self.staged.insert(&path, value);
        self.store_proof_nodes(proof);
    }

    fn store_proof_nodes(&mut self, proof: Proof) {
        proof.nodes_into().into_iter().for_each(|node| {
            self.nodes.insert(node.hash::<H>(), node);
        });
    }

    pub fn verify_proof(&self, proof: &Proof) -> bool {
        proof.verify::<H>(&self.root_hash)
    }

    pub fn commit(&mut self) -> (Multihash, HashMap<Multihash, Node>) {
        if self.staged.is_empty() {
            return (self.root_hash, HashMap::new());
        }

        let mut changeds = HashMap::new();
        let staged = mem::take(&mut self.staged);
        let new_root = self.apply(&self.root_hash, &staged, &mut changeds);

        changeds.extend(self.nodes.iter().map(|(k, v)| (*k, v.clone())));

        self.root_hash = new_root.hash::<H>();
        self.nodes.insert(self.root_hash, new_root);

        (self.root_hash, changeds)
    }

    fn apply(
        &self,
        node_hash: &Multihash,
        path_trie: &PathTrie,
        changeds: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let node = self.nodes.get(node_hash).unwrap().clone();

        match node {
            Node::Empty => self.create_new_subtree(path_trie, changeds),
            Node::Leaf { path, value } => {
                self.handle_leaf_batch_update(path, value, path_trie, changeds)
            }
            Node::Extension { path, child } => {
                self.handle_extension_update(path, child, path_trie, changeds)
            }
            Node::Branch { children, value } => {
                self.handle_branch_update(*children, value, path_trie, changeds)
            }
        }
    }

    fn create_new_subtree(
        &self,
        path_trie: &PathTrie,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        if let Some((path, value)) = path_trie.get_single_path() {
            return Node::new_leaf(path, value);
        }

        self.create_branch_from_path_trie(path_trie, changed_nodes)
    }

    fn create_branch_from_path_trie(
        &self,
        path_trie: &PathTrie,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let mut children: [Option<Multihash>; 16] = [None; 16];
        let branch_value = path_trie.get_value_at_empty_path();

        children.iter_mut().enumerate().for_each(|(i, child)| {
            let child_trie = path_trie.get_subtrie_for_nibble(i as u8);
            if !child_trie.is_empty() {
                let child_node = self.create_new_subtree(&child_trie, changed_nodes);
                let child_hash = child_node.hash::<H>();
                changed_nodes.insert(child_hash, child_node);
                *child = Some(child_hash);
            }
        });

        Node::Branch {
            children: children.into(),
            value: branch_value,
        }
    }

    fn handle_leaf_batch_update(
        &self,
        leaf_path: Vec<Nibble>,
        leaf_value: Multihash,
        path_trie: &PathTrie,
        changeds: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let common_prefix = path_trie.find_common_prefix_with(&leaf_path);

        if common_prefix.len() == leaf_path.len() {
            if let Some(new_value) = path_trie.get_value_at_path(&leaf_path) {
                return Node::new_leaf(leaf_path, new_value);
            }
        }

        self.split_leaf(leaf_path, leaf_value, path_trie, common_prefix, changeds)
    }

    fn split_leaf(
        &self,
        leaf_path: Vec<Nibble>,
        leaf_value: Multihash,
        path_trie: &PathTrie,
        common_prefix: Vec<Nibble>,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let leaf_remaining = &leaf_path[common_prefix.len()..];

        let mut branch_children: [Option<Multihash>; 16] = [None; 16];
        let mut branch_value = None;

        if leaf_remaining.is_empty() {
            branch_value = Some(leaf_value);
        } else {
            let leaf_child = Node::new_leaf(leaf_remaining[1..].to_vec(), leaf_value);
            let leaf_child_hash = leaf_child.hash::<H>();
            changed_nodes.insert(leaf_child_hash, leaf_child);
            branch_children[leaf_remaining[0] as usize] = Some(leaf_child_hash);
        }

        let remaining_trie = path_trie.get_subtrie_after_prefix(&common_prefix);

        if let Some(value) = remaining_trie.get_value_at_empty_path() {
            branch_value = Some(value);
        }

        branch_children
            .iter_mut()
            .enumerate()
            .for_each(|(i, child)| {
                let child_trie = remaining_trie.get_subtrie_for_nibble(i as u8);
                if !child_trie.is_empty() {
                    let child_node = self.create_new_subtree(&child_trie, changed_nodes);
                    let child_hash = child_node.hash::<H>();
                    changed_nodes.insert(child_hash, child_node);
                    *child = Some(child_hash);
                }
            });

        let branch = Node::Branch {
            children: branch_children.into(),
            value: branch_value,
        };

        if common_prefix.is_empty() {
            branch
        } else {
            let branch_hash = branch.hash::<H>();
            changed_nodes.insert(branch_hash, branch.clone());
            Node::Extension {
                path: common_prefix,
                child: branch_hash,
            }
        }
    }

    fn handle_extension_update(
        &self,
        ext_path: Vec<Nibble>,
        child_hash: Multihash,
        path_trie: &PathTrie,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let common_prefix = path_trie.find_common_prefix_with(&ext_path);

        if common_prefix.len() == ext_path.len() {
            let remaining_trie = path_trie.get_subtrie_after_prefix(&ext_path);
            let new_child = self.apply(&child_hash, &remaining_trie, changed_nodes);
            let new_child_hash = new_child.hash::<H>();
            changed_nodes.insert(new_child_hash, new_child);
            return Node::Extension {
                path: ext_path,
                child: new_child_hash,
            };
        }

        self.split_extension(
            ext_path,
            child_hash,
            path_trie,
            common_prefix,
            changed_nodes,
        )
    }

    fn split_extension(
        &self,
        ext_path: Vec<Nibble>,
        child_hash: Multihash,
        path_trie: &PathTrie,
        common_prefix: Vec<Nibble>,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let ext_remaining = &ext_path[common_prefix.len()..];

        let mut branch_children: [Option<Multihash>; 16] = [None; 16];
        let mut branch_value = None;

        if ext_remaining.is_empty() {
            panic!("Extension node cannot have empty remaining path");
        } else if ext_remaining.len() == 1 {
            branch_children[ext_remaining[0] as usize] = Some(child_hash);
        } else {
            let new_ext = Node::Extension {
                path: ext_remaining[1..].to_vec(),
                child: child_hash,
            };
            let new_ext_hash = new_ext.hash::<H>();
            changed_nodes.insert(new_ext_hash, new_ext);
            branch_children[ext_remaining[0] as usize] = Some(new_ext_hash);
        }

        let remaining_trie = path_trie.get_subtrie_after_prefix(&common_prefix);

        if let Some(value) = remaining_trie.get_value_at_empty_path() {
            branch_value = Some(value);
        }

        branch_children
            .iter_mut()
            .enumerate()
            .for_each(|(i, child)| {
                let child_trie = remaining_trie.get_subtrie_for_nibble(i as u8);
                if !child_trie.is_empty() {
                    let child_node = self.create_new_subtree(&child_trie, changed_nodes);
                    let child_hash = child_node.hash::<H>();
                    changed_nodes.insert(child_hash, child_node);
                    *child = Some(child_hash);
                }
            });

        let branch = Node::Branch {
            children: branch_children.into(),
            value: branch_value,
        };

        if common_prefix.is_empty() {
            branch
        } else {
            let branch_hash = branch.hash::<H>();
            changed_nodes.insert(branch_hash, branch.clone());
            Node::Extension {
                path: common_prefix,
                child: branch_hash,
            }
        }
    }

    fn handle_branch_update(
        &self,
        mut children: [Option<Multihash>; 16],
        branch_value: Option<Multihash>,
        path_trie: &PathTrie,
        changed_nodes: &mut HashMap<Multihash, Node>,
    ) -> Node {
        let mut new_value = branch_value;

        if let Some(value) = path_trie.get_value_at_empty_path() {
            new_value = Some(value);
        }

        children.iter_mut().enumerate().for_each(|(i, child)| {
            let child_trie = path_trie.get_subtrie_for_nibble(i as u8);
            if !child_trie.is_empty() {
                let child_hash = child.unwrap_or_else(|| Node::Empty.hash::<H>());
                let new_child = self.apply(&child_hash, &child_trie, changed_nodes);
                let new_child_hash = new_child.hash::<H>();
                changed_nodes.insert(new_child_hash, new_child);
                *child = Some(new_child_hash);
            }
        });

        Node::Branch {
            children: children.into(),
            value: new_value,
        }
    }

    pub fn uncommit_root(&self) -> (Multihash, HashMap<Multihash, Node>) {
        if self.staged.is_empty() {
            return (self.root_hash, HashMap::new());
        }

        let mut changeds = HashMap::new();
        let new_root = self.apply(&self.root_hash, &self.staged, &mut changeds);
        let new_root_hash = new_root.hash::<H>();

        (new_root_hash, changeds)
    }

    pub fn get(&self, key: &[u8]) -> Option<Multihash> {
        let path = bytes_to_nibbles(key);

        if let Some(staged_value) = self.staged.get_value_at_path(&path) {
            return Some(staged_value);
        }

        self.get_from_node(&self.root_hash, &path)
    }

    fn get_from_node(&self, node_hash: &Multihash, path: &[Nibble]) -> Option<Multihash> {
        let node = self.nodes.get(node_hash)?;

        match node {
            Node::Empty => None,
            Node::Leaf {
                path: leaf_path,
                value,
            } => {
                if leaf_path == path {
                    Some(*value)
                } else {
                    None
                }
            }
            Node::Extension {
                path: ext_path,
                child,
            } => {
                if path.starts_with(ext_path) {
                    self.get_from_node(child, &path[ext_path.len()..])
                } else {
                    None
                }
            }
            Node::Branch { children, value } => {
                if path.is_empty() {
                    *value
                } else {
                    let nibble = path[0];
                    if let Some(child_hash) = &children[nibble as usize] {
                        self.get_from_node(child_hash, &path[1..])
                    } else {
                        None
                    }
                }
            }
        }
    }

    pub fn generate_proof(&self, key: &[u8], expected_value: Option<Vec<u8>>) -> Option<Proof> {
        let path = bytes_to_nibbles(key);

        let mut proof_nodes = Vec::new();
        let mut cur_hash = self.root_hash;
        let mut cur_path = path.as_slice();

        loop {
            let node = self.nodes.get(&cur_hash)?;
            proof_nodes.push(node.clone());

            match node {
                Node::Empty => return None,
                Node::Leaf { path, value } => {
                    let Some(expected_value) = expected_value else {
                        if path != cur_path {
                            return Some(Proof::new_non_existence(key.to_vec(), proof_nodes));
                        }
                        return None;
                    };

                    if path != cur_path {
                        return None;
                    }

                    if H::hash(&expected_value) == *value {
                        return Some(Proof::new_existence(
                            key.to_vec(),
                            expected_value,
                            proof_nodes,
                        ));
                    }

                    return None;
                }
                Node::Extension {
                    path: ext_path,
                    child,
                } => {
                    if cur_path.starts_with(ext_path) {
                        cur_path = &cur_path[path.len()..];
                        cur_hash = *child;
                    } else {
                        if expected_value.is_none() {
                            return Some(Proof::new_non_existence(key.to_vec(), proof_nodes));
                        }
                        return None;
                    }
                }
                Node::Branch { children, value } => {
                    if cur_path.is_empty() {
                        if expected_value.is_some() != value.is_some() {
                            return None;
                        }

                        if value.is_some() {
                            return Some(Proof::new_existence(
                                key.to_vec(),
                                expected_value.unwrap(),
                                proof_nodes,
                            ));
                        }

                        return Some(Proof::new_non_existence(key.to_vec(), proof_nodes));
                    }

                    let idx = cur_path[0] as usize;
                    if idx >= 16 {
                        return None;
                    }

                    if let Some(child) = &children[idx] {
                        cur_path = &cur_path[1..];
                        cur_hash = *child;
                    } else {
                        if expected_value.is_none() {
                            return Some(Proof::new_non_existence(key.to_vec(), proof_nodes));
                        }
                        return None;
                    }
                }
            }
        }
    }

    pub fn clear(&mut self) {
        std::mem::take(&mut self.staged);
    }
}

fn bytes_to_nibbles(bytes: &[u8]) -> Path {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        nibbles.push((byte >> 4) & 0xF);
        nibbles.push(byte & 0xF);
    }
    nibbles
}

impl Default for PathTrie {
    fn default() -> Self {
        Self {
            value: None,
            children: HashMap::new(),
            is_single_path: true,
        }
    }
}

impl<H: Hasher> Default for MerklePatriciaTrie<H> {
    fn default() -> Self {
        let root = Node::Empty;
        let root_hash = root.hash::<H>();
        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root);

        Self {
            root_hash,
            staged: PathTrie::default(),
            nodes,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    type TestHasher = Sha256;
    type TestMpt = MerklePatriciaTrie<TestHasher>;

    #[test]
    fn insert_and_get() {
        let mut mpt = TestMpt::new();

        let key = b"test_key";
        let value = b"test_value";

        let value_hash = TestHasher::hash(value);

        mpt.insert_raw(key, value_hash);
        mpt.commit();

        let get_value = mpt.get(key);

        assert_eq!(get_value, Some(value_hash));
    }

    #[test]
    fn generate_proof_and_verify() {
        let mut mpt = TestMpt::new();

        let key = b"test_key";
        let value = b"test_value";

        let value_hash = TestHasher::hash(value);

        mpt.insert_raw(key, value_hash);
        mpt.commit();

        let existence_proof = mpt
            .generate_proof(key, Some(value.to_vec()))
            .expect("Failed to generate existence proof");

        assert!(existence_proof.verify::<TestHasher>(&mpt.root_hash));
    }
}
