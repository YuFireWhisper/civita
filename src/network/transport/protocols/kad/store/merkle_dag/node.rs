use std::{collections::HashSet, sync::OnceLock};

#[derive(Debug, Clone)]
pub struct Node {
    data: Vec<u8>,
    links: HashSet<[u8; 32]>,
    parent: [u8; 32],
    hash_cache: OnceLock<[u8; 32]>,
}

impl Node {
    pub fn new(data: Vec<u8>, parent: [u8; 32]) -> Self {
        Node {
            data,
            links: HashSet::new(),
            parent,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn add_link(&mut self, link: [u8; 32]) -> bool {
        let changed = self.links.insert(link);
        if changed {
            self.invalidate_hash();
        }
        changed
    }

    fn invalidate_hash(&mut self) {
        self.hash_cache = OnceLock::new();
    }

    pub fn remove_link(&mut self, link: &[u8; 32]) -> bool {
        let changed = self.links.remove(link);
        if changed {
            self.invalidate_hash();
        }
        changed
    }

    pub fn change_link(&mut self, old_link: [u8; 32], new_link: [u8; 32]) -> bool {
        if old_link == new_link {
            return false;
        }

        let changed = self.remove_link(&old_link) && self.add_link(new_link);
        if changed {
            self.invalidate_hash();
        }
        changed
    }

    pub fn hash(&self) -> [u8; 32] {
        *self.hash_cache.get_or_init(|| {
            let mut hasher = blake3::Hasher::new();

            hasher.update(&self.data);

            let mut sorted_links: Vec<&[u8; 32]> = self.links.iter().collect();
            sorted_links.sort_unstable();

            for link in sorted_links {
                hasher.update(link);
            }

            hasher.finalize().into()
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn links(&self) -> &HashSet<[u8; 32]> {
        &self.links
    }

    pub fn parent(&self) -> [u8; 32] {
        self.parent
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
        self.invalidate_hash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARENT_HASH: [u8; 32] = [1; 32];
    const TEST_LINK1: [u8; 32] = [2; 32];
    const TEST_LINK2: [u8; 32] = [3; 32];

    fn create_test_node() -> Node {
        Node::new(vec![1, 2, 3], TEST_PARENT_HASH)
    }

    #[test]
    fn new_creates_node_with_correct_initial_state() {
        let data = vec![1, 2, 3];
        let node = Node::new(data.clone(), TEST_PARENT_HASH);

        assert_eq!(node.data(), &data);
        assert_eq!(node.parent(), TEST_PARENT_HASH);
        assert!(node.links().is_empty());
        assert!(node.hash_cache.get().is_none());
    }

    #[test]
    fn add_link_when_new_returns_true() {
        let mut node = create_test_node();

        let result = node.add_link(TEST_LINK1);

        assert!(result);
        assert!(node.links().contains(&TEST_LINK1));
        assert!(node.hash_cache.get().is_none());
    }

    #[test]
    fn add_link_when_duplicate_returns_false() {
        let mut node = create_test_node();
        node.add_link(TEST_LINK1);

        let result = node.add_link(TEST_LINK1);

        assert!(!result);
        assert_eq!(node.links().len(), 1);
    }

    #[test]
    fn remove_link_when_exists_returns_true() {
        let mut node = create_test_node();
        node.add_link(TEST_LINK1);
        node.hash();

        let result = node.remove_link(&TEST_LINK1);

        assert!(result);
        assert!(node.links().is_empty());
        assert!(node.hash_cache.get().is_none());
    }

    #[test]
    fn remove_link_when_not_exists_returns_false() {
        let mut node = create_test_node();
        let hash_before = node.hash();

        let result = node.remove_link(&TEST_LINK1);

        assert!(!result);
        assert_eq!(node.hash(), hash_before);
    }

    #[test]
    fn change_link_should_update_links_when_old_exists() {
        let mut node = create_test_node();
        node.add_link(TEST_LINK1);

        let result = node.change_link(TEST_LINK1, TEST_LINK2);

        assert!(result);
        assert!(!node.links().contains(&TEST_LINK1));
        assert!(node.links().contains(&TEST_LINK2));
        assert!(node.hash_cache.get().is_none());
    }

    #[test]
    fn change_link_should_return_false_when_old_not_exists() {
        let mut node = create_test_node();

        let result = node.change_link(TEST_LINK1, TEST_LINK2);

        assert!(!result);
        assert!(!node.links().contains(&TEST_LINK1));
        assert!(!node.links().contains(&TEST_LINK2));
    }

    #[test]
    fn change_link_when_same_returns_false() {
        let mut node = create_test_node();
        node.add_link(TEST_LINK1);
        node.hash();

        let result = node.change_link(TEST_LINK1, TEST_LINK1);

        assert!(!result);
        assert!(node.hash_cache.get().is_some());
    }

    #[test]
    fn hash_calculation_should_be_deterministic() {
        let mut node1 = create_test_node();
        node1.add_link(TEST_LINK1);
        node1.add_link(TEST_LINK2);

        let hash1 = node1.hash();
        let hash2 = node1.hash();

        assert_eq!(hash1, hash2);

        let mut node2 = create_test_node();
        node2.add_link(TEST_LINK2);
        node2.add_link(TEST_LINK1);

        assert_eq!(node1.hash(), node2.hash());
    }

    #[test]
    fn hash_should_cache_result() {
        let node = create_test_node();

        let hash1 = node.hash();
        assert!(node.hash_cache.get().is_some());

        let hash2 = node.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn set_data_should_update_and_invalidate_hash() {
        let mut node = create_test_node();
        let original_hash = node.hash();

        let new_data = vec![4, 5, 6];
        node.set_data(new_data.clone());

        assert_eq!(node.data(), &new_data);
        assert!(node.hash_cache.get().is_none());
        assert_ne!(node.hash(), original_hash);
    }

    #[test]
    fn invalidate_hash_should_clear_hash_cache() {
        let mut node = create_test_node();
        node.hash();

        node.invalidate_hash();

        assert!(node.hash_cache.get().is_none());
    }

    #[test]
    fn links_getter_returns_correct_reference() {
        let mut node = create_test_node();
        node.add_link(TEST_LINK1);
        node.add_link(TEST_LINK2);

        let links = node.links();

        assert_eq!(links.len(), 2);
        assert!(links.contains(&TEST_LINK1));
        assert!(links.contains(&TEST_LINK2));
    }

    #[test]
    fn parent_getter_returns_correct_value() {
        let node = create_test_node();

        assert_eq!(node.parent(), TEST_PARENT_HASH);
    }
}

