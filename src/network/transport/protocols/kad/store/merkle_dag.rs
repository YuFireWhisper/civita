use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

use crate::network::transport::protocols::kad::store::merkle_dag::node::Node;

mod node;

type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Node not found: {0:?}")]
    NodeNotFound([u8; 32]),

    #[error("Circular dependency detected")]
    CircularDependency,
}

pub struct MerkleDag {
    root: [u8; 32],
    target: [u8; 32],
    nodes: HashMap<[u8; 32], Node>,
    changes: HashSet<[u8; 32]>,
}

impl MerkleDag {
    pub fn new(mut root: Node, mut target: Node) -> Self {
        let root_hash = root.hash();
        let target_hash = target.hash();

        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root);
        nodes.insert(target_hash, target);

        MerkleDag {
            root: root_hash,
            target: target_hash,
            nodes,
            changes: HashSet::new(),
        }
    }

    pub fn insert(&mut self, mut node: Node) -> [u8; 32] {
        let hash = node.hash();
        self.nodes.insert(hash, node);
        hash
    }

    pub fn append(&mut self, data: Vec<u8>) -> [u8; 32] {
        let mut node = Node::new(data, self.target);
        let hash = node.hash();

        self.nodes.insert(hash, node);

        if let Some(target_node) = self.nodes.get_mut(&self.target) {
            target_node.add_link(hash);
            self.changes.insert(self.target);
        }

        hash
    }

    pub fn update(&mut self, old_hash: [u8; 32], new_data: Vec<u8>) -> Result<[u8; 32]> {
        let node = self
            .nodes
            .get_mut(&old_hash)
            .ok_or(Error::NodeNotFound(old_hash))?;

        node.set_data(new_data);
        let parent = node.parent();
        self.changes.insert(old_hash);

        if parent != [0u8; 32] {
            self.changes.insert(parent);
        }

        Ok(old_hash)
    }

    pub fn commit(&mut self) -> Result<()> {
        if self.changes.is_empty() {
            return Ok(());
        }

        let sorted_nodes = self.collect_affected_nodes()?;
        let mut hash_updates = HashMap::new();

        for hash in sorted_nodes {
            if let Some(node) = self.nodes.get(&hash).cloned() {
                let mut updated_node = node;

                for (old_hash, new_hash) in &hash_updates {
                    updated_node.change_link(*old_hash, *new_hash);
                }

                self.nodes.remove(&hash);

                let new_hash = updated_node.hash();
                self.nodes.insert(new_hash, updated_node);

                if new_hash != hash {
                    hash_updates.insert(hash, new_hash);

                    if self.root == hash {
                        self.root = new_hash;
                    }
                    if self.target == hash {
                        self.target = new_hash;
                    }
                }
            }
        }

        self.changes.clear();
        Ok(())
    }

    fn collect_affected_nodes(&self) -> Result<Vec<[u8; 32]>> {
        let mut affected_nodes = HashSet::new();
        let mut to_visit = VecDeque::new();

        for &changed in &self.changes {
            to_visit.push_back(changed);
            affected_nodes.insert(changed);
        }

        while let Some(hash) = to_visit.pop_front() {
            let node = self.nodes.get(&hash).ok_or(Error::NodeNotFound(hash))?;

            let parent = node.parent();
            if parent != [0u8; 32] && !affected_nodes.contains(&parent) {
                affected_nodes.insert(parent);
                to_visit.push_back(parent);
            }
        }

        self.topological_sort(affected_nodes)
    }

    fn topological_sort(&self, nodes: HashSet<[u8; 32]>) -> Result<Vec<[u8; 32]>> {
        let mut result = Vec::with_capacity(nodes.len());
        let mut in_degree: HashMap<[u8; 32], usize> = HashMap::new();
        let mut graph: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        if self.has_links_cycle(&nodes) {
            return Err(Error::CircularDependency);
        }

        for &hash in &nodes {
            if let Some(node) = self.nodes.get(&hash) {
                let parent = node.parent();
                if parent != [0u8; 32] && nodes.contains(&parent) {
                    graph.entry(hash).or_default().push(parent);
                    *in_degree.entry(parent).or_insert(0) += 1;
                }
            }
        }

        let mut queue: VecDeque<[u8; 32]> = nodes
            .iter()
            .filter(|&&hash| !in_degree.contains_key(&hash))
            .copied()
            .collect();

        while let Some(hash) = queue.pop_front() {
            result.push(hash);

            if let Some(children) = graph.get(&hash) {
                for &child in children {
                    if let Some(degree) = in_degree.get_mut(&child) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(child);
                        }
                    }
                }
            }
        }

        if result.len() != nodes.len() {
            return Err(Error::CircularDependency);
        }

        Ok(result)
    }

    fn has_links_cycle(&self, nodes: &HashSet<[u8; 32]>) -> bool {
        let mut graph: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for &hash in nodes {
            if let Some(node) = self.nodes.get(&hash) {
                for &link in node.links() {
                    if nodes.contains(&link) {
                        graph.entry(hash).or_default().push(link);
                    }
                }
            }
        }

        let mut visited = HashSet::new();
        let mut in_current_path = HashSet::new();

        for &start in nodes {
            if !visited.contains(&start)
                && Self::dfs_check_cycle(start, &graph, &mut visited, &mut in_current_path)
            {
                return true;
            }
        }

        false
    }

    fn dfs_check_cycle(
        node: [u8; 32],
        graph: &HashMap<[u8; 32], Vec<[u8; 32]>>,
        visited: &mut HashSet<[u8; 32]>,
        in_current_path: &mut HashSet<[u8; 32]>,
    ) -> bool {
        visited.insert(node);
        in_current_path.insert(node);

        if let Some(neighbors) = graph.get(&node) {
            for &neighbor in neighbors {
                if in_current_path.contains(&neighbor) {
                    return true;
                }

                if !visited.contains(&neighbor)
                    && Self::dfs_check_cycle(neighbor, graph, visited, in_current_path)
                {
                    return true;
                }
            }
        }

        in_current_path.remove(&node);
        false
    }

    pub fn get_node(&self, hash: &[u8; 32]) -> Option<&Node> {
        self.nodes.get(hash)
    }

    pub fn root_hash(&self) -> [u8; 32] {
        self.root
    }

    pub fn target_hash(&self) -> [u8; 32] {
        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_node(data: &[u8], parent: [u8; 32]) -> Node {
        Node::new(data.to_vec(), parent)
    }

    fn create_empty_dag() -> MerkleDag {
        let root_node = create_node(b"root", [0u8; 32]);
        let target_node = create_node(b"target", [0u8; 32]);
        MerkleDag::new(root_node, target_node)
    }

    #[test]
    fn new_creates_dag_with_root_and_target() {
        let mut root_node = create_node(b"root", [0u8; 32]);
        let root_hash = root_node.hash();
        let mut target_node = create_node(b"target", [0u8; 32]);
        let target_hash = target_node.hash();

        let dag = MerkleDag::new(root_node, target_node);

        assert_eq!(dag.root_hash(), root_hash);
        assert_eq!(dag.target_hash(), target_hash);
        assert!(dag.get_node(&root_hash).is_some());
        assert!(dag.get_node(&target_hash).is_some());
    }

    #[test]
    fn insert_adds_node_to_dag() {
        let mut dag = create_empty_dag();
        let mut new_node = create_node(b"new_node", [0u8; 32]);
        let expected_hash = new_node.hash();

        let actual_hash = dag.insert(new_node);

        assert_eq!(actual_hash, expected_hash);
        assert!(dag.get_node(&expected_hash).is_some());
        assert_eq!(dag.get_node(&expected_hash).unwrap().data(), b"new_node");
    }

    #[test]
    fn append_links_node_to_target() {
        let mut dag = create_empty_dag();
        let target_hash = dag.target_hash();

        let new_hash = dag.append(b"appended".to_vec());

        let new_node = dag.get_node(&new_hash).unwrap();
        assert_eq!(new_node.data(), b"appended");
        assert_eq!(new_node.parent(), target_hash);

        let target_node = dag.get_node(&target_hash).unwrap();
        assert!(target_node.links().contains(&new_hash));
    }

    #[test]
    fn update_modifies_node_data() {
        let mut dag = create_empty_dag();
        let target_hash = dag.target_hash();

        let result = dag.update(target_hash, b"updated_target".to_vec());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target_hash);
        assert_eq!(
            dag.get_node(&target_hash).unwrap().data(),
            b"updated_target"
        );
        assert!(dag.changes.contains(&target_hash));
    }

    #[test]
    fn when_updating_nonexistent_node_returns_error() {
        let mut dag = create_empty_dag();
        let invalid_hash = [42u8; 32];

        let result = dag.update(invalid_hash, b"new_data".to_vec());

        assert!(result.is_err());
        if let Err(Error::NodeNotFound(hash)) = result {
            assert_eq!(hash, invalid_hash);
        } else {
            panic!("Expected NodeNotFound error");
        }
    }

    #[test]
    fn commit_updates_node_hashes() {
        let mut dag = create_empty_dag();
        let original_target_hash = dag.target_hash();

        dag.update(original_target_hash, b"modified".to_vec())
            .unwrap();

        dag.commit().unwrap();

        let new_target_hash = dag.target_hash();
        assert_ne!(new_target_hash, original_target_hash);
        assert!(dag.changes.is_empty());
        assert_eq!(dag.get_node(&new_target_hash).unwrap().data(), b"modified");
    }

    #[test]
    fn commit_with_no_changes_succeeds() {
        let mut dag = create_empty_dag();
        let root_hash = dag.root_hash();
        let target_hash = dag.target_hash();

        let result = dag.commit();

        assert!(result.is_ok());
        assert_eq!(dag.root_hash(), root_hash);
        assert_eq!(dag.target_hash(), target_hash);
    }

    #[test]
    fn should_propagate_hash_changes_to_parents() {
        let mut dag = create_empty_dag();
        let original_root_hash = dag.root_hash();
        let original_target_hash = dag.target_hash();

        if let Some(root_node) = dag.nodes.get_mut(&original_root_hash) {
            root_node.add_link(original_target_hash);
            dag.changes.insert(original_root_hash);
        }

        dag.update(original_target_hash, b"modified".to_vec())
            .unwrap();

        dag.commit().unwrap();

        assert_ne!(dag.target_hash(), original_target_hash);
        assert_ne!(dag.root_hash(), original_root_hash);
    }

    #[test]
    fn when_circular_dependency_exists_commit_returns_error() {
        let mut dag = create_empty_dag();
        let root_hash = dag.root_hash();
        let target_hash = dag.target_hash();

        if let Some(root_node) = dag.nodes.get_mut(&root_hash) {
            root_node.add_link(target_hash);
            dag.changes.insert(root_hash);
        }

        if let Some(target_node) = dag.nodes.get_mut(&target_hash) {
            target_node.add_link(root_hash);
            dag.changes.insert(target_hash);
        }

        let result = dag.commit();

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::CircularDependency)));
    }

    #[test]
    fn hash_changes_propagate_correctly_in_chain() {
        let mut dag = create_empty_dag();

        let a_hash = dag.root_hash();
        let b_node = create_node(b"B", a_hash);
        let b_hash = dag.insert(b_node);

        let c_node = create_node(b"C", b_hash);
        let c_hash = dag.insert(c_node);

        let d_node = create_node(b"D", c_hash);
        let d_hash = dag.insert(d_node);

        if let Some(a_node) = dag.nodes.get_mut(&a_hash) {
            a_node.add_link(b_hash);
            dag.changes.insert(a_hash);
        }

        if let Some(b_node) = dag.nodes.get_mut(&b_hash) {
            b_node.add_link(c_hash);
            dag.changes.insert(b_hash);
        }

        if let Some(c_node) = dag.nodes.get_mut(&c_hash) {
            c_node.add_link(d_hash);
            dag.changes.insert(c_hash);
        }

        let old_hashes = [a_hash, b_hash, c_hash, d_hash];

        dag.update(d_hash, b"updated D".to_vec()).unwrap();
        dag.commit().unwrap();

        let new_a_hash = dag.root_hash();
        assert_ne!(
            new_a_hash, old_hashes[0],
            "Root hash should change after commit"
        );

        let new_a = dag.get_node(&new_a_hash).unwrap();
        let new_b_hash = *new_a.links().iter().next().unwrap();
        assert_ne!(
            new_b_hash, old_hashes[1],
            "B hash should change after commit"
        );

        let new_b = dag.get_node(&new_b_hash).unwrap();
        let new_c_hash = *new_b.links().iter().next().unwrap();
        assert_ne!(
            new_c_hash, old_hashes[2],
            "C hash should change after commit"
        );

        let new_c = dag.get_node(&new_c_hash).unwrap();
        let new_d_hash = *new_c.links().iter().next().unwrap();
        assert_ne!(
            new_d_hash, old_hashes[3],
            "D hash should change after commit"
        );

        assert_eq!(dag.get_node(&new_d_hash).unwrap().data(), b"updated D");
    }

    #[test]
    fn complex_dag_updates_propagate_correctly() {
        // A -> B -> D
        // |    |    ^
        // v    v    |
        // C -> E ---+
        let mut dag = create_empty_dag();

        let a_hash = dag.root_hash();
        let b_node = create_node(b"B", a_hash);
        let b_hash = dag.insert(b_node);

        let c_node = create_node(b"C", a_hash);
        let c_hash = dag.insert(c_node);

        let d_node = create_node(b"D", b_hash);
        let d_hash = dag.insert(d_node);

        let e_node = create_node(b"E", c_hash);
        let e_hash = dag.insert(e_node);

        if let Some(a_node) = dag.nodes.get_mut(&a_hash) {
            a_node.add_link(b_hash);
            a_node.add_link(c_hash);
            dag.changes.insert(a_hash);
        }

        if let Some(b_node) = dag.nodes.get_mut(&b_hash) {
            b_node.add_link(d_hash);
            b_node.add_link(e_hash);
            dag.changes.insert(b_hash);
        }

        if let Some(c_node) = dag.nodes.get_mut(&c_hash) {
            c_node.add_link(e_hash);
            dag.changes.insert(c_hash);
        }

        if let Some(e_node) = dag.nodes.get_mut(&e_hash) {
            e_node.add_link(d_hash);
            dag.changes.insert(e_hash);
        }

        let old_a = a_hash;
        let old_b = b_hash;
        let old_c = c_hash;
        let old_d = d_hash;
        let old_e = e_hash;

        dag.update(d_hash, b"modified D".to_vec()).unwrap();
        dag.commit().unwrap();

        let new_a = dag.root_hash();
        assert_ne!(new_a, old_a, "Root A hash should change");

        let all_nodes: Vec<_> = dag.nodes.keys().cloned().collect();
        assert!(!all_nodes.contains(&old_a), "Old A hash should be gone");
        assert!(!all_nodes.contains(&old_b), "Old B hash should be gone");
        assert!(!all_nodes.contains(&old_c), "Old C hash should be gone");
        assert!(!all_nodes.contains(&old_d), "Old D hash should be gone");
        assert!(!all_nodes.contains(&old_e), "Old E hash should be gone");
    }

    #[test]
    fn update_multiple_nodes_before_commit_tracks_all_changes() {
        let mut dag = create_empty_dag();
        let root_hash = dag.root_hash();
        let target_hash = dag.target_hash();

        dag.update(root_hash, b"new root".to_vec()).unwrap();
        dag.update(target_hash, b"new target".to_vec()).unwrap();

        assert!(dag.changes.contains(&root_hash));
        assert!(dag.changes.contains(&target_hash));

        assert_eq!(dag.root_hash(), root_hash);
        assert_eq!(dag.target_hash(), target_hash);

        dag.commit().unwrap();

        assert_ne!(dag.root_hash(), root_hash);
        assert_ne!(dag.target_hash(), target_hash);
    }
}
