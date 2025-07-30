use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use derivative::Derivative;

pub trait Node {
    type Id: Clone + Eq + Hash + Debug;

    fn id(&self) -> Self::Id;
    fn validate(&self) -> bool;
    fn on_parent_valid(&self, child: &Self) -> bool;
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derivative(Debug(bound = "N::Id: Debug"))]
pub struct ValidationResult<N: Node> {
    pub validated: Vec<N::Id>,
    pub invalidated: Vec<N::Id>,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
enum State {
    Valid,
    Invalid,
    Pending,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "N: Clone"))]
struct Entry<N: Node> {
    node: Option<N>,
    state: State,
    parents: HashSet<usize>,
    children: HashSet<usize>,
    pending: usize,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derivative(Clone(bound = "N: Clone"))]
pub struct Dag<N: Node> {
    index: HashMap<N::Id, usize>,
    entries: Vec<Entry<N>>,
}

impl State {
    pub fn is_valid(&self) -> bool {
        matches!(self, State::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, State::Invalid)
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, State::Pending)
    }
}

impl<N: Node> ValidationResult<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_invalidated(id: N::Id) -> Self {
        let mut result = Self::default();
        result.add_invalidated(id);
        result
    }

    pub fn add_validated(&mut self, id: N::Id) {
        self.validated.push(id);
    }

    pub fn add_invalidated(&mut self, id: N::Id) {
        self.invalidated.push(id);
    }
}

impl<N: Node> Entry<N> {
    fn new(node: N) -> Self {
        Self {
            node: Some(node),
            state: State::Pending,
            parents: HashSet::new(),
            children: HashSet::new(),
            pending: 0,
        }
    }

    pub fn new_placeholder() -> Self {
        Self {
            node: None,
            state: State::Pending,
            parents: HashSet::new(),
            children: HashSet::new(),
            pending: 0,
        }
    }

    pub fn id(&self) -> N::Id {
        self.node.as_ref().expect("Node should be present").id()
    }

    pub fn is_valid(&self) -> bool {
        self.state.is_valid()
    }

    pub fn is_invalid(&self) -> bool {
        self.state.is_invalid()
    }

    pub fn on_parent_valid(&self, parent: &N) -> bool {
        self.node.as_ref().unwrap().on_parent_valid(parent)
    }

    pub fn validate(&self) -> bool {
        self.node.as_ref().unwrap().validate()
    }
}

impl<N: Node> Dag<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(node: N) -> Self {
        let mut dag = Self::default();
        dag.upsert(node, vec![]);
        dag
    }

    pub fn upsert<I>(&mut self, node: N, parents: I) -> ValidationResult<N>
    where
        I: IntoIterator<Item = N::Id>,
    {
        let mut result = ValidationResult::new();
        let id = node.id();

        if self
            .index
            .get(&id)
            .is_some_and(|&idx| self.entries[idx].node.is_some())
        {
            return result; // Node already exists, no need to revalidate
        }

        let idx = self.create_entry(node);

        if !self.establish_relationships(idx, parents, &mut result) {
            return result;
        }

        if self.entries[idx].pending == 0 {
            self.validate_from(idx, &mut result);
        }

        result
    }

    fn create_entry(&mut self, node: N) -> usize {
        if let Some(&idx) = self.index.get(&node.id()) {
            self.entries[idx].node = Some(node);
            idx
        } else {
            let idx = self.entries.len();
            self.index.insert(node.id(), idx);
            self.entries.push(Entry::new(node));
            idx
        }
    }

    fn establish_relationships<I>(
        &mut self,
        idx: usize,
        parents: I,
        result: &mut ValidationResult<N>,
    ) -> bool
    where
        I: IntoIterator<Item = N::Id>,
    {
        for pid in parents {
            let Some(&pidx) = self.index.get(&pid) else {
                let placeholder_idx = self.create_placeholder(&pid);
                self.link_parent_child(idx, placeholder_idx, true);
                continue;
            };

            if self.entries[pidx].is_invalid() || self.detect_cycle(pidx, idx) {
                self.invalidate_subtree(idx, result);
                return false;
            }

            self.link_parent_child(idx, pidx, false);

            if self.entries[pidx].state.is_pending() {
                self.entries[idx].pending += 1;
            } else {
                // Parent is valid
                if !self.entries[idx].on_parent_valid(self.entries[pidx].node.as_ref().unwrap()) {
                    self.invalidate_subtree(idx, result);
                    return false;
                }
            }
        }

        true
    }

    fn link_parent_child(&mut self, child_idx: usize, parent_idx: usize, increment_pending: bool) {
        self.entries[child_idx].parents.insert(parent_idx);
        self.entries[parent_idx].children.insert(child_idx);
        if increment_pending {
            self.entries[child_idx].pending += 1;
        }
    }

    fn invalidate_subtree(&mut self, idx: usize, result: &mut ValidationResult<N>) {
        let mut stk = vec![idx];
        while let Some(u) = stk.pop() {
            let entry = &mut self.entries[u];
            if !entry.is_invalid() {
                entry.state = State::Invalid;
                result.add_invalidated(entry.id());
                entry.children.iter().for_each(|&c| {
                    stk.push(c);
                });
            }
        }
    }

    fn create_placeholder(&mut self, id: &N::Id) -> usize {
        let idx = self.entries.len();
        self.entries.push(Entry::new_placeholder());
        self.index.insert(id.clone(), idx);
        idx
    }

    fn detect_cycle(&self, start: usize, target: usize) -> bool {
        let mut stack = vec![start];
        let mut visited = vec![false; self.entries.len()];

        while let Some(u) = stack.pop() {
            if u == target {
                return true;
            }
            if visited[u] {
                continue;
            }
            visited[u] = true;
            stack.extend(&self.entries[u].children);
        }

        false
    }

    fn validate_from(&mut self, root: usize, result: &mut ValidationResult<N>) {
        let mut stk = vec![root];
        while let Some(u) = stk.pop() {
            if self.entries[u].is_valid() {
                continue;
            }

            if self.validate_node(u, result) {
                self.entries[u].children.clone().iter().for_each(|&cidx| {
                    self.entries[cidx].pending = self.entries[cidx].pending.saturating_sub(1);
                    if self.entries[cidx].pending == 0 {
                        stk.push(cidx);
                    }
                });
            } else {
                self.invalidate_subtree(u, result);
            }
        }
    }

    fn validate_node(&mut self, idx: usize, result: &mut ValidationResult<N>) -> bool {
        let valid = self.entries[idx].validate();

        self.entries[idx].state = if valid { State::Valid } else { State::Invalid };

        let id = self.entries[idx].id();

        if valid {
            result.add_validated(id);
        } else {
            result.add_invalidated(id);
        }

        valid
    }

    pub fn remove(&mut self, id: &N::Id) -> Option<N> {
        let &idx = self.index.get(id)?;
        let entry = self.entries.swap_remove(idx);

        self.index.remove(id);

        if idx < self.entries.len() {
            let moved_id = self.entries[idx].id();
            self.index.insert(moved_id, idx);
        }

        entry.parents.iter().for_each(|&parent_idx| {
            self.entries[parent_idx].children.remove(&idx);
        });

        entry.children.iter().for_each(|&child_idx| {
            self.entries[child_idx].parents.remove(&idx);
        });

        entry.node
    }

    pub fn get(&self, id: &N::Id) -> Option<&N> {
        self.index
            .get(id)
            .and_then(|&idx| self.entries[idx].node.as_ref())
    }

    pub fn contains(&self, id: &N::Id) -> bool {
        self.index
            .get(id)
            .is_some_and(|&idx| self.entries[idx].node.is_some())
    }

    pub fn get_leaf_nodes(&self, root_id: &N::Id) -> Option<Vec<N::Id>> {
        let start = *self.index.get(root_id)?;
        let mut leaves = Vec::new();
        let mut stk = vec![start];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            visited.insert(u);

            if !self.entries[u].is_valid() {
                continue;
            }

            let mut is_leaf = true;

            self.entries[u]
                .children
                .iter()
                .filter(|&&c| self.entries[c].is_valid() && !visited.contains(&c))
                .for_each(|&cidx| {
                    is_leaf = false;
                    stk.push(cidx);
                });

            if is_leaf && u != start {
                leaves.push(self.entries[u].id());
            }
        }

        Some(leaves)
    }

    pub fn retain(&mut self, id: &N::Id) -> Vec<N> {
        let Some(&start_idx) = self.index.get(id) else {
            return Vec::new();
        };

        let mut to_retain = HashSet::new();
        let mut stack = vec![start_idx];

        while let Some(u) = stack.pop() {
            if to_retain.insert(u) {
                self.entries[u].parents.iter().for_each(|&p| {
                    stack.push(p);
                });
            }
        }

        let mut removed_nodes = Vec::new();
        let mut indices_to_remove = Vec::new();

        self.entries.iter().enumerate().for_each(|(idx, entry)| {
            if !to_retain.contains(&idx) && entry.node.is_some() {
                indices_to_remove.push(idx);
            }
        });

        indices_to_remove.sort_by(|a, b| b.cmp(a));

        indices_to_remove.iter().for_each(|&idx| {
            if let Some(node) = self.remove(&self.entries[idx].id()) {
                removed_nodes.push(node);
            }
        });

        removed_nodes
    }

    pub fn get_children(&self, id: &N::Id) -> Option<Vec<N::Id>> {
        let &idx = self.index.get(id)?;
        let children_ids = self.entries[idx]
            .children
            .iter()
            .filter_map(|&cidx| self.entries[cidx].node.as_ref().map(|n| n.id()))
            .collect();
        Some(children_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, sync::Arc};

    const VALID_NODE_ID: u32 = 1;
    const INVALID_NODE_ID: u32 = 2;
    const ROOT_NODE_ID: u32 = 0;

    struct TestNode {
        id: u32,
        should_validate: bool,
        parent_validation_logic: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    }

    impl TestNode {
        fn new(id: u32) -> Self {
            Self {
                id,
                should_validate: true,
                parent_validation_logic: None,
            }
        }

        fn new_invalid(id: u32) -> Self {
            Self {
                id,
                should_validate: false,
                parent_validation_logic: None,
            }
        }

        fn with_parent_logic<F>(id: u32, logic: F) -> Self
        where
            F: Fn(u32) -> bool + 'static + Send + Sync,
        {
            Self {
                id,
                should_validate: true,
                parent_validation_logic: Some(Arc::new(logic)),
            }
        }
    }

    impl Node for TestNode {
        type Id = u32;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn validate(&self) -> bool {
            self.should_validate
        }

        fn on_parent_valid(&self, parent: &Self) -> bool {
            if let Some(ref logic) = self.parent_validation_logic {
                logic(parent.id())
            } else {
                true
            }
        }
    }

    fn create_basic_dag() -> Dag<TestNode> {
        Dag::with_root(TestNode::new(ROOT_NODE_ID))
    }

    fn assert_validation_result(
        result: &ValidationResult<TestNode>,
        expected_validated: &[u32],
        expected_invalidated: &[u32],
    ) {
        let validated_set: HashSet<_> = result.validated.iter().collect();
        let invalidated_set: HashSet<_> = result.invalidated.iter().collect();
        let expected_validated_set: HashSet<_> = expected_validated.iter().collect();
        let expected_invalidated_set: HashSet<_> = expected_invalidated.iter().collect();

        assert_eq!(
            validated_set, expected_validated_set,
            "Validated nodes mismatch. Expected: {:?}, Got: {:?}",
            expected_validated, result.validated
        );
        assert_eq!(
            invalidated_set, expected_invalidated_set,
            "Invalidated nodes mismatch. Expected: {:?}, Got: {:?}",
            expected_invalidated, result.invalidated
        );
    }

    #[test]
    fn validation_result_creation() {
        let result = ValidationResult::<TestNode>::new();
        assert!(result.validated.is_empty());
        assert!(result.invalidated.is_empty());
    }

    #[test]
    fn validation_result_add_operations() {
        let mut result = ValidationResult::<TestNode>::new();

        result.add_validated(VALID_NODE_ID);
        result.add_invalidated(INVALID_NODE_ID);

        assert_eq!(result.validated, vec![VALID_NODE_ID]);
        assert_eq!(result.invalidated, vec![INVALID_NODE_ID]);
    }

    #[test]
    fn empty_dag_creation() {
        let dag = Dag::<TestNode>::new();
        assert!(dag.index.is_empty());
        assert!(dag.entries.is_empty());
    }

    #[test]
    fn dag_with_root_creation() {
        let dag = create_basic_dag();
        assert_eq!(dag.index.len(), 1);
        assert_eq!(dag.entries.len(), 1);
        assert_eq!(dag.entries[0].pending, 0);
        assert!(dag.entries[0].children.is_empty());
    }

    #[test]
    fn upsert_single_child() {
        let mut dag = create_basic_dag();

        let res = dag.upsert(TestNode::new(VALID_NODE_ID), vec![ROOT_NODE_ID]);

        assert_validation_result(&res, &[VALID_NODE_ID], &[]);
    }

    #[test]
    fn upsert_duplicate_node() {
        let mut dag = create_basic_dag();

        dag.upsert(TestNode::new(VALID_NODE_ID), vec![ROOT_NODE_ID]);
        let res = dag.upsert(TestNode::new(VALID_NODE_ID), vec![ROOT_NODE_ID]);

        assert_validation_result(&res, &[], &[]);
    }

    #[test]
    fn upsert_with_nonexistent_parent() {
        let mut dag = create_basic_dag();
        let result = dag.upsert(TestNode::new(VALID_NODE_ID), vec![999]);

        assert_validation_result(&result, &[], &[]);
    }

    #[test]
    fn upsert_multiple_parents() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);

        let result = dag.upsert(TestNode::new(3), vec![1, 2]);

        assert_validation_result(&result, &[3], &[]);
    }

    #[test]
    fn upsert_invalid_node() {
        let mut dag = create_basic_dag();

        let res = dag.upsert(TestNode::new_invalid(INVALID_NODE_ID), vec![ROOT_NODE_ID]);

        assert_validation_result(&res, &[], &[INVALID_NODE_ID]);
    }

    #[test]
    fn parent_validation_rejection() {
        let mut dag = create_basic_dag();
        let node = TestNode::with_parent_logic(VALID_NODE_ID, |_| false);

        let res = dag.upsert(node, vec![ROOT_NODE_ID]);

        assert_validation_result(&res, &[], &[VALID_NODE_ID]);
    }

    #[test]
    fn parent_validation_acceptance() {
        let mut dag = create_basic_dag();
        let node =
            TestNode::with_parent_logic(VALID_NODE_ID, |parent_id| parent_id == ROOT_NODE_ID);

        let res = dag.upsert(node, vec![ROOT_NODE_ID]);

        assert_validation_result(&res, &[VALID_NODE_ID], &[]);
    }

    #[test]
    fn invalidation_cascades_to_children() {
        let mut dag = create_basic_dag();

        dag.upsert(TestNode::new_invalid(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![1]);

        let result = dag.upsert(TestNode::new(3), vec![2]);

        assert_validation_result(&result, &[], &[3]);
    }

    #[test]
    fn parent_rejection_cascades() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![1]);

        let rejecting_node = TestNode::with_parent_logic(3, |_| false);
        let result = dag.upsert(rejecting_node, vec![1]);

        assert_validation_result(&result, &[], &[3]);
    }

    #[test]
    fn cycle_detection_direct() {
        let mut dag = Dag::new();
        dag.upsert(TestNode::new(1), vec![]);
        dag.upsert(TestNode::new(2), vec![1]);

        let result = dag.upsert(TestNode::new(1), vec![2]);

        assert_validation_result(&result, &[], &[]);
    }

    #[test]
    fn cycle_detection_indirect() {
        let mut dag = Dag::new();
        dag.upsert(TestNode::new(1), vec![]);
        dag.upsert(TestNode::new(2), vec![1]);
        dag.upsert(TestNode::new(3), vec![2]);

        let result = dag.upsert(TestNode::new(1), vec![3]);

        assert_validation_result(&result, &[], &[]);
    }

    #[test]
    fn no_false_cycle_detection() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);

        let result = dag.upsert(TestNode::new(3), vec![1, 2]);

        assert_validation_result(&result, &[3], &[]);
    }

    #[test]
    fn pending_validation_resolution() {
        let mut dag = create_basic_dag();

        let res1 = dag.upsert(TestNode::new(2), vec![1]);
        let res2 = dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);

        assert_validation_result(&res1, &[], &[]);
        assert_validation_result(&res2, &[1, 2], &[]);
    }

    #[test]
    fn multiple_pending_parents() {
        let mut dag = create_basic_dag();

        let res3 = dag.upsert(TestNode::new(3), vec![1, 2]);
        let res1 = dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        let res2 = dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);

        assert_validation_result(&res3, &[], &[]);
        assert_validation_result(&res1, &[1], &[]);
        assert_validation_result(&res2, &[2, 3], &[]);
    }

    #[test]
    fn get_existing_node() {
        let dag = create_basic_dag();
        let node = dag.get(&ROOT_NODE_ID);

        assert!(node.is_some());
        assert_eq!(node.unwrap().id(), ROOT_NODE_ID);
    }

    #[test]
    fn get_nonexistent_node() {
        let dag = create_basic_dag();
        let node = dag.get(&999);
        assert!(node.is_none());
    }

    #[test]
    fn invalidation_with_complex_dependencies() {
        let mut dag = create_basic_dag();

        let invalid_node = TestNode::with_parent_logic(5, |_| false);

        let res1 = dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        let res2 = dag.upsert(TestNode::new(2), vec![1]);
        let res3 = dag.upsert(TestNode::new(3), vec![1]);
        let res4 = dag.upsert(TestNode::new(4), vec![2, 3]);
        let res5 = dag.upsert(invalid_node, vec![1]);

        assert_validation_result(&res1, &[1], &[]);
        assert_validation_result(&res2, &[2], &[]);
        assert_validation_result(&res3, &[3], &[]);
        assert_validation_result(&res4, &[4], &[]);
        assert_validation_result(&res5, &[], &[5]);
    }

    #[test]
    fn edge_case_empty_parent_list() {
        let mut dag = Dag::new();
        let res = dag.upsert(TestNode::new(1), vec![]);
        assert_validation_result(&res, &[1], &[]);
    }

    #[test]
    fn get_leaf_nodes_empty_dag() {
        let dag = Dag::<TestNode>::new();
        let res = dag.get_leaf_nodes(&ROOT_NODE_ID);
        assert!(res.is_none());
    }

    #[test]
    fn get_leaf_nodes_single_root() {
        let dag = create_basic_dag();
        let res = dag.get_leaf_nodes(&ROOT_NODE_ID).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn get_leaf_nodes_linear_chain() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![1]);
        dag.upsert(TestNode::new(3), vec![2]);

        let res = dag.get_leaf_nodes(&ROOT_NODE_ID).unwrap();

        assert_eq!(res, vec![3]);
    }

    #[test]
    fn get_leaf_nodes_multiple_branches() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(3), vec![1]);
        dag.upsert(TestNode::new(4), vec![2]);

        let mut res = dag.get_leaf_nodes(&ROOT_NODE_ID).unwrap();
        res.sort();

        assert_eq!(res, vec![3, 4]);
    }

    #[test]
    fn get_leaf_nodes_with_invalid_nodes() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new_invalid(2), vec![1]);
        dag.upsert(TestNode::new(3), vec![1]);

        let res = dag.get_leaf_nodes(&ROOT_NODE_ID).unwrap();

        assert_eq!(res, vec![3]);
    }
}
