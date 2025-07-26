use std::{
    collections::{HashMap, VecDeque},
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

struct Entry<N: Node> {
    node: N,
    valid: bool,
    pending: usize,
    children: Vec<usize>,
    waiting_children: Vec<usize>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Dag<N: Node> {
    index: HashMap<N::Id, usize>,
    entries: Vec<Entry<N>>,
    phantom_waiting: HashMap<N::Id, Vec<usize>>,
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
            node,
            valid: false,
            pending: 0,
            children: Vec::new(),
            waiting_children: Vec::new(),
        }
    }

    fn new_valid(node: N) -> Self {
        Self {
            node,
            valid: true,
            pending: 0,
            children: Vec::new(),
            waiting_children: Vec::new(),
        }
    }
}

impl<N: Node> Dag<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(node: N) -> Self {
        let mut dag = Self::default();
        dag.index.insert(node.id().clone(), 0);
        dag.entries.push(Entry::new_valid(node));
        dag
    }

    pub fn upsert<I>(&mut self, node: N, parent_ids: I) -> ValidationResult<N>
    where
        I: IntoIterator<Item = N::Id>,
    {
        let id = node.id();

        let mut result = ValidationResult::new();

        if self.index.contains_key(&id) {
            return result;
        }

        let idx = self.create_entry(node);
        let parent_ids: Vec<_> = parent_ids.into_iter().collect();

        if self.establish_parent_relationships(idx, &parent_ids, &mut result) {
            return result;
        }

        if self.entries[idx].pending == 0 {
            self.validate_from(idx, &mut result);
        }

        self.process_waiting_children(idx, &mut result);

        result
    }

    fn create_entry(&mut self, node: N) -> usize {
        let id = node.id();
        let idx = self.entries.len();

        self.index.insert(id.clone(), idx);
        self.entries.push(Entry::new(node));

        if let Some(waiting) = self.phantom_waiting.remove(&id) {
            self.entries[idx].waiting_children = waiting;
        }

        idx
    }

    fn establish_parent_relationships(
        &mut self,
        idx: usize,
        parent_ids: &[N::Id],
        result: &mut ValidationResult<N>,
    ) -> bool {
        for pid in parent_ids {
            if let Some(&parent_idx) = self.index.get(pid) {
                if self.detect_cycle(parent_idx, idx) {
                    self.entries[idx].valid = false;
                    let id = self.entries[idx].node.id().clone();
                    result.add_invalidated(id);
                    return true;
                }

                self.entries[parent_idx].children.push(idx);

                if self.check_parent_constraint(idx, parent_idx, result) {
                    return true;
                }
            } else {
                self.phantom_waiting
                    .entry(pid.clone())
                    .or_default()
                    .push(idx);
                self.entries[idx].pending += 1;
            }
        }

        false
    }

    fn check_parent_constraint(
        &mut self,
        cidx: usize,
        pidx: usize,
        result: &mut ValidationResult<N>,
    ) -> bool {
        if !self.entries[pidx].valid {
            self.entries[cidx].pending += 1;
            return false;
        }

        if !self.entries[cidx]
            .node
            .on_parent_valid(&self.entries[pidx].node)
        {
            let id = self.entries[cidx].node.id().clone();
            result.add_invalidated(id);
            return true;
        }

        false
    }

    fn process_waiting_children(&mut self, idx: usize, result: &mut ValidationResult<N>) {
        let waiting_children = std::mem::take(&mut self.entries[idx].waiting_children);

        for &child_idx in &waiting_children {
            self.entries[idx].children.push(child_idx);
        }

        waiting_children.iter().for_each(|&child_idx| {
            self.process_waiting_child(idx, child_idx, result);
        });
    }

    fn process_waiting_child(
        &mut self,
        parent_idx: usize,
        child_idx: usize,
        result: &mut ValidationResult<N>,
    ) {
        let parent_valid = self.entries[parent_idx].valid;

        let constraint_satisfied = if parent_valid {
            let parent_node = &self.entries[parent_idx].node;
            let child_node = &self.entries[child_idx].node;
            child_node.on_parent_valid(parent_node)
        } else {
            true
        };

        if parent_valid && !constraint_satisfied {
            self.invalidate_subtree(child_idx, result);
            return;
        }

        self.entries[child_idx].pending -= 1;

        if self.entries[child_idx].pending == 0 {
            self.validate_from(child_idx, result);
        }
    }

    fn invalidate_subtree(&mut self, root_idx: usize, result: &mut ValidationResult<N>) {
        let mut stack = vec![root_idx];

        while let Some(u) = stack.pop() {
            if self.entries[u].valid {
                self.entries[u].valid = false;
                result.add_invalidated(self.entries[u].node.id().clone());

                for &child in &self.entries[u].children.clone() {
                    if self.entries[child].valid {
                        stack.push(child);
                    }
                }
            }
        }
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
        let mut stack = vec![root];

        while let Some(u) = stack.pop() {
            if self.entries[u].valid {
                continue;
            }

            if self.validate_node(u, result) {
                self.process_children_after_validation(u, &mut stack, result);
            } else {
                self.invalidate_children(u, &mut stack, result);
            }
        }
    }

    fn validate_node(&mut self, idx: usize, result: &mut ValidationResult<N>) -> bool {
        let valid = self.entries[idx].node.validate();
        self.entries[idx].valid = valid;

        if valid {
            result.add_validated(self.entries[idx].node.id().clone());
        } else {
            result.add_invalidated(self.entries[idx].node.id().clone());
        }

        valid
    }

    fn process_children_after_validation(
        &mut self,
        parent_idx: usize,
        stack: &mut Vec<usize>,
        result: &mut ValidationResult<N>,
    ) {
        self.entries[parent_idx]
            .children
            .clone()
            .iter()
            .for_each(|&cidx| {
                let parent = &self.entries[parent_idx].node;
                let valid = self.entries[cidx].node.on_parent_valid(parent);

                if !valid {
                    self.invalidate_subtree(cidx, result);
                } else {
                    self.entries[cidx].pending = self.entries[cidx].pending.saturating_sub(1);
                    if self.entries[cidx].pending == 0 {
                        stack.push(cidx);
                    }
                }
            });
    }

    fn invalidate_children(
        &mut self,
        parent_idx: usize,
        stack: &mut Vec<usize>,
        result: &mut ValidationResult<N>,
    ) {
        self.entries[parent_idx]
            .children
            .clone()
            .iter()
            .for_each(|&i| {
                if self.entries[i].valid {
                    self.entries[i].valid = false;
                    result.add_invalidated(self.entries[i].node.id().clone());
                    stack.push(i);
                }
            });
    }

    pub fn sorted_levels(&self, id: &N::Id) -> Option<Vec<Vec<N::Id>>> {
        let start = *self.index.get(id)?;

        let valid_nodes = self.collect_valid_descendants(start);
        if valid_nodes.is_empty() {
            return Some(Vec::new());
        }

        self.topological_sort(&valid_nodes)
    }

    fn collect_valid_descendants(&self, start: usize) -> Vec<usize> {
        let mut visited = vec![false; self.entries.len()];
        let mut queue = VecDeque::new();
        let mut nodes = Vec::new();

        visited[start] = true;
        queue.push_back(start);

        while let Some(u) = queue.pop_front() {
            if self.entries[u].valid {
                nodes.push(u);
                for &child in &self.entries[u].children {
                    if !visited[child] {
                        visited[child] = true;
                        queue.push_back(child);
                    }
                }
            }
        }

        nodes
    }

    fn topological_sort(&self, nodes: &[usize]) -> Option<Vec<Vec<N::Id>>> {
        let n = self.entries.len();
        let mut indeg = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        for &u in nodes {
            for &child in &self.entries[u].children {
                if self.entries[child].valid {
                    indeg[child] += 1;
                    adj[u].push(child);
                }
            }
        }

        let mut levels = Vec::new();
        let mut zero: Vec<usize> = nodes.iter().copied().filter(|&u| indeg[u] == 0).collect();

        while !zero.is_empty() {
            levels.push(
                zero.iter()
                    .map(|&u| self.entries[u].node.id().clone())
                    .collect(),
            );

            let mut next_zero = Vec::new();
            for &u in &zero {
                for &child in &adj[u] {
                    indeg[child] -= 1;
                    if indeg[child] == 0 {
                        next_zero.push(child);
                    }
                }
            }
            zero = next_zero;
        }

        Some(levels)
    }

    pub fn get_node(&self, id: &N::Id) -> Option<&N> {
        self.index
            .get(id)
            .and_then(|&idx| self.entries.get(idx).map(|e| &e.node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, sync::Arc};

    const VALID_NODE_ID: u32 = 1;
    const INVALID_NODE_ID: u32 = 2;
    const ROOT_NODE_ID: u32 = 0;

    #[derive(Clone)]
    #[derive(Derivative)]
    #[derivative(Debug)]
    struct TestNode {
        id: u32,
        should_validate: bool,
        #[derivative(Debug = "ignore")]
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
        assert!(dag.entries[0].valid);
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
        assert_eq!(dag.entries[1].pending, 1);
        assert!(!dag.entries[1].valid);
    }

    #[test]
    fn upsert_multiple_parents() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);

        let result = dag.upsert(TestNode::new(3), vec![1, 2]);

        assert_validation_result(&result, &[3], &[]);
        assert!(dag.entries[3].valid);
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

        assert_validation_result(&result, &[], &[]);
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
    fn sorted_levels_empty_dag() {
        let dag = Dag::<TestNode>::new();
        let res = dag.sorted_levels(&ROOT_NODE_ID);
        assert!(res.is_none());
    }

    #[test]
    fn sorted_levels_single_node() {
        let dag = create_basic_dag();
        let levels = dag.sorted_levels(&ROOT_NODE_ID).unwrap();

        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec![ROOT_NODE_ID]);
    }

    #[test]
    fn sorted_levels_linear_chain() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![1]);

        let levels = dag.sorted_levels(&ROOT_NODE_ID).unwrap();

        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec![ROOT_NODE_ID]);
        assert_eq!(levels[1], vec![1]);
        assert_eq!(levels[2], vec![2]);
    }

    #[test]
    fn sorted_levels_parallel_branches() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(3), vec![1, 2]);

        let levels = dag.sorted_levels(&ROOT_NODE_ID).unwrap();

        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec![ROOT_NODE_ID]);
        assert_eq!(levels[1].len(), 2);
        assert!(levels[1].contains(&1));
        assert!(levels[1].contains(&2));
        assert_eq!(levels[2], vec![3]);
    }

    #[test]
    fn sorted_levels_with_invalid_nodes() {
        let mut dag = create_basic_dag();
        dag.upsert(TestNode::new_invalid(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);

        let levels = dag.sorted_levels(&ROOT_NODE_ID).unwrap();

        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec![ROOT_NODE_ID]);
        assert_eq!(levels[1], vec![2]);
    }

    #[test]
    fn sorted_levels_nonexistent_start() {
        let dag = create_basic_dag();
        let res = dag.sorted_levels(&999);
        assert!(res.is_none());
    }

    #[test]
    fn get_existing_node() {
        let dag = create_basic_dag();
        let node = dag.get_node(&ROOT_NODE_ID);

        assert!(node.is_some());
        assert_eq!(node.unwrap().id(), ROOT_NODE_ID);
    }

    #[test]
    fn get_nonexistent_node() {
        let dag = create_basic_dag();
        let node = dag.get_node(&999);
        assert!(node.is_none());
    }

    #[test]
    fn complex_dag_operations() {
        let mut dag = create_basic_dag();

        dag.upsert(TestNode::new(1), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(2), vec![ROOT_NODE_ID]);
        dag.upsert(TestNode::new(3), vec![1]);
        dag.upsert(TestNode::new(4), vec![2]);
        dag.upsert(TestNode::new(5), vec![3, 4]);

        let levels = dag.sorted_levels(&ROOT_NODE_ID).unwrap();

        assert_eq!(levels.len(), 4);
        assert_eq!(levels[0], vec![ROOT_NODE_ID]);
        assert_eq!(levels[1].len(), 2);
        assert_eq!(levels[2].len(), 2);
        assert_eq!(levels[3], vec![5]);
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
}
