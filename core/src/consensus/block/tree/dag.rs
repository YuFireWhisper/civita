use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    sync::Arc,
};

use dashmap::DashMap;
use derivative::Derivative;
use parking_lot::RwLock as ParkingRwLock;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum State {
    Pending,
    Valid,
    Invalid,
}

pub trait Node: Sized {
    type Id: Clone + Hash + Eq;

    fn id(&self) -> Self::Id;
    fn validate(&self) -> State;
    fn set_state(&mut self, state: State);
    fn parent_ids(&self) -> Vec<Self::Id>;
    fn state(&self) -> State;
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct ValidationResult<N: Node> {
    pub validated: HashSet<N::Id>,
    pub invalidated: HashSet<N::Id>,
    pub cycle_detected: bool,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Dag<N: Node> {
    nodes: Arc<DashMap<N::Id, Arc<ParkingRwLock<N>>>>,
    children: HashMap<N::Id, HashSet<N::Id>>,
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

    pub fn with_cycle_detected() -> Self {
        Self {
            cycle_detected: true,
            ..Default::default()
        }
    }

    pub fn add_validated(&mut self, id: N::Id) {
        self.validated.insert(id);
    }

    pub fn add_invalidated(&mut self, id: N::Id) {
        self.invalidated.insert(id);
    }
}

impl<N: Node> Dag<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, mut node: N) -> ValidationResult<N> {
        let id = node.id();
        let new_parent_ids = node.parent_ids();

        let old_parent_ids = self
            .nodes
            .get(&id)
            .map(|n| n.read().parent_ids())
            .unwrap_or_default();

        if self.would_create_cycle(&id, &new_parent_ids) {
            return ValidationResult::with_cycle_detected();
        }

        self.update_relationships(&id, &old_parent_ids, &new_parent_ids);

        let is_any_parent_invalid = new_parent_ids.iter().any(|pid| {
            self.nodes
                .get(pid)
                .is_none_or(|n| n.read().state().is_invalid())
        });

        let initial_state = if is_any_parent_invalid {
            State::Invalid
        } else {
            State::Pending
        };

        node.set_state(initial_state);
        let node_arc = Arc::new(ParkingRwLock::new(node));
        self.nodes.insert(id.clone(), node_arc);

        if initial_state.is_invalid() {
            let mut result = ValidationResult::new();
            result.add_invalidated(id.clone());
            self.invalidate_descendants(&id, &mut result);
            return result;
        }

        self.validate_from(&id)
    }

    fn would_create_cycle(&self, node_id: &N::Id, parent_ids: &[N::Id]) -> bool {
        parent_ids
            .iter()
            .any(|parent_id| self.has_path_to(node_id, parent_id))
    }

    fn has_path_to(&self, from: &N::Id, to: &N::Id) -> bool {
        if from == to {
            return true;
        }

        let mut queue = VecDeque::from([from.clone()]);
        let mut visited = HashSet::from([from.clone()]);

        while let Some(current_id) = queue.pop_front() {
            if let Some(children) = self.children.get(&current_id) {
                for child_id in children {
                    if child_id == to {
                        return true;
                    }
                    if visited.insert(child_id.clone()) {
                        queue.push_back(child_id.clone());
                    }
                }
            }
        }
        false
    }

    fn update_relationships(
        &mut self,
        node_id: &N::Id,
        old_parents: &[N::Id],
        new_parents: &[N::Id],
    ) {
        let old_parents_set: HashSet<_> = old_parents.iter().collect();
        let new_parents_set: HashSet<_> = new_parents.iter().collect();

        for parent_id in old_parents_set.difference(&new_parents_set) {
            if let Some(children_set) = self.children.get_mut(parent_id) {
                children_set.remove(node_id);
            }
        }

        for parent_id in new_parents_set.difference(&old_parents_set) {
            self.children
                .entry((*parent_id).clone())
                .or_default()
                .insert(node_id.clone());
        }
    }

    fn validate_from(&self, start_id: &N::Id) -> ValidationResult<N> {
        let mut result = ValidationResult::new();
        let mut queue = VecDeque::from([start_id.clone()]);
        let mut queued = HashSet::from([start_id.clone()]);

        while let Some(id) = queue.pop_front() {
            let Some(node_arc) = self.nodes.get(&id) else {
                continue;
            };

            let node_guard = node_arc.read();

            if !node_guard.state().is_pending() {
                continue;
            }

            let all_parents_valid = node_guard.parent_ids().iter().all(|pid| {
                self.nodes
                    .get(pid)
                    .is_some_and(|n| n.read().state().is_valid())
            });

            if !all_parents_valid {
                continue;
            }

            let validation_result = node_guard.validate();
            drop(node_guard);

            match validation_result {
                State::Valid => {
                    node_arc.write().set_state(State::Valid);
                    result.add_validated(id.clone());

                    if let Some(children) = self.children.get(&id) {
                        for child_id in children {
                            if queued.insert(child_id.clone()) {
                                queue.push_back(child_id.clone());
                            }
                        }
                    }
                }
                State::Invalid => {
                    node_arc.write().set_state(State::Invalid);
                    result.add_invalidated(id.clone());
                    self.invalidate_descendants(&id, &mut result);
                }
                State::Pending => {}
            }
        }
        result
    }

    fn invalidate_descendants(&self, start_id: &N::Id, result: &mut ValidationResult<N>) {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        if let Some(children) = self.children.get(start_id) {
            for child_id in children {
                if visited.insert(child_id.clone()) {
                    queue.push_back(child_id.clone());
                }
            }
        }

        while let Some(id) = queue.pop_front() {
            if let Some(node_arc) = self.nodes.get(&id) {
                if !node_arc.read().state().is_invalid() {
                    node_arc.write().set_state(State::Invalid);
                    result.add_invalidated(id.clone());
                }

                if let Some(children) = self.children.get(&id) {
                    for child_id in children {
                        if visited.insert(child_id.clone()) {
                            queue.push_back(child_id.clone());
                        }
                    }
                }
            }
        }
    }

    pub fn get_parents(&self, id: &N::Id) -> Vec<N::Id> {
        self.nodes
            .get(id)
            .map(|node| node.read().parent_ids())
            .unwrap_or_default()
    }

    pub fn get_children(&self, id: &N::Id) -> Vec<N::Id> {
        self.children
            .get(id)
            .map(|children| children.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_node(&self, id: &N::Id) -> Option<Arc<ParkingRwLock<N>>> {
        self.nodes.get(id).map(|entry| entry.value().clone())
    }

    pub fn contains_node(&self, id: &N::Id) -> bool {
        self.nodes.contains_key(id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn topological_sort(&self) -> Result<Vec<N::Id>, ValidationResult<N>> {
        let mut in_degree: HashMap<N::Id, usize> =
            self.nodes.iter().map(|e| (e.key().clone(), 0)).collect();

        for children_set in self.children.values() {
            for child_id in children_set {
                if let Some(degree) = in_degree.get_mut(child_id) {
                    *degree += 1;
                }
            }
        }

        let mut queue: VecDeque<_> = in_degree
            .iter()
            .filter_map(|(id, &degree)| (degree == 0).then_some(id.clone()))
            .collect();

        let mut result = Vec::with_capacity(self.nodes.len());

        while let Some(node_id) = queue.pop_front() {
            if let Some(children) = self.children.get(&node_id) {
                for child_id in children {
                    if let Some(degree) = in_degree.get_mut(child_id) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(child_id.clone());
                        }
                    }
                }
            }
            result.push(node_id);
        }

        if result.len() == self.nodes.len() {
            Ok(result)
        } else {
            Err(ValidationResult::with_cycle_detected())
        }
    }
}
