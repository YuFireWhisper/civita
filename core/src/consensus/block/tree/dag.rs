use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};

use dashmap::DashMap;
use derivative::Derivative;
use parking_lot::RwLock as ParkingRwLock;
use petgraph::{
    algo::{is_cyclic_directed, toposort},
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
    Direction,
};

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
    fn validate(&self, nodes: Arc<DashMap<Self::Id, Arc<ParkingRwLock<Self>>>>) -> State;
    fn set_state(&mut self, state: State);
    fn parent_ids(&self) -> Option<Vec<Self::Id>>;
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
    graph: DiGraph<N::Id, ()>,
    id_to_index: HashMap<N::Id, NodeIndex>,
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

    pub fn with_invalidated(id: N::Id) -> Self {
        let mut result = Self::new();
        result.add_invalidated(id);
        result
    }

    pub fn with_cycle_detected() -> Self {
        let mut result = Self::new();
        result.cycle_detected = true;
        result
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

    pub fn update(&mut self, node: N) -> ValidationResult<N> {
        let id = node.id();
        let node_arc = Arc::new(ParkingRwLock::new(node));

        let node_index = self.get_or_create_node_index(id.clone());

        let parent_ids = {
            let node_read = node_arc.read();
            node_read.parent_ids()
        };

        if let Some(parent_ids) = parent_ids {
            self.remove_incoming_edges(node_index);

            for parent_id in &parent_ids {
                let parent_index = self.get_or_create_node_index(parent_id.clone());
                self.graph.add_edge(parent_index, node_index, ());
            }

            if is_cyclic_directed(&self.graph) {
                self.remove_incoming_edges(node_index);
                return ValidationResult::with_cycle_detected();
            }

            let has_invalid_parent = parent_ids.iter().any(|parent_id| {
                self.nodes
                    .get(parent_id)
                    .map(|parent_node| parent_node.read().state().is_invalid())
                    .unwrap_or(true) // If parent doesn't exist, consider it invalid
            });

            if has_invalid_parent {
                node_arc.write().set_state(State::Invalid);
                self.nodes.insert(id.clone(), node_arc);
                return ValidationResult::with_invalidated(id);
            }
        } else {
            self.remove_incoming_edges(node_index);
        }

        self.nodes.insert(id.clone(), node_arc);

        self.try_validate_from(id)
    }

    fn get_or_create_node_index(&mut self, id: N::Id) -> NodeIndex {
        if let Some(&index) = self.id_to_index.get(&id) {
            index
        } else {
            let index = self.graph.add_node(id.clone());
            self.id_to_index.insert(id, index);
            index
        }
    }

    fn remove_incoming_edges(&mut self, node_index: NodeIndex) {
        let edges_to_remove: Vec<_> = self
            .graph
            .edges_directed(node_index, Direction::Incoming)
            .map(|edge| edge.id())
            .collect();

        for edge_id in edges_to_remove {
            self.graph.remove_edge(edge_id);
        }
    }

    fn try_validate_from(&self, start: N::Id) -> ValidationResult<N> {
        if !self.id_to_index.contains_key(&start) {
            return ValidationResult::new();
        }

        // Check if node exists and is pending
        let should_validate = self
            .nodes
            .get(&start)
            .map(|node| node.read().state().is_pending())
            .unwrap_or(false);

        if !should_validate {
            return ValidationResult::new();
        }

        let mut result = ValidationResult::new();

        let mut queue = vec![start];
        let mut visited = HashSet::new();
        let mut is_invalid = false;

        while let Some(id) = queue.pop() {
            if visited.contains(&id) {
                continue;
            }

            visited.insert(id.clone());

            let Some(node_arc) = self.nodes.get(&id) else {
                continue;
            };

            if is_invalid {
                node_arc.write().set_state(State::Invalid);
                result.add_invalidated(id.clone());

                if let Some(&node_index) = self.id_to_index.get(&id) {
                    for child_index in self.graph.neighbors(node_index) {
                        if let Some(child_id) = self.graph.node_weight(child_index) {
                            queue.push(child_id.clone());
                        }
                    }
                }
                continue;
            }

            let validation_state = {
                let node_read = node_arc.read();
                node_read.validate(self.nodes.clone())
            };

            match validation_state {
                State::Valid => {
                    node_arc.write().set_state(State::Valid);
                    result.add_validated(id.clone());

                    if let Some(&node_index) = self.id_to_index.get(&id) {
                        for child_index in self.graph.neighbors(node_index) {
                            if let Some(child_id) = self.graph.node_weight(child_index) {
                                queue.push(child_id.clone());
                            }
                        }
                    }
                }
                State::Invalid => {
                    node_arc.write().set_state(State::Invalid);
                    result.add_invalidated(id.clone());
                    is_invalid = true;

                    if let Some(&node_index) = self.id_to_index.get(&id) {
                        for child_index in self.graph.neighbors(node_index) {
                            if let Some(child_id) = self.graph.node_weight(child_index) {
                                queue.push(child_id.clone());
                            }
                        }
                    }
                }
                State::Pending => continue,
            }
        }

        result
    }

    pub fn get_parents(&self, id: &N::Id) -> Vec<N::Id> {
        self.id_to_index
            .get(id)
            .map(|&node_index| {
                self.graph
                    .neighbors_directed(node_index, Direction::Incoming)
                    .filter_map(|parent_index| self.graph.node_weight(parent_index))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_children(&self, id: &N::Id) -> Vec<N::Id> {
        self.id_to_index
            .get(id)
            .map(|&node_index| {
                self.graph
                    .neighbors_directed(node_index, Direction::Outgoing)
                    .filter_map(|child_index| self.graph.node_weight(child_index))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_path(&self, from: &N::Id, to: &N::Id) -> bool {
        let Some(&from_index) = self.id_to_index.get(from) else {
            return false;
        };
        let Some(&to_index) = self.id_to_index.get(to) else {
            return false;
        };

        petgraph::algo::has_path_connecting(&self.graph, from_index, to_index, None)
    }

    pub fn topological_sort(&self) -> Result<Vec<N::Id>, ValidationResult<N>> {
        match toposort(&self.graph, None) {
            Ok(order) => Ok(order
                .into_iter()
                .filter_map(|index| self.graph.node_weight(index))
                .cloned()
                .collect()),
            Err(_) => Err(ValidationResult::with_cycle_detected()),
        }
    }

    pub fn get_node(&self, id: &N::Id) -> Option<Arc<ParkingRwLock<N>>> {
        self.nodes.get(id).map(|entry| entry.clone())
    }

    pub fn contains_node(&self, id: &N::Id) -> bool {
        self.nodes.contains_key(id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
