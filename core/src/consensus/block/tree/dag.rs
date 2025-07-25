use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    hash::Hash,
    sync::RwLock,
};

use derivative::Derivative;

pub trait Node {
    type Id: Clone + Eq + Hash + Debug;

    fn id(&self) -> Self::Id;
    fn validate(&self) -> bool;
    fn on_parent_valid(&self, child: &Self);
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct ValidationResult<N: Node> {
    pub validated: Vec<N::Id>,
    pub invalidated: Vec<N::Id>,
}

struct Entry<N: Node> {
    node: N,
    valid: bool,
    pending: usize,
    children: Vec<usize>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Dag<N: Node> {
    index: HashMap<N::Id, usize>,
    entries: Vec<Entry<N>>,
    lock: RwLock<()>,
}

impl<N: Node> ValidationResult<N> {
    pub fn new() -> Self {
        Self::default()
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
        }
    }
}

impl<N: Node> Dag<N> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert<I>(&mut self, node: N, parent_ids: I) -> ValidationResult<N>
    where
        I: IntoIterator<Item = N::Id>,
    {
        let _guard = self.lock.write().unwrap();

        let id = node.id();

        if self.index.contains_key(&id) {
            return ValidationResult::new();
        }

        let idx = self.entries.len();
        self.index.insert(id.clone(), idx);

        self.entries.push(Entry::new(node));

        for pid in parent_ids.into_iter() {
            if let Some(&pi) = self.index.get(&pid) {
                if self.detect_cycle(pi, idx) {
                    self.entries[idx].valid = false;
                    let mut result = ValidationResult::new();
                    result.add_invalidated(id);
                    return result;
                }
                self.entries[pi].children.push(idx);
                self.entries[idx].pending += 1;
            } else {
                self.entries[idx].pending += 1;
            }
        }

        drop(_guard);

        if self.entries[idx].pending == 0 {
            self.validate_from(idx)
        } else {
            ValidationResult::new()
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
            for &c in &self.entries[u].children {
                stack.push(c);
            }
        }
        false
    }

    fn validate_from(&mut self, root: usize) -> ValidationResult<N> {
        let _guard = self.lock.write().unwrap();

        let mut result = ValidationResult::new();
        let mut stack = vec![root];

        while let Some(u) = stack.pop() {
            if self.entries[u].valid {
                continue;
            }

            let ok = self.entries[u].node.validate();
            self.entries[u].valid = ok;

            if ok {
                result.add_validated(self.entries[u].node.id().clone());
                let children: Vec<usize> = self.entries[u].children.clone();

                for &c in &children {
                    {
                        let mut pend = self.entries[c].pending;
                        pend -= 1;
                        if pend == 0 {
                            stack.push(c);
                        }
                    }

                    self.entries[c].node.on_parent_valid(&self.entries[u].node);
                }
            } else {
                result.add_invalidated(self.entries[u].node.id().clone());
                let children: Vec<usize> = self.entries[u].children.clone();

                for &c in &children {
                    if self.entries[c].valid {
                        self.entries[c].valid = false;
                        stack.push(c);
                    }
                }
            }
        }

        result
    }

    pub fn sorted_levels(&self, id: &N::Id) -> Option<Vec<Vec<N::Id>>> {
        let _guard = self.lock.read().unwrap();

        let start = *self.index.get(id)?;

        let n = self.entries.len();

        let mut visited = vec![false; n];
        let mut queue = VecDeque::new();
        let mut nodes = Vec::new();

        visited[start] = true;
        queue.push_back(start);

        while let Some(u) = queue.pop_front() {
            if self.entries[u].valid {
                nodes.push(u);
                for &c in &self.entries[u].children {
                    if !visited[c] {
                        visited[c] = true;
                        queue.push_back(c);
                    }
                }
            }
        }

        if nodes.is_empty() {
            return Some(Vec::new());
        }

        let mut indeg = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        for &u in &nodes {
            for &c in &self.entries[u].children {
                if self.entries[c].valid {
                    indeg[c] += 1;
                    adj[u].push(c);
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
                for &c in &adj[u] {
                    indeg[c] -= 1;
                    if indeg[c] == 0 {
                        next_zero.push(c);
                    }
                }
            }
            zero = next_zero;
        }

        Some(levels)
    }
}
