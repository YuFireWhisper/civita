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
                    self.entries[c].pending -= 1;
                    if self.entries[c].pending == 0 {
                        stack.push(c);
                    }
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
        let mut visited = vec![false; self.entries.len()];

        let mut queue = VecDeque::new();
        visited[start] = true;
        queue.push_back(start);

        let mut subnodes = Vec::new();

        while let Some(u) = queue.pop_front() {
            subnodes.push(u);
            for &c in &self.entries[u].children {
                if !visited[c] {
                    visited[c] = true;
                    queue.push_back(c);
                }
            }
        }

        let mut indeg = HashMap::new();
        let mut adj = HashMap::new();
        for &u in &subnodes {
            indeg.insert(u, 0usize);
        }
        for &u in &subnodes {
            for &c in &self.entries[u].children {
                if indeg.contains_key(&c) {
                    *indeg.get_mut(&c).unwrap() += 1;
                    adj.entry(u).or_insert_with(Vec::new).push(c);
                }
            }
        }

        let mut levels = Vec::new();
        let mut zero: Vec<_> = indeg
            .iter()
            .filter_map(|(&k, &v)| if v == 0 { Some(k) } else { None })
            .collect();
        while !zero.is_empty() {
            levels.push(
                zero.iter()
                    .map(|&i| self.entries[i].node.id().clone())
                    .collect(),
            );
            let mut next = Vec::new();
            for &u in &zero {
                if let Some(children) = adj.get(&u) {
                    for &c in children {
                        let d = indeg.get_mut(&c).unwrap();
                        *d -= 1;
                        if *d == 0 {
                            next.push(c);
                        }
                    }
                }
            }
            zero = next;
        }
        Some(levels)
    }
}
