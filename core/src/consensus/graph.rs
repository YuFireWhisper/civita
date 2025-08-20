use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
};

use civita_serialize::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Multihash, PublicKey},
    ty::atom::{Atom, Command, Height, Nonce, Witness},
    utils::Trie,
};

#[derive(Clone)]
#[derive(Default)]
pub struct UpdateResult {
    pub invalidated: Vec<Multihash>,
    pub missing: Vec<Multihash>,
}

struct BlockStats {
    trie: Trie,
    distinct_publishers: usize,
    cmd_count: usize,
    atom_count: usize,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry<C: Command> {
    pub atom: Atom<C>,
    pub witness: Witness,
    pub public_key: PublicKey,

    pub block_stats: Option<BlockStats>,

    pub block_parent: Option<usize>,
    pub parents: HashSet<usize>,
    pub children: HashSet<usize>,

    pub pending_parents: usize,
    pub max_nonce: Nonce,

    #[derivative(Default(value = "true"))]
    pub is_missing: bool,
}

struct AtomExecuter<C: Command> {
    state: HashMap<Vec<u8>, C::Value>,
    publishers: HashSet<PublicKey>,
    cmd_count: usize,
    atom_count: usize,
}

pub struct Graph<C: Command> {
    index: HashMap<Multihash, usize>,
    entries: Vec<Entry<C>>,

    nonce_used: HashMap<usize, HashMap<PublicKey, HashSet<Nonce>>>,

    main_head: Option<usize>,
    checkpoint: Option<usize>,

    block_threshold: usize,
    checkpoint_distance: u32,
}

impl<C: Command> Entry<C> {
    pub fn new(atom: Atom<C>, witness: Witness, pk: PublicKey) -> Self {
        Self {
            atom,
            witness,
            public_key: pk,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn hash(&self) -> Multihash {
        self.atom.hash()
    }

    pub fn is_valid(&self) -> bool {
        !self.is_missing && self.block_stats.is_some()
    }
}

impl<C: Command> AtomExecuter<C> {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            publishers: HashSet::new(),
            cmd_count: 0,
            atom_count: 0,
        }
    }

    pub fn execute<'a, I>(&mut self, order: I, trie_root: Multihash) -> bool
    where
        I: IntoIterator<Item = &'a Entry<C>>,
    {
        order
            .into_iter()
            .all(|entry| self.execute_single(entry, trie_root))
    }

    fn execute_single(&mut self, entry: &Entry<C>, trie_root: Multihash) -> bool {
        self.publishers.insert(entry.public_key.clone());
        self.atom_count += 1;

        let Some(cmd) = &entry.atom.cmd else {
            return true;
        };

        let input = self.prepare_command_input(cmd, &entry.witness.trie_proofs, trie_root);
        let Ok(output) = cmd.execute(input) else {
            return false;
        };

        self.cmd_count += 1;
        self.state.extend(output);

        true
    }

    fn prepare_command_input(
        &mut self,
        cmd: &C,
        proof: &HashMap<Multihash, Vec<u8>>,
        trie_root: Multihash,
    ) -> HashMap<Vec<u8>, C::Value> {
        cmd.keys()
            .into_iter()
            .map(|k| {
                let value = self.state.remove(&k).unwrap_or_else(|| {
                    Trie::verify_proof(trie_root, &k, proof)
                        .expect("Proof should be valid")
                        .map(|v| C::Value::from_slice(&v).expect("Value should be valid"))
                        .unwrap_or_default()
                });
                (k, value)
            })
            .collect()
    }

    pub fn into_block_stats(self, mut trie: Trie) -> BlockStats {
        trie.extend(self.state.into_iter().map(|(k, v)| (k, v.to_vec())));

        BlockStats {
            trie,
            distinct_publishers: self.publishers.len(),
            cmd_count: self.cmd_count,
            atom_count: self.atom_count,
        }
    }
}

impl<C: Command> Graph<C> {
    pub fn new(block_threshold: usize, checkpoint_distance: u32) -> Self {
        Self {
            index: HashMap::new(),
            entries: Vec::new(),
            main_head: None,
            checkpoint: None,
            nonce_used: HashMap::new(),
            block_threshold,
            checkpoint_distance,
        }
    }

    pub fn upsert(&mut self, atom: Atom<C>, witness: Witness, pk: PublicKey) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if self.contains(&hash) || atom.height <= self.checkpoint_height() {
            return result;
        }

        let idx = self.upsert_entry(atom, witness, pk);

        if !self.link_parents(idx, &mut result) {
            self.remove_subgraph(idx, &mut result);
            return result;
        }

        if self.entries[idx].is_valid() {
            self.on_all_parent_valid(idx, &mut result);
        }

        result
    }

    fn checkpoint_height(&self) -> Height {
        self.checkpoint
            .map(|i| self.entries[i].atom.height)
            .unwrap_or(0)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.index
            .get(h)
            .and_then(|&i| self.entries.get(i))
            .is_some_and(|e| !e.is_missing)
    }

    fn upsert_entry(&mut self, atom: Atom<C>, witness: Witness, pk: PublicKey) -> usize {
        let hash = atom.hash();

        if let Some(idx) = self.index.get(&hash).copied() {
            debug_assert!(self.entries[idx].is_missing);
            self.entries[idx] = Entry::new(atom, witness, pk);
            idx
        } else {
            let idx = self.entries.len();
            self.index.insert(hash, idx);
            self.entries.push(Entry::default());
            idx
        }
    }

    fn link_parents(&mut self, idx: usize, result: &mut UpdateResult) -> bool {
        let parents = self.entries[idx]
            .witness
            .parents
            .values()
            .copied()
            .collect::<Vec<_>>();

        parents.into_iter().all(|h| {
            let pidx = self.index.get(&h).copied().unwrap_or_else(|| {
                let idx = self.entries.len();
                self.index.insert(h, idx);
                self.entries.push(Entry::default());
                result.missing.push(h);
                idx
            });

            self.add_edge(idx, pidx);
            self.on_parent_valid(idx, pidx)
        })
    }

    fn add_edge(&mut self, idx: usize, pidx: usize) {
        let (cur, parent) = self.get_two_entries_mut(idx, pidx);

        cur.parents.insert(pidx);
        parent.children.insert(idx);

        if !parent.is_valid() {
            cur.pending_parents += 1;
        }
    }

    fn get_two_entries_mut(&mut self, idx: usize, pidx: usize) -> (&mut Entry<C>, &mut Entry<C>) {
        if idx < pidx {
            let (l, r) = self.entries.split_at_mut(pidx);
            (&mut l[idx], &mut r[0])
        } else {
            let (l, r) = self.entries.split_at_mut(idx);
            (&mut r[0], &mut l[pidx])
        }
    }

    fn on_parent_valid(&mut self, idx: usize, pidx: usize) -> bool {
        let (cur, parent) = self.get_two_entries_mut(idx, pidx);

        if cur.atom.height != parent.atom.height + 1
            || !cur.witness.parents.contains_key(&parent.public_key)
        {
            return false;
        }

        if parent.block_stats.is_none() {
            if cur.atom.nonce <= parent.atom.nonce {
                return false;
            }
            cur.max_nonce = cur.max_nonce.max(parent.max_nonce);
        }

        let bpidx = if parent.block_stats.is_some() {
            pidx
        } else {
            parent.block_parent.expect("Block parent must exist")
        };

        cur.block_parent.replace(bpidx).is_none_or(|i| i == bpidx)
    }

    fn remove_subgraph(&mut self, idx: usize, result: &mut UpdateResult) {
        let mut stk = vec![idx];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) {
                continue;
            }

            let mut entry = std::mem::take(&mut self.entries[u]);
            let hash = entry.hash();

            if !entry.is_missing {
                if let Some(bpidx) = entry.block_parent {
                    self.remove_nonce(bpidx, &entry.public_key, &entry.atom.nonce);
                }
            }

            stk.extend(entry.children);
            entry.parents.drain().for_each(|p| {
                self.entries[p].children.remove(&u);
            });

            self.index.remove(&hash);
            result.invalidated.push(hash);
        }
    }

    fn remove_nonce(&mut self, bpidx: usize, public_key: &PublicKey, nonce: &Nonce) {
        let Some(by_pk) = self.nonce_used.get_mut(&bpidx) else {
            return;
        };

        let Some(set) = by_pk.get_mut(public_key) else {
            return;
        };

        set.remove(nonce);

        if set.is_empty() {
            by_pk.remove(public_key);
        }

        if by_pk.is_empty() {
            self.nonce_used.remove(&bpidx);
        }
    }

    fn on_all_parent_valid(&mut self, idx: usize, result: &mut UpdateResult) {
        if self.entries[idx].atom.nonce != self.entries[idx].max_nonce + 1 {
            self.remove_subgraph(idx, result);
            return;
        }

        let Some(bpidx) = self.entries[idx].block_parent else {
            self.remove_subgraph(idx, result);
            return;
        };

        {
            let pk = self.entries[idx].public_key.clone();
            let nonce = self.entries[idx].atom.nonce;
            let by_pk = self.nonce_used.entry(bpidx).or_default();
            let set = by_pk.entry(pk).or_default();
            if !set.insert(nonce) {
                self.remove_subgraph(idx, result);
                return;
            }
        }

        let block_stats = self.entries[bpidx]
            .block_stats
            .as_ref()
            .expect("Block stats must exist");

        let order = self.topo_parents(idx);
        let mut executer = AtomExecuter::new();
        let root_hash = block_stats.trie.root_hash();

        if !executer.execute(order.into_iter().rev().map(|i| &self.entries[i]), root_hash) {
            self.remove_subgraph(idx, result);
            return;
        }

        if executer.atom_count >= self.block_threshold {
            let trie = block_stats.trie.clone();
            self.entries[idx].block_stats = Some(executer.into_block_stats(trie));
        }

        self.recompute_main_chain_and_checkpoint();

        let mut queue = VecDeque::new();
        queue.push_back(idx);

        while let Some(idx) = queue.pop_front() {
            let children = self.entries[idx].children.clone();

            children.into_iter().for_each(|cidx| {
                if !self.on_parent_valid(cidx, idx) {
                    self.remove_subgraph(cidx, result);
                    return;
                }

                self.entries[cidx].pending_parents -= 1;
                if self.entries[cidx].pending_parents == 0 {
                    queue.push_back(cidx);
                }
            });
        }
    }

    fn topo_parents(&self, idx: usize) -> Vec<usize> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut heap = BinaryHeap::new();

        queue.push_back(idx);
        visited.insert(idx);

        while let Some(u) = queue.pop_front() {
            let entry = &self.entries[u];

            if entry.block_stats.is_some() {
                continue;
            }

            heap.push(Reverse((entry.atom.nonce, u)));
            queue.extend(entry.parents.iter().filter(|&&p| visited.insert(p)));
        }

        heap.into_sorted_vec()
            .into_iter()
            .map(|Reverse((_, idx))| idx)
            .collect()
    }

    fn recompute_main_chain_and_checkpoint(&mut self) {
        let start = self.checkpoint.unwrap_or_default();

        let new_head = self.ghost_select(start);
        self.main_head = Some(new_head);

        self.maybe_advance_checkpoint(new_head);
    }

    fn ghost_select(&self, start: usize) -> usize {
        let mut cur = start;

        while let Some(next_idx) = self.entries[cur]
            .children
            .iter()
            .filter_map(|&child_idx| {
                let child = &self.entries[child_idx];
                let stats = child.block_stats.as_ref()?;
                let h = child.atom.hash();
                Some((
                    stats.distinct_publishers,
                    stats.cmd_count,
                    stats.atom_count,
                    h,
                    child_idx,
                ))
            })
            .max()
            .map(|(.., idx)| idx)
        {
            cur = next_idx;
        }

        cur
    }

    fn maybe_advance_checkpoint(&mut self, head_idx: usize) {
        let head_h = self.entries[head_idx].atom.height;
        let cur_cp_h = self.checkpoint_height();

        if cur_cp_h == 0 {
            self.checkpoint = Some(head_idx);
            return;
        }

        if head_h - cur_cp_h > self.checkpoint_distance {
            let target_h = head_h.saturating_sub(self.checkpoint_distance as Height);

            let mut cur_idx = head_idx;
            let mut cur = &self.entries[cur_idx];

            while cur.atom.height > target_h {
                let block_parent = cur.block_parent.expect("Block parent must exist");
                cur_idx = block_parent;
                cur = &self.entries[cur_idx];
            }

            self.checkpoint = Some(cur_idx);
        }
    }

    pub fn subgraph_leaves(&self) -> Option<HashMap<PublicKey, Multihash>> {
        let mut stk: Vec<usize> = self.entries[self.main_head?]
            .children
            .iter()
            .copied()
            .filter(|&child| {
                let e = &self.entries[child];
                !e.is_missing && e.block_stats.is_none()
            })
            .collect();

        if stk.is_empty() {
            return None;
        }

        let mut result: HashMap<PublicKey, (Nonce, Multihash)> = HashMap::new();
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if visited.insert(u) {
                continue;
            }

            let entry = &self.entries[u];

            let is_leaf = entry
                .children
                .iter()
                .filter(|c| {
                    let ce = &self.entries[**c];
                    !ce.is_missing && ce.block_stats.is_none()
                })
                .inspect(|&c| stk.push(*c))
                .count()
                == 0;

            if !is_leaf {
                let pk = entry.public_key.clone();
                let nonce = entry.atom.nonce;
                let h = entry.atom.hash();

                result
                    .entry(pk)
                    .and_modify(|(best_nonce, best_hash)| {
                        if nonce > *best_nonce {
                            *best_nonce = nonce;
                            *best_hash = h;
                        }
                    })
                    .or_insert((nonce, h));
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result.into_iter().map(|(pk, (_, h))| (pk, h)).collect())
        }
    }
}
