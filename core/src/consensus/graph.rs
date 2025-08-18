use std::collections::{BTreeMap, HashMap, HashSet};

use civita_serialize::Serialize;

use crate::{
    consensus::graph::entry::Entry,
    crypto::Multihash,
    ty::atom::{Atom, Command, Height, Key, MergeStrategy, Version, Witness},
};

mod entry;

#[derive(Clone)]
#[derive(Default)]
pub struct UpdateResult {
    pub invalidated: Vec<Multihash>,
    pub missing: Vec<Multihash>,
}

pub struct Graph<C: Command, M: MergeStrategy<C::Value>> {
    index: HashMap<Multihash, usize>,
    entries: Vec<Entry<C>>,

    main_head: Option<usize>,
    checkpoint: Option<usize>,

    block_witness_threshold: usize,
    checkpoint_distance: u32,

    merge_strategy: M,
}

impl<C: Command, M: MergeStrategy<C::Value>> Graph<C, M> {
    pub fn new(
        merge_strategy: M,
        block_witness_threshold: usize,
        checkpoint_distance: u32,
    ) -> Self {
        Self {
            index: HashMap::new(),
            entries: Vec::new(),
            main_head: None,
            checkpoint: None,
            block_witness_threshold,
            checkpoint_distance,
            merge_strategy,
        }
    }

    pub fn upsert(&mut self, atom: Atom<C>, witness: Witness) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if self.contains(&hash) || atom.height <= self.checkpoint_height() {
            return result;
        }

        let idx = self.insert_entry(atom, witness);

        if !self.link_parents(idx, &mut result) {
            self.remove_subgraph(idx, &mut result);
            return result;
        }

        if self.entries[idx].as_pending().pending_parent_count == 0 {
            self.on_all_parent_valid(idx, &mut result);
        }

        result
    }

    fn checkpoint_height(&self) -> Height {
        self.checkpoint
            .map(|i| self.entries[i].as_block().atom.height)
            .unwrap_or(0)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.index
            .get(h)
            .and_then(|&i| self.entries.get(i))
            .is_some_and(|e| !e.is_missing())
    }

    fn insert_entry(&mut self, atom: Atom<C>, witness: Witness) -> usize {
        let idx = self.entries.len();
        self.index.insert(atom.hash(), idx);
        let entry = Entry::new_pending(atom, witness);
        debug_assert!(self.validate_entry_inputs(&entry));
        self.entries.push(entry);
        idx
    }

    fn validate_entry_inputs(&self, entry: &Entry<C>) -> bool {
        entry
            .as_pending()
            .remaining_inputs
            .iter()
            .all(|(k, v)| self.merge_strategy.is_mergeable(k) == v.is_none())
    }

    fn link_parents(&mut self, idx: usize, result: &mut UpdateResult) -> bool {
        let parents = self.entries[idx].as_pending().atom.atoms.clone();

        for h in parents {
            let pidx = self.index.get(&h).copied().unwrap_or_else(|| {
                let idx = self.entries.len();
                self.index.insert(h, idx);
                self.entries.push(Entry::default());
                result.missing.push(h);
                idx
            });

            self.entries[idx].as_pending_mut().parents.insert(pidx);
            self.entries[pidx].add_child(idx);

            if !self.entries[pidx].is_valid() {
                self.entries[idx].as_pending_mut().pending_parent_count += 1;
                continue;
            }

            if !self.on_parent_valid(idx, pidx) {
                return false;
            }
        }

        true
    }

    fn on_parent_valid(&mut self, idx: usize, pidx: usize) -> bool {
        if self.entries[pidx].is_block() {
            self.process_block_parent(idx, pidx)
        } else {
            self.process_basic_parent(idx, pidx);
            true
        }
    }

    fn process_block_parent(&mut self, idx: usize, pidx: usize) -> bool {
        let (cur, parent) = if idx < pidx {
            let (l, r) = self.entries.split_at_mut(pidx);
            (l[idx].as_pending_mut(), r[0].as_block_mut())
        } else {
            let (l, r) = self.entries.split_at_mut(idx);
            (r[0].as_pending_mut(), l[pidx].as_block_mut())
        };

        if !cur.atom.atoms.contains(&parent.atom.hash())
            || cur.block_parent.replace(pidx).is_some()
            || cur.atom.height != parent.atom.height + 1
        {
            return false;
        }

        let keys = cur
            .remaining_inputs
            .extract_if(|_, v| v.is_none())
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        if !parent.trie.resolve(&keys, &cur.witness.trie_proofs) {
            return false;
        }

        cur.input.extend(keys.into_iter().map(|k| {
            let val = parent
                .trie
                .get(k.as_slice())
                .map(|v| C::Value::from_slice(&v).expect("Value must valid"))
                .unwrap_or_default();
            (k, (val, 0))
        }));

        true
    }

    fn process_basic_parent(&mut self, idx: usize, pidx: usize) {
        let block_parent_idx = self.entries[pidx].as_basic().block_parent;

        if self.entries[idx].as_pending().block_parent.is_none() {
            self.process_block_parent(idx, block_parent_idx);
        }

        let (cur, parent) = if idx < pidx {
            let (l, r) = self.entries.split_at_mut(pidx);
            (l[idx].as_pending_mut(), r[0].as_basic_mut())
        } else {
            let (l, r) = self.entries.split_at_mut(idx);
            (r[0].as_pending_mut(), l[pidx].as_basic_mut())
        };

        parent
            .output
            .iter()
            .filter(|(_, (_, ver))| ver != &0)
            .for_each(|(k, (v, ver))| {
                if cur
                    .remaining_inputs
                    .get(k)
                    .is_some_and(|v| v.is_some_and(|c| &c == ver))
                {
                    cur.input.insert(k.clone(), (v.clone(), *ver));
                    cur.remaining_inputs.remove(k);
                }
            });
    }

    fn remove_subgraph(&mut self, idx: usize, result: &mut UpdateResult) {
        let mut stk = vec![idx];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) {
                continue;
            }

            let mut entry = std::mem::take(&mut self.entries[u]);

            let Some(hash) = entry.hash() else {
                continue;
            };

            stk.extend(entry.children_take().into_iter());

            if let Some(parents) = entry
                .as_pending_mut_opt()
                .map(|e| std::mem::take(&mut e.parents))
            {
                parents.into_iter().for_each(|p| {
                    self.entries[p].remove_child(u);
                });
            }

            result.invalidated.push(hash);
            self.index.remove(&hash);
        }
    }

    fn on_all_parent_valid(&mut self, idx: usize, result: &mut UpdateResult) {
        let entry = self.entries[idx].as_pending_mut();

        if entry.block_parent.is_none() || !entry.remaining_inputs.is_empty() {
            self.remove_subgraph(idx, result);
            return;
        }

        let input_raw = std::mem::take(&mut entry.input);

        if let Some(cmd) = &entry.atom.cmd {
            let mut versions = HashMap::new();
            let mut input = HashMap::new();

            input_raw.into_iter().for_each(|(k, (v, ver))| {
                let ver = if ver == 0 { ver } else { ver + 1 };
                input.insert(k.clone(), v);
                versions.insert(k, ver);
            });

            let Ok(output) = cmd.output(input) else {
                self.remove_subgraph(idx, result);
                return;
            };

            output.into_iter().for_each(|(k, v)| {
                let ver = versions.remove(&k).unwrap_or_default();
                entry.output.insert(k, (v, ver));
            });
        }

        self.try_execute(idx);

        let children = self.entries[idx].children().clone();
        children.into_iter().for_each(|cidx| {
            if !self.on_parent_valid(cidx, idx) {
                self.remove_subgraph(cidx, result);
            }
            self.entries[cidx].as_pending_mut().pending_parent_count -= 1;
            if self.entries[cidx].as_pending().pending_parent_count == 0 {
                self.on_all_parent_valid(cidx, result);
            }
        });
    }

    fn try_execute(&mut self, idx: usize) -> bool {
        let mut max: BTreeMap<&Key, &Version> = BTreeMap::new();
        let mut not_specified_state: BTreeMap<&Key, C::Value> = BTreeMap::new();
        let mut specified_state: BTreeMap<&Key, &C::Value> = BTreeMap::new();
        let mut conflicting: HashSet<usize> = HashSet::new();

        let entry = self.entries[idx].as_pending();
        let block_parent = entry.block_parent.expect("Block parent must exist");
        let block_parent_outputs = &self.entries[block_parent].as_block().outputs;

        for idx in entry
            .atom
            .atoms
            .iter()
            .map(|h| *self.index.get(h).expect("Atom must exist"))
            .chain(std::iter::once(idx))
            .filter(|&i| i != block_parent)
        {
            if conflicting.contains(&idx) {
                return false;
            }

            for (k, (v, ver)) in self.entries[idx].as_basic().output.iter() {
                if let Some(con) = block_parent_outputs.get(k).and_then(|vm| vm.get(ver)) {
                    conflicting.extend(con.iter().copied());
                }

                if ver == &0 {
                    let v = not_specified_state
                        .remove(k)
                        .map(|p| self.merge_strategy.merge(k, &p, v))
                        .unwrap_or_else(|| v.clone());
                    not_specified_state.insert(k, v);
                    continue;
                }

                if max.get(k).is_none_or(|o| o < &ver) {
                    max.insert(k, ver);
                    specified_state.insert(k, v);
                }
            }
        }

        if entry.atom.atoms.len() >= self.block_witness_threshold {
            let mut trie = self.entries[block_parent].as_block().trie.clone();

            let iter = specified_state
                .into_iter()
                .map(|(k, v)| (k, v.to_vec()))
                .chain(
                    not_specified_state
                        .into_iter()
                        .map(|(k, v)| (k, v.to_vec())),
                );

            trie.extend(iter);

            let entry = std::mem::take(&mut self.entries[idx]);
            self.entries[idx] = entry.into_block(trie);
        } else {
            let entry = std::mem::take(&mut self.entries[idx]);
            self.entries[idx] = entry.into_basic();
        }

        self.update_weight(idx);
        self.recompute_main_chain_and_checkpoint();

        true
    }

    fn update_weight(&mut self, idx: usize) {
        let mut cur = self.entries[idx]
            .block_parent()
            .expect("Block parent must exist");

        loop {
            if cur == 0 {
                break; // root block
            }

            let entry = self.entries[cur].as_block_mut();
            entry.weight += 1;
            cur = entry.parent;
        }
    }

    fn recompute_main_chain_and_checkpoint(&mut self) {
        let start = self.checkpoint.unwrap_or_default();

        let new_head = self.ghost_select(start);
        self.main_head = Some(new_head);

        self.maybe_advance_checkpoint(new_head);
    }

    fn ghost_select(&self, start: usize) -> usize {
        let mut cur = start;

        while let Some((_, _, next_idx)) = self.entries[cur]
            .children()
            .iter()
            .filter_map(|&idx| {
                self.entries[idx]
                    .as_block_opt()
                    .map(|block| (block.weight, block.atom.hash(), idx))
            })
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
        {
            cur = next_idx;
        }

        cur
    }

    fn maybe_advance_checkpoint(&mut self, head_idx: usize) {
        let head_h = self.entries[head_idx].as_block().atom.height;
        let cur_cp_h = self.checkpoint_height();

        if cur_cp_h == 0 {
            self.checkpoint = Some(head_idx);
            return;
        }

        if head_h - cur_cp_h > self.checkpoint_distance {
            let target_h = head_h.saturating_sub(self.checkpoint_distance as Height);

            let mut cur_idx = head_idx;
            let mut cur = self.entries[cur_idx].as_block();

            while cur.atom.height > target_h {
                cur_idx = cur.parent;
                cur = self.entries[cur.parent].as_block();
            }

            self.checkpoint = Some(cur_idx);
        }
    }
}
