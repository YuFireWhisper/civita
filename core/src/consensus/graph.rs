use std::collections::{BTreeMap, HashMap, HashSet};

use civita_serialize::Serialize;
use derivative::Derivative;

use crate::{
    crypto::Multihash,
    ty::atom::{Atom, Command, Height, Key, MergeStrategy, Version, Witness},
    utils::Trie,
};

#[derive(Clone)]
#[derive(Default)]
pub struct UpdateResult {
    pub invalidated: Vec<Multihash>,
    pub missing: Vec<Multihash>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry<C: Command> {
    atom: Option<Atom<C>>,
    witness: Option<Witness>,

    trie: Option<Trie>,

    remaining_input: HashMap<Key, Option<Version>>,
    input: HashMap<Key, (C::Value, Version)>,
    output: HashMap<Key, (C::Value, Version)>,

    existing: HashSet<(Key, Version)>,

    parents: HashSet<usize>,
    children: HashSet<usize>,
    block_parent: Option<usize>,

    pending_parent_count: usize,
    weight: usize,
}

pub struct Graph<C: Command, M: MergeStrategy<C::Value>> {
    index: HashMap<Multihash, usize>,
    entries: Vec<Entry<C>>,

    main_head: Option<usize>,
    checkpoint: Option<usize>,

    block_witness_threshold: usize,
    checkpoint_distance: usize,

    merge_strategy: M,
}

impl<C: Command> Entry<C> {
    pub fn new(atom: Atom<C>, witness: Witness) -> Self {
        let remaining_input = atom.cmd.as_ref().map(|c| c.input()).unwrap_or_default();

        Self {
            atom: Some(atom),
            witness: Some(witness),
            remaining_input,
            ..Default::default()
        }
    }

    pub fn atom_unchecked(&self) -> &Atom<C> {
        self.atom.as_ref().expect("Entry must have atom")
    }

    pub fn hash(&self) -> Multihash {
        self.atom_unchecked().hash()
    }
}

impl<C: Command, M: MergeStrategy<C::Value>> Graph<C, M> {
    pub fn new(
        merge_strategy: M,
        block_witness_threshold: usize,
        checkpoint_distance: usize,
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

        if self.entries[idx].pending_parent_count == 0 {
            self.on_all_parent_valid(idx, &mut result);
        }

        result
    }

    fn checkpoint_height(&self) -> Height {
        self.checkpoint
            .map(|i| self.entries[i].atom_unchecked().height)
            .unwrap_or(0)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.index
            .get(h)
            .and_then(|&i| self.entries.get(i))
            .is_some_and(|e| e.atom.is_some())
    }

    fn insert_entry(&mut self, atom: Atom<C>, witness: Witness) -> usize {
        let idx = self.entries.len();
        self.index.insert(atom.hash(), idx);
        let entry = Entry::new(atom, witness);
        debug_assert!(self.validate_entry_inputs(&entry));
        self.entries.push(entry);
        idx
    }

    fn validate_entry_inputs(&self, entry: &Entry<C>) -> bool {
        entry.remaining_input.is_empty()
            || entry
                .remaining_input
                .iter()
                .all(|(k, v)| self.merge_strategy.is_mergeable(k) == v.is_none())
    }

    fn link_parents(&mut self, idx: usize, result: &mut UpdateResult) -> bool {
        let parents = self.entries[idx].atom_unchecked().atoms.clone();

        parents.into_iter().all(|h| {
            let pidx = self.index.get(&h).copied().unwrap_or_else(|| {
                let idx = self.entries.len();
                self.index.insert(h, idx);
                self.entries.push(Entry::default());
                result.missing.push(h);
                idx
            });

            self.entries[idx].parents.insert(pidx);
            self.entries[pidx].children.insert(idx);

            if self.entries[pidx].pending_parent_count != 0 {
                self.entries[pidx].pending_parent_count += 1;
                true
            } else {
                self.on_parent_valid(idx, pidx)
            }
        })
    }

    fn on_parent_valid(&mut self, idx: usize, pidx: usize) -> bool {
        if self.entries[pidx].trie.is_some() {
            self.process_block_parent(idx, pidx)
        } else {
            self.process_basic_parent(idx, pidx)
        }
    }

    fn process_block_parent(&mut self, idx: usize, pidx: usize) -> bool {
        if self.entries[idx].block_parent.replace(pidx).is_some() {
            return false;
        }

        if self.entries[idx].atom_unchecked().height
            != self.entries[pidx].atom_unchecked().height + 1
        {
            return false;
        }

        let (cur, parent) = if idx < pidx {
            let (l, r) = self.entries.split_at_mut(pidx);
            (&mut l[idx], &mut r[0])
        } else {
            let (l, r) = self.entries.split_at_mut(idx);
            (&mut r[0], &mut l[pidx])
        };

        let trie = parent.trie.as_mut().expect("Parent must have a trie");
        let keys = cur
            .remaining_input
            .extract_if(|_, v| v.is_none())
            .map(|(k, _)| k)
            .collect::<Vec<_>>();
        let proofs = &cur.witness.as_mut().unwrap().trie_proofs;

        if !trie.resolve(&keys, proofs) {
            return false;
        }

        cur.input.extend(keys.into_iter().map(|k| {
            let val = trie
                .get(k.as_slice())
                .map(|v| C::Value::from_slice(&v).expect("Value must valid"))
                .unwrap_or_default();
            (k, (val, 0))
        }));

        true
    }

    fn process_basic_parent(&mut self, idx: usize, pidx: usize) -> bool {
        let (cur, parent) = if idx < pidx {
            let (l, r) = self.entries.split_at_mut(pidx);
            (&mut l[idx], &mut r[0])
        } else {
            let (l, r) = self.entries.split_at_mut(idx);
            (&mut r[0], &mut l[pidx])
        };

        parent
            .output
            .iter()
            .filter(|(_, (_, ver))| ver != &0)
            .all(|(k, (v, ver))| {
                if !cur.existing.insert((k.clone(), *ver)) {
                    return false;
                }

                if cur
                    .remaining_input
                    .get(k)
                    .is_some_and(|v| v.is_some_and(|c| &c == ver))
                {
                    cur.input.insert(k.clone(), (v.clone(), *ver));
                    cur.remaining_input.remove(k);
                }

                true
            })
    }

    fn remove_subgraph(&mut self, idx: usize, result: &mut UpdateResult) {
        let mut stk = vec![idx];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) {
                continue;
            }

            let entry = std::mem::take(&mut self.entries[u]);
            let hash = entry.atom_unchecked().hash();

            stk.extend(entry.children.into_iter());
            entry.parents.into_iter().for_each(|p| {
                self.entries[p].children.remove(&u);
            });

            result.invalidated.push(hash);
            self.index.remove(&hash);
        }
    }

    fn on_all_parent_valid(&mut self, idx: usize, result: &mut UpdateResult) {
        let entry = &mut self.entries[idx];

        if entry.block_parent.is_none() {
            self.remove_subgraph(idx, result);
            return;
        }

        if !entry.remaining_input.is_empty() {
            self.remove_subgraph(idx, result);
            return;
        }

        let input_raw = std::mem::take(&mut entry.input);

        if let Some(cmd) = &entry.atom_unchecked().cmd {
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

        let children = self.entries[idx].children.clone();
        children.iter().for_each(|&cidx| {
            if !self.on_parent_valid(cidx, idx) {
                self.remove_subgraph(cidx, result);
            }
            self.entries[cidx].pending_parent_count -= 1;
            if self.entries[cidx].pending_parent_count == 0 {
                self.on_all_parent_valid(cidx, result);
            }
        });
    }

    fn try_execute(&mut self, idx: usize) {
        let mut max: BTreeMap<&Key, &Version> = BTreeMap::new();
        let mut not_specified_state: BTreeMap<&Key, C::Value> = BTreeMap::new();
        let mut specified_state: BTreeMap<&Key, &C::Value> = BTreeMap::new();

        self.entries[idx]
            .atom_unchecked()
            .atoms
            .iter()
            .map(|h| *self.index.get(h).expect("Atom must exist"))
            .chain(std::iter::once(idx))
            .for_each(|idx| {
                self.entries[idx].output.iter().for_each(|(k, (v, ver))| {
                    if ver == &0 {
                        let v = not_specified_state
                            .remove(k)
                            .map(|p| self.merge_strategy.merge(k, &p, v))
                            .unwrap_or_else(|| v.clone());
                        not_specified_state.insert(k, v);
                    } else if max.get(k).is_none_or(|o| o < &ver) {
                        max.insert(k, ver);
                        specified_state.insert(k, v);
                    } else {
                        // nothing
                    }
                });
            });

        if self.entries[idx].atom_unchecked().atoms.len() < self.block_witness_threshold {
            return;
        }

        let parent_idx = self.entries[idx]
            .block_parent
            .expect("Block parent must exist");

        let mut trie = self.entries[parent_idx]
            .trie
            .as_ref()
            .expect("Parent trie must exist")
            .clone();

        let iter = specified_state
            .into_iter()
            .map(|(k, v)| (k, v.to_vec()))
            .chain(
                not_specified_state
                    .into_iter()
                    .map(|(k, v)| (k, v.to_vec())),
            );

        trie.extend(iter);

        self.entries[idx].trie = Some(trie);
        self.update_weight(idx);
        self.recompute_main_chain_and_checkpoint(idx);
    }

    fn update_weight(&mut self, idx: usize) {
        let is_block = self.entries[idx].trie.is_some();

        let mut cur = if is_block {
            Some(idx)
        } else {
            self.entries[idx].block_parent
        };

        while let Some(i) = cur {
            self.entries[i].weight += 1;
            cur = self.entries[i].block_parent;
        }
    }

    fn recompute_main_chain_and_checkpoint(&mut self, last_updated: usize) {
        let start = self
            .checkpoint
            .as_ref()
            .map_or(self.root_of(last_updated), |cp| *cp);

        let new_head = self.ghost_select(start);
        self.main_head = Some(new_head);

        self.maybe_advance_checkpoint(new_head);
    }

    fn root_of(&self, mut i: usize) -> usize {
        while let Some(p) = self.entries[i].block_parent {
            i = p;
        }
        i
    }

    fn ghost_select(&self, start: usize) -> usize {
        let mut cur = start;
        loop {
            let mut best: Option<(usize, Multihash, usize)> = None; // (weight, hash, idx)

            for &child in &self.entries[cur].children {
                if self.entries[child].trie.is_some()
                    && self.entries[child].block_parent == Some(cur)
                {
                    let w = self.entries[child].weight;
                    let h = self.entries[child].hash();
                    match &mut best {
                        None => best = Some((w, h, child)),
                        Some((bw, bh, bi)) => {
                            if w > *bw || (w == *bw && h < *bh) {
                                *bw = w;
                                *bh = h;
                                *bi = child;
                            }
                        }
                    }
                }
            }

            if let Some((_, _, nxt)) = best {
                cur = nxt;
            } else {
                break;
            }
        }
        cur
    }

    fn maybe_advance_checkpoint(&mut self, head_idx: usize) {
        let head_h = self.entries[head_idx].atom_unchecked().height;
        let cur_cp_h = self.checkpoint_height();

        if head_h > cur_cp_h && (head_h - cur_cp_h) as usize > self.checkpoint_distance {
            let target_h = head_h.saturating_sub(self.checkpoint_distance as Height);

            let mut cur = head_idx;
            while self.entries[cur].atom_unchecked().height > target_h {
                cur = self.entries[cur]
                    .block_parent
                    .expect("Block parent must exist while seeking checkpoint");
            }

            self.checkpoint = Some(cur);
        }
    }
}
