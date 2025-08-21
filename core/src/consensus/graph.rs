use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::atomic::AtomicU64,
};

use civita_serialize::Serialize;
use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap,
};
use derivative::Derivative;
use parking_lot::RwLock as ParkingLock;

use crate::{
    crypto::{Multihash, PublicKey},
    ty::atom::{Atom, Command, Height, Nonce, Witness},
    utils::Trie,
};

type RefMutEntry<'a, C> = RefMut<'a, Multihash, Entry<C>>;
type RefEntry<'a, C> = Ref<'a, Multihash, Entry<C>>;

#[derive(Clone)]
#[derive(Default)]
pub struct UpdateResult {
    pub invalidated: Vec<Multihash>,
    pub missing: Vec<Multihash>,
}

struct BlockStats {
    trie: Trie,
    distinct_publishers: u32,
    cmd_count: u32,
    atom_count: u32,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry<C: Command> {
    pub atom: Atom<C>,
    pub witness: Witness,
    pub public_key: PublicKey,

    pub block_stats: Option<BlockStats>,

    pub block_parent: Option<Multihash>,
    pub parents: HashSet<Multihash>,
    pub children: HashSet<Multihash>,

    pub pending_parents: usize,
    pub max_nonce: Nonce,

    #[derivative(Default(value = "true"))]
    pub is_missing: bool,
}

struct AtomExecuter<C: Command> {
    state: HashMap<Vec<u8>, C::Value>,
    publishers: HashSet<PublicKey>,
    cmd_count: u32,
    atom_count: u32,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    #[derivative(Default(value = "1000"))]
    pub block_threshold: u32,

    #[derivative(Default(value = "10"))]
    pub checkpoint_distance: u32,

    #[derivative(Default(value = "60_000"))]
    pub target_block_time_ms: u64,

    #[derivative(Default(value = "50000"))]
    pub init_vdf_difficulty: u64,

    #[derivative(Default(value = "0.1"))]
    pub max_difficulty_adjustment: f32,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Graph<C: Command> {
    entries: DashMap<Multihash, Entry<C>>,
    nonce_used: DashMap<Multihash, HashMap<PublicKey, HashSet<Nonce>>>,

    main_head: ParkingLock<Option<Multihash>>,
    checkpoint: ParkingLock<Option<Multihash>>,

    #[derivative(Default(value = "AtomicU64::new(50000)"))]
    difficulty: AtomicU64,

    config: Config,
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
        I: IntoIterator<Item = RefEntry<'a, C>>,
    {
        order
            .into_iter()
            .all(|entry| self.execute_single(entry, trie_root))
    }

    fn execute_single(&mut self, entry: RefEntry<C>, trie_root: Multihash) -> bool {
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
            distinct_publishers: self.publishers.len() as u32,
            cmd_count: self.cmd_count,
            atom_count: self.atom_count,
        }
    }
}

impl<C: Command> Graph<C> {
    pub fn new(config: Config) -> Self {
        Self {
            difficulty: AtomicU64::new(config.init_vdf_difficulty),
            config,
            ..Default::default()
        }
    }

    pub fn upsert(&mut self, atom: Atom<C>, witness: Witness, pk: PublicKey) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if self.contains(&hash) || atom.height <= self.checkpoint_height() {
            return result;
        }

        self.entries.insert(hash, Entry::new(atom, witness, pk));

        if !self.link_parents(hash, &mut result) {
            self.remove_subgraph(hash, &mut result);
            return result;
        }

        if self.entries.get(&hash).unwrap().pending_parents == 0 {
            self.on_all_parent_valid(hash, &mut result);
        }

        result
    }

    fn checkpoint_height(&self) -> Height {
        self.checkpoint
            .read()
            .map(|h| self.entries.get(&h).unwrap().atom.height)
            .unwrap_or(0)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn link_parents(&mut self, hash: Multihash, result: &mut UpdateResult) -> bool {
        let mut cur = self.entries.get_mut(&hash).expect("Entry must exist");
        let parents = cur.witness.parents.values().copied().collect::<Vec<_>>();

        let mut is_valid = true;

        parents.into_iter().for_each(|ph| {
            let mut parent = self.entries.entry(ph).or_insert_with(|| {
                result.missing.push(ph);
                Entry::default()
            });

            cur.parents.insert(ph);
            parent.children.insert(hash);

            if !parent.is_missing && parent.pending_parents == 0 {
                is_valid &= Self::on_parent_valid(&mut cur, &parent.downgrade());
            } else {
                cur.pending_parents += 1;
            }
        });

        is_valid
    }

    fn on_parent_valid(cur: &mut RefMutEntry<C>, parent: &RefEntry<C>) -> bool {
        if cur.atom.height != parent.atom.height + 1
            || !cur.witness.parents.contains_key(&parent.public_key)
        {
            return false;
        }

        if parent.block_stats.is_none() {
            if cur.atom.nonce <= parent.atom.nonce {
                return false;
            }
            cur.value_mut().max_nonce = cur.max_nonce.max(parent.atom.nonce);
        }

        let bp = if parent.block_stats.is_some() {
            *parent.key()
        } else {
            parent.block_parent.expect("Block parent must exist")
        };

        cur.block_parent.replace(bp).is_none_or(|pre| pre == bp)
    }

    fn remove_subgraph(&self, hash: Multihash, result: &mut UpdateResult) {
        let mut stk = vec![hash];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) {
                continue;
            }

            let Some((_, mut entry)) = self.entries.remove(&u) else {
                continue;
            };

            let hash = entry.hash();

            if !entry.is_missing {
                if let Some(bp) = &entry.block_parent {
                    self.remove_nonce(bp, &entry.public_key, &entry.atom.nonce);
                }
            }

            stk.extend(entry.children);
            entry
                .parents
                .drain()
                .filter_map(|h| self.entries.get_mut(&h))
                .for_each(|mut p| {
                    p.children.remove(&hash);
                });

            result.invalidated.push(hash);
        }
    }

    fn remove_nonce(&self, bp: &Multihash, public_key: &PublicKey, nonce: &Nonce) {
        let Some(mut pks) = self.nonce_used.get_mut(bp) else {
            return;
        };

        let Some(set) = pks.get_mut(public_key) else {
            return;
        };

        set.remove(nonce);

        if set.is_empty() {
            pks.remove(public_key);
        }

        if pks.is_empty() {
            self.nonce_used.remove(bp);
        }
    }

    fn on_all_parent_valid(&self, hash: Multihash, result: &mut UpdateResult) {
        let mut queue = VecDeque::new();
        queue.push_back(hash);

        while let Some(h) = queue.pop_front() {
            if !self.try_final_validate(&h) {
                self.remove_subgraph(h, result);
                continue;
            }

            let e = self.entries.get(&h).expect("Entry must exist");

            e.children.iter().for_each(|ch| {
                let mut c = self.entries.get_mut(ch).expect("Child entry must exist");

                if !Self::on_parent_valid(&mut c, &e) {
                    self.remove_subgraph(*ch, result);
                    return;
                }

                c.pending_parents -= 1;
                if c.pending_parents == 0 {
                    queue.push_back(*ch);
                }
            });
        }
    }

    fn try_final_validate(&self, hash: &Multihash) -> bool {
        let mut entry = self.entries.get_mut(hash).expect("Entry must exist");

        if entry.atom.nonce != entry.max_nonce + 1 {
            return false;
        }

        let Some(bp) = entry.block_parent else {
            return false;
        };

        let exist = !self
            .nonce_used
            .entry(bp)
            .or_default()
            .entry(entry.public_key.clone())
            .or_default()
            .insert(entry.atom.nonce);

        if exist {
            return false;
        }

        let (order, root_hash) = {
            let bp_e = self.entries.get(&bp).expect("Block parent must exist");
            let order = self.topo_parents(*entry.key());
            let stats = bp_e.block_stats.as_ref().expect("Block stats must exist");
            (order, stats.trie.root_hash())
        };

        let mut executer = AtomExecuter::new();
        if !executer.execute(
            order
                .into_iter()
                .rev()
                .map(|h| self.entries.get(&h).expect("Entry must exist")),
            root_hash,
        ) {
            return false;
        }

        if executer.atom_count >= self.config.block_threshold {
            let trie = {
                let bp_e = self.entries.get(&bp).expect("Block parent must exist");
                bp_e.block_stats
                    .as_ref()
                    .expect("Block stats must exist")
                    .trie
                    .clone()
            };
            let block_stats = executer.into_block_stats(trie);
            entry.block_stats = Some(block_stats);
        }

        self.recompute_main_chain_and_checkpoint();

        true
    }

    fn topo_parents(&self, hash: Multihash) -> Vec<Multihash> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut heap = BinaryHeap::new();

        queue.push_back(hash);
        visited.insert(hash);

        while let Some(h) = queue.pop_front() {
            let e = self.entries.get(&h).expect("Entry must exist");
            if e.block_stats.is_some() {
                continue;
            }

            heap.push(Reverse((e.atom.nonce, h)));
            queue.extend(e.parents.iter().filter(|&&p| visited.insert(p)));
        }

        heap.into_sorted_vec()
            .into_iter()
            .map(|Reverse((_, idx))| idx)
            .collect()
    }

    fn recompute_main_chain_and_checkpoint(&self) {
        debug_assert!(!self.entries.is_empty());

        if self.entries.len() == 1 {
            let h = *self.entries.iter().next().unwrap().key();
            self.main_head.write().replace(h);
            self.checkpoint.write().replace(h);
            return;
        }

        let start = self.checkpoint.read().unwrap();
        let new_head = self.ghost_select(start);
        self.main_head.write().replace(new_head);
        self.maybe_advance_checkpoint(new_head, start);
    }

    fn ghost_select(&self, start: Multihash) -> Multihash {
        let mut cur = start;

        while let Some(next) = self
            .entries
            .get(&cur)
            .expect("Entry must exist")
            .children
            .iter()
            .filter_map(|h| {
                let c = self.entries.get(h).expect("Child entry must exist");
                let stats = c.block_stats.as_ref()?;
                Some((
                    stats.distinct_publishers,
                    stats.cmd_count,
                    stats.atom_count,
                    h,
                ))
            })
            .max()
            .map(|(.., h)| h)
        {
            cur = *next;
        }

        cur
    }

    fn maybe_advance_checkpoint(&self, head_hash: Multihash, old_cp: Multihash) {
        let head_height = self
            .entries
            .get(&head_hash)
            .expect("Head entry must exist")
            .atom
            .height;
        let checkpoint_height = self.checkpoint_height();

        if head_height - checkpoint_height <= self.config.checkpoint_distance {
            return;
        }

        let target_h = head_height.saturating_sub(self.config.checkpoint_distance);
        let mut cur = self.entries.get(&head_hash).expect("Entry must exist");

        while cur.atom.height > target_h {
            let next = &cur.block_parent.expect("Block parent must exist");
            cur = self.entries.get(next).expect("Entry must exist");
        }

        let new_cp = *cur.key();

        self.checkpoint.write().replace(new_cp);
        self.adjust_difficulty(old_cp, new_cp);
    }

    fn adjust_difficulty(&self, prev_cp: Multihash, new_cp: Multihash) {
        use std::sync::atomic::Ordering;

        let mut times: Vec<u64> = Vec::new();
        let mut cur = new_cp;

        while cur != prev_cp {
            let cur_e = self.entries.get(&cur).expect("Entry must exist");
            cur = cur_e.block_parent.expect("Block parent must exist");
            let p_e = self.entries.get(&cur).expect("Parent entry must exist");

            if cur_e.block_stats.is_some() && p_e.block_stats.is_some() {
                let dt = cur_e.atom.timestamp.saturating_sub(p_e.atom.timestamp);
                if dt > 0 {
                    times.push(dt);
                }
            }
        }

        if times.is_empty() {
            return;
        }

        times.sort_unstable();

        let median = times[times.len() / 2] as f32;
        let target = self.config.target_block_time_ms as f32;

        if median == 0.0 {
            return;
        }

        let ratio_raw = target / median;
        let ratio = ratio_raw.clamp(
            1.0 / self.config.max_difficulty_adjustment,
            self.config.max_difficulty_adjustment,
        );

        let old = self.difficulty.load(Ordering::Relaxed) as f32;
        let new = ((old * ratio) as u64).max(1);

        self.difficulty.store(new, Ordering::Relaxed);
    }

    pub fn subgraph_leaves(&self) -> Option<HashMap<PublicKey, Multihash>> {
        let mut stk: Vec<_> = self
            .entries
            .get(self.main_head.read().as_ref()?)
            .expect("Main head must exist")
            .children
            .iter()
            .copied()
            .filter(|ch| {
                let e = self.entries.get(ch).expect("Child entry must exist");
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

            let e = self.entries.get(&u).expect("Entry must exist");

            let is_leaf = e
                .children
                .iter()
                .filter(|ch| {
                    let ce = self.entries.get(ch).expect("Child entry must exist");
                    !ce.is_missing && ce.block_stats.is_none()
                })
                .inspect(|c| stk.push(**c))
                .count()
                == 0;

            if !is_leaf {
                let pk = e.public_key.clone();
                let nonce = e.atom.nonce;
                let h = *e.key();

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

    pub fn get_clone(&self, h: &Multihash) -> Option<(Atom<C>, Witness, PublicKey)> {
        self.entries.get(h).and_then(|entry| {
            if entry.is_missing {
                None
            } else {
                Some((
                    entry.atom.clone(),
                    entry.witness.clone(),
                    entry.public_key.clone(),
                ))
            }
        })
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty.load(std::sync::atomic::Ordering::Relaxed)
    }
}
