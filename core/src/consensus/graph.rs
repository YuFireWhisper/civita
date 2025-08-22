use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::atomic::AtomicU64,
};

use civita_serialize::Serialize;
use dashmap::DashMap;
use derivative::Derivative;
use parking_lot::RwLock as ParkingLock;

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

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry<C: Command> {
    // Basic information
    pub atom: Atom<C>,
    pub witness: Witness,
    pub public_key: PublicKey,

    // General
    pub block_parent: Option<Multihash>,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PublicKey>,
    pub nonce_used: HashMap<PublicKey, HashSet<Nonce>>,

    // Pending only
    pub pending_parents: u32,
    pub children: HashSet<Multihash>,
    pub max_nonce: Nonce,
    #[derivative(Default(value = "true"))]
    pub is_missing: bool,
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

pub struct NextInfo {
    pub height: Height,
    pub nonce: Nonce,
    pub vdf_difficulty: u64,
    pub parents: HashMap<PublicKey, Multihash>,
    pub unknown_keys: HashSet<Vec<u8>>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Graph<C: Command> {
    entries: DashMap<Multihash, Entry<C>>,

    main_head: ParkingLock<Option<Multihash>>,
    checkpoint: ParkingLock<Option<Multihash>>,

    #[derivative(Default(value = "AtomicU64::new(50000)"))]
    difficulty: AtomicU64,

    config: Config,
}

impl<C: Command> Entry<C> {
    pub fn new(atom: Atom<C>, witness: Witness, pk: PublicKey) -> Self {
        let pending_parents = witness.parents.len() as u32;

        Self {
            atom,
            witness,
            public_key: pk,
            pending_parents,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn hash(&self) -> Multihash {
        self.atom.hash()
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

    pub fn upsert(&self, atom: Atom<C>, witness: Witness, pk: PublicKey) -> UpdateResult {
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

    fn link_parents(&self, hash: Multihash, result: &mut UpdateResult) -> bool {
        let mut cur = self.entries.get_mut(&hash).expect("Entry must exist");
        let parents = cur.witness.parents.values().copied().collect::<Vec<_>>();

        let mut is_valid = true;

        parents.into_iter().for_each(|ph| {
            let mut parent = self.entries.entry(ph).or_insert_with(|| {
                result.missing.push(ph);
                Entry::default()
            });

            if !parent.is_missing && parent.pending_parents == 0 {
                cur.pending_parents -= 1;
                is_valid &= Self::on_parent_valid(&mut cur, &parent);
            } else {
                parent.children.insert(hash);
            }
        });

        is_valid
    }

    fn on_parent_valid(cur: &mut Entry<C>, parent: &Entry<C>) -> bool {
        if !cur.witness.parents.contains_key(&parent.public_key) {
            return false;
        }

        let bp = if parent.is_block {
            if cur.atom.height != parent.atom.height + 1 {
                return false;
            }

            parent.hash()
        } else {
            if cur.atom.height != parent.atom.height || cur.atom.nonce <= parent.atom.nonce {
                return false;
            }

            cur.max_nonce = cur.max_nonce.max(parent.atom.nonce);
            parent.block_parent.expect("Block parent must exist")
        };

        cur.block_parent.replace(bp).is_none_or(|prev| prev == bp)
    }

    fn remove_subgraph(&self, hash: Multihash, result: &mut UpdateResult) {
        let mut stk = vec![hash];
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) {
                continue;
            }

            let Some((_, entry)) = self.entries.remove(&u) else {
                continue;
            };

            let hash = entry.hash();

            if let Some(bp) = &entry.block_parent {
                let mut bp_e = self.entries.get_mut(bp).expect("Block parent must exist");
                bp_e.nonce_used
                    .get_mut(&entry.public_key)
                    .map(|set| set.remove(&entry.atom.nonce));

                if bp_e
                    .nonce_used
                    .get(&entry.public_key)
                    .is_some_and(|set| set.is_empty())
                {
                    bp_e.nonce_used.remove(&entry.public_key);
                }
            }

            stk.extend(entry.children);
            result.invalidated.push(hash);
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

            let (e, mut children) = {
                let mut e = self.entries.get_mut(&h).expect("Entry must exist");
                // We don't need to keep children in the entry anymore
                let c = std::mem::take(&mut e.children);
                (e.downgrade(), c)
            };

            children.drain().for_each(|ch| {
                let mut c = self.entries.get_mut(&ch).expect("Child entry must exist");

                if !Self::on_parent_valid(&mut c, &e) {
                    self.remove_subgraph(ch, result);
                    return;
                }

                c.pending_parents -= 1;
                if c.pending_parents == 0 {
                    queue.push_back(ch);
                }
            });
        }
    }

    fn try_final_validate(&self, hash: &Multihash) -> bool {
        let mut entry = self.entries.get_mut(hash).expect("Entry must exist");

        if entry.atom.nonce != entry.max_nonce + 1 {
            return false;
        }

        let mut bp_e = {
            let Some(bp) = entry.block_parent else {
                return false;
            };

            self.entries.get_mut(&bp).expect("Block parent must exist")
        };

        if !bp_e
            .nonce_used
            .entry(entry.public_key.clone())
            .or_default()
            .insert(entry.atom.nonce)
        {
            // Nonce already used by this publisher
            return false;
        }

        let (order, root_hash) = {
            let order = self.topo_parents(*entry.key(), bp_e.key());
            (order, bp_e.trie.root_hash())
        };

        let (state, publishers) = {
            let mut state = HashMap::new();
            let mut publishers = HashSet::new();

            for h in order.iter().rev() {
                let e = self.entries.get(h).expect("Entry must exist");
                publishers.insert(e.public_key.clone());

                if let Some(cmd) = &e.atom.cmd {
                    let input = self.prepare_command_input(cmd, &e.witness.trie_proofs, root_hash);

                    let Ok(output) = cmd.execute(input) else {
                        return false;
                    };

                    state.extend(output);
                }
            }

            (state, publishers)
        };

        let atom_count = order.len() as u32;

        if atom_count >= self.config.block_threshold {
            let mut trie = bp_e.trie.clone();
            trie.extend(state.into_iter().map(|(k, v)| (k, v.to_vec())));
            entry.is_block = true;
            entry.trie = trie;

            let bp = *bp_e.key();

            drop(bp_e);
            drop(entry);

            self.update_publishers(bp, &publishers);
            self.recompute_main_chain_and_checkpoint();
        }

        true
    }

    fn topo_parents(&self, hash: Multihash, bp: &Multihash) -> Vec<Multihash> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut heap = BinaryHeap::new();

        queue.push_back(hash);
        visited.insert(hash);

        while let Some(h) = queue.pop_front() {
            if &h == bp {
                continue;
            }

            let e = self.entries.get(&h).expect("Entry must exist");

            heap.push(Reverse((e.atom.nonce, h)));
            queue.extend(e.witness.parents.values().filter(|&&p| visited.insert(p)));
        }

        heap.into_sorted_vec()
            .into_iter()
            .map(|Reverse((_, idx))| idx)
            .collect()
    }

    fn prepare_command_input(
        &self,
        cmd: &C,
        proof: &HashMap<Multihash, Vec<u8>>,
        trie_root: Multihash,
    ) -> HashMap<Vec<u8>, C::Value> {
        cmd.keys()
            .into_iter()
            .map(|k| {
                let value = Trie::verify_proof(trie_root, &k, proof)
                    .expect("Proof should be valid")
                    .map(|v| C::Value::from_slice(&v).expect("Value should be valid"))
                    .unwrap_or_default();
                (k, value)
            })
            .collect()
    }

    fn update_publishers(&self, mut cur: Multihash, publishers: &HashSet<PublicKey>) {
        let cp = *self.checkpoint.read();

        loop {
            let mut e = self.entries.get_mut(&cur).expect("Entry must exist");
            e.publishers.extend(publishers.iter().cloned());

            if cp.is_some_and(|cp| cp == cur) {
                break;
            }

            let Some(next) = e.block_parent else {
                break;
            };

            cur = next;
        }
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
            .map(|h| {
                let c = self.entries.get(h).expect("Child entry must exist");
                (c.publishers.len(), h)
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
            .expect("Entry must exist")
            .atom
            .height;

        let n = self.config.checkpoint_distance as Height;
        debug_assert!(n > 0);

        let head_div = head_height / n;
        if head_div < 2 {
            return;
        }

        let desired_cp_height = (head_div - 1) * n;

        let checkpoint_height = self.checkpoint_height();
        if checkpoint_height >= desired_cp_height {
            return;
        }

        let mut cur = self.entries.get(&head_hash).expect("Entry must exist");
        while cur.atom.height > desired_cp_height {
            let next = &cur.block_parent.expect("Block parent must exist");
            cur = self.entries.get(next).expect("Entry must exist");
        }

        debug_assert_eq!(cur.atom.height, desired_cp_height);
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

            let dt = cur_e.atom.timestamp.saturating_sub(p_e.atom.timestamp);

            if dt > 0 {
                times.push(dt);
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

    pub fn next_info(&self, mut keys: HashSet<Vec<u8>>) -> Option<NextInfo> {
        let head = *self.main_head.read().as_ref()?;

        let (parents, nonce) = self.get_subgraph_leaves_and_nonce(&head);
        let (height, unknown_keys) = {
            let e = self.entries.get(&head).expect("Main head entry must exist");
            keys.retain(|k| e.trie.get(k.as_ref()).is_none());
            (e.atom.height + 1, keys)
        };

        Some(NextInfo {
            height,
            nonce,
            vdf_difficulty: self.difficulty(),
            parents,
            unknown_keys,
        })
    }

    fn get_subgraph_leaves_and_nonce(
        &self,
        root: &Multihash,
    ) -> (HashMap<PublicKey, Multihash>, Nonce) {
        let mut stk: Vec<_> = self
            .entries
            .get(root)
            .expect("Main head must exist")
            .children
            .iter()
            .copied()
            .filter(|ch| {
                let e = self.entries.get(ch).expect("Child entry must exist");
                !e.is_missing && !e.is_block
            })
            .collect();

        if stk.is_empty() {
            return (HashMap::new(), Nonce::default());
        }

        let mut result: HashMap<PublicKey, (Nonce, Multihash)> = HashMap::new();
        let mut max_nonce = Nonce::default();
        let mut visited = HashSet::new();

        while let Some(u) = stk.pop() {
            if !visited.insert(u) || !self.is_leaf_and_enqueue(&u, &mut stk) {
                continue;
            }

            let (pk, nonce) = {
                let e = self.entries.get(&u).expect("Entry must exist");
                (e.public_key.clone(), e.atom.nonce)
            };

            max_nonce = max_nonce.max(nonce);

            result
                .entry(pk)
                .and_modify(|(best_nonce, best_hash)| {
                    if nonce > *best_nonce {
                        *best_nonce = nonce;
                        *best_hash = u;
                    }
                })
                .or_insert((nonce, u));
        }

        (
            result.into_iter().map(|(pk, (_, h))| (pk, h)).collect(),
            max_nonce,
        )
    }

    fn is_leaf_and_enqueue(&self, hash: &Multihash, stk: &mut Vec<Multihash>) -> bool {
        self.entries
            .get(hash)
            .expect("Entry must exist")
            .children
            .iter()
            .filter(|ch| {
                let ce = self.entries.get(ch).expect("Child entry must exist");
                !ce.is_missing && !ce.is_block
            })
            .inspect(|c| stk.push(**c))
            .count()
            == 0
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn next_height(&self) -> Height {
        self.main_head
            .read()
            .and_then(|h| self.entries.get(&h))
            .map_or(0, |e| e.atom.height + 1)
    }

    pub fn unknow_keys(&self, mut keys: HashSet<Vec<u8>>) -> HashSet<Vec<u8>> {
        let head = {
            let g = self.main_head.read();
            let Some(h) = g.as_ref() else {
                return keys;
            };
            self.entries.get(h).expect("Main head entry must exist")
        };

        keys.retain(|k| head.trie.get(k.as_ref()).is_none());

        keys
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

    pub fn get_vec(&self, hash: &Multihash) -> Option<Vec<u8>> {
        self.entries.get(hash).and_then(|entry| {
            if entry.is_missing {
                None
            } else {
                let mut buf = Vec::new();
                entry.atom.to_writer(&mut buf);
                entry.witness.to_writer(&mut buf);
                entry.public_key.to_writer(&mut buf);
                Some(buf)
            }
        })
    }
}
