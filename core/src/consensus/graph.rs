use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::atomic::AtomicU64,
};

use civita_serialize::Serialize;
use dashmap::DashMap;
use derivative::Derivative;
use libp2p::PeerId;
use parking_lot::RwLock as ParkingLock;

use crate::{
    consensus::validator::Validator,
    crypto::{hasher::Hasher, Multihash},
    ty::{
        atom::{Atom, Height, Witness},
        token::Token,
    },
    utils::Trie,
};

#[derive(Clone)]
#[derive(Default)]
pub struct UpdateResult {
    pub invalidated: Vec<PeerId>,
    pub missing: Vec<Multihash>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    // Basic information
    pub atom: Atom,
    pub witness: Witness,

    // General
    pub block_parent: Option<Multihash>,
    pub children: HashSet<Multihash>,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PeerId>,

    // Pending only
    pub pending_parents: u32,
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

    /// Keys to retain in the trie at checkpoint.
    /// If `None`, all keys will be retained.
    /// If `Some`, only the keys in the vector will be retained.
    pub retain_keys: Option<Vec<Vec<u8>>>,
}

pub struct Graph<V> {
    entries: DashMap<Multihash, Entry>,

    main_head: ParkingLock<Multihash>,
    checkpoint: ParkingLock<Multihash>,

    difficulty: AtomicU64,

    config: Config,

    _marker: std::marker::PhantomData<V>,
}

impl Entry {
    pub fn new(atom: Atom, witness: Witness) -> Self {
        let pending_parents = witness.atoms.len() as u32;

        Self {
            atom,
            witness,
            pending_parents,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn genesis() -> Self {
        Self {
            is_block: true,
            trie: Trie::default(),
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn hash(&self) -> Multihash {
        self.atom.hash()
    }
}

impl<V: Validator> Graph<V> {
    pub fn upsert(&self, atom: Atom, witness: Witness) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if self.contains(&hash) || atom.height <= self.checkpoint_height() {
            return result;
        }

        self.entries.insert(hash, Entry::new(atom, witness));

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
        self.entries
            .get(&self.checkpoint.read())
            .map_or(0, |e| e.atom.height)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn link_parents(&self, hash: Multihash, result: &mut UpdateResult) -> bool {
        let mut cur = self.entries.get_mut(&hash).expect("Entry must exist");

        if cur.witness.atoms.is_empty() {
            // At least contain one parent(block parent)
            return false;
        }

        if cur.witness.atoms.contains(&hash) {
            return false;
        }

        let parents = cur.witness.atoms.clone();
        parents
            .into_iter()
            .map(|h| {
                self.entries.entry(h).or_insert_with(|| {
                    result.missing.push(h);
                    Entry::default()
                })
            })
            .all(|mut p| {
                p.children.insert(hash);

                if p.is_missing && p.pending_parents == 0 {
                    cur.pending_parents -= 1;
                    Self::on_parent_valid(&mut cur, &p)
                } else {
                    p.children.insert(hash);
                    true
                }
            })
    }

    fn on_parent_valid(cur: &mut Entry, parent: &Entry) -> bool {
        let bp = if parent.is_block {
            if cur.atom.height != parent.atom.height + 1 {
                return false;
            }

            parent.hash()
        } else {
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

            stk.extend(entry.children);

            if !entry.is_missing {
                result.invalidated.push(entry.atom.peer);
            }
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

            let entry = self.entries.get(&h).expect("Entry must exist");

            entry.children.iter().for_each(|ch| {
                let mut c = self.entries.get_mut(ch).expect("Child entry must exist");

                if !Self::on_parent_valid(&mut c, &entry) {
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
        let (bp, count) = {
            let e = self.entries.get(hash).expect("Entry must exist");
            let bp = e.block_parent.expect("Block parent must exist");
            let count = e.witness.atoms.len() as u32;
            (bp, count)
        };

        let mut bp_e = self.entries.get_mut(&bp).expect("Block parent must exist");
        let trie = &mut bp_e.trie;

        let parents_order = self.topo_parents(*hash);
        let mut state = HashMap::new();
        let mut publishers = HashSet::new();

        if !parents_order
            .iter()
            .all(|h| self.execute_atom(h, trie, &mut state, &mut publishers, true))
        {
            return false;
        }

        if !self.execute_atom(hash, trie, &mut state, &mut publishers, false) {
            return false;
        }

        if count >= self.config.block_threshold {
            let mut trie = trie.clone();
            trie.update(
                state
                    .into_iter()
                    .map(|(k, v)| (k.to_vec(), v.map(|t| t.to_vec()))),
            );

            let mut e = self.entries.get_mut(&bp).expect("Entry must exist");
            e.is_block = true;
            e.trie = trie;

            drop(e);
            drop(bp_e);

            self.update_publishers(bp, &publishers);
            self.recompute_main_chain_and_checkpoint();
        }

        true
    }

    fn topo_parents(&self, hash: Multihash) -> Vec<Multihash> {
        let hashes = {
            let e = self.entries.get(&hash).expect("Entry must exist");
            let bp = e.block_parent.unwrap();
            let mut atoms = e.witness.atoms.clone();
            atoms.remove(&bp);
            atoms
        };

        if hashes.is_empty() {
            return Vec::new();
        }

        let (mut indeg, adj) = hashes.iter().fold(
            (HashMap::<_, u32>::new(), HashMap::<_, Vec<_>>::new()),
            |(mut indeg, mut adj), &h| {
                self.entries
                    .get(&h)
                    .expect("Entry must exist")
                    .witness
                    .atoms
                    .iter()
                    .filter(|p| hashes.contains(p))
                    .for_each(|p| {
                        *indeg.entry(h).or_default() += 1;
                        adj.entry(*p).or_default().push(h);
                    });
                (indeg, adj)
            },
        );

        let key = |x: Multihash| {
            let h = self.entries.get(&x).expect("Entry must exist").atom.height;
            (h, x)
        };

        let mut topo = Vec::with_capacity(hashes.len());
        let mut heap = BinaryHeap::from_iter(
            indeg
                .iter()
                .filter(|(_, d)| d == &&0)
                .map(|(h, _)| Reverse(key(*h))),
        );

        while let Some(Reverse((_, u))) = heap.pop() {
            topo.push(u);

            let Some(children) = adj.get(&u) else {
                continue;
            };

            children.iter().for_each(|ch| {
                let d = indeg.get_mut(ch).expect("Indegree must exist");
                *d -= 1;
                if *d == 0 {
                    heap.push(Reverse(key(*ch)));
                }
            });
        }

        debug_assert_eq!(topo.len(), hashes.len());

        topo
    }

    fn execute_atom(
        &self,
        hash: &Multihash,
        trie: &mut Trie,
        state: &mut HashMap<Multihash, Option<Token>>,
        publishers: &mut HashSet<PeerId>,
        is_parent: bool,
    ) -> bool {
        let e = self.entries.get_mut(hash).expect("Entry must exist");
        publishers.insert(e.atom.peer);

        let Some(cmd) = &e.atom.cmd else {
            return true;
        };

        let inputs = cmd.input.iter().try_fold(HashMap::new(), |mut acc, hash| {
            let input = state.remove(hash).unwrap_or_else(|| {
                let key = hash.to_vec();
                trie.resolve(std::iter::once(&key), &e.witness.trie_proofs)
                    .then_some(Token::from_slice(&trie.get(&key).unwrap()).unwrap())
            })?;

            if !is_parent
                && e.witness
                    .script_sigs
                    .get(hash)
                    .is_none_or(|sig| V::validate_script_sig(&input.script_pk, sig))
            {
                return None;
            }

            acc.insert(*hash, input);
            Some(acc)
        });

        let Some(inputs) = inputs else {
            return false;
        };

        if !is_parent
            && !V::validate_conversion(cmd.code, inputs.values(), cmd.consumed.iter(), &cmd.created)
        {
            return false;
        }

        state.extend(inputs.into_iter().map(|(k, v)| {
            if cmd.consumed.contains(&k) {
                (k, None)
            } else {
                (k, Some(v))
            }
        }));

        cmd.created.iter().cloned().enumerate().for_each(|(i, t)| {
            // Token Id = H(AtomHash || Index)
            let data = (hash.to_vec(), i as u32).to_vec();
            let hash = Hasher::digest(&data);
            state.insert(hash, Some(t));
        });

        true
    }

    fn update_publishers(&self, mut cur: Multihash, publishers: &HashSet<PeerId>) {
        let cp = *self.checkpoint.read();

        loop {
            let mut e = self.entries.get_mut(&cur).expect("Entry must exist");
            e.publishers.extend(publishers.iter().cloned());

            if cp == cur {
                break;
            }

            let Some(next) = e.block_parent else {
                break;
            };

            cur = next;
        }
    }

    fn recompute_main_chain_and_checkpoint(&self) {
        let start = *self.checkpoint.read();
        let new_head = self.ghost_select(start);
        *self.main_head.write() = new_head;
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

        *self.checkpoint.write() = new_cp;
        self.adjust_difficulty(old_cp, new_cp);
        self.prune_trie_at_checkpoint(new_cp);
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

    fn prune_trie_at_checkpoint(&self, cp: Multihash) {
        let Some(keys) = self.config.retain_keys.as_ref() else {
            return;
        };

        if let Some(mut e) = self.entries.get_mut(&cp) {
            let _ = e.trie.retain(keys);
        }
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get(&self, h: &Multihash) -> Option<(Atom, Witness)> {
        self.entries.get(h).is_some_and(|e| !e.is_missing).then(|| {
            let e = self.entries.get(h).expect("Entry must exist");
            (e.atom.clone(), e.witness.clone())
        })
    }
}

impl<V> Default for Graph<V> {
    fn default() -> Self {
        let entry = Entry::genesis();
        let hash = entry.hash();
        let config = Config::default();
        let difficulty = AtomicU64::new(config.init_vdf_difficulty);

        Self {
            entries: DashMap::from_iter([(hash, entry)]),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
    }
}
