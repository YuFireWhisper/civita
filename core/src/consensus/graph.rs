use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::atomic::AtomicU64,
};

use civita_serialize::Serialize;
use dashmap::{DashMap, DashSet};
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
pub enum UpdateResult {
    Noop,
    Missing(Vec<Multihash>),
    Invalidated(Vec<PeerId>),
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    // Basic information
    pub atom: Atom,
    pub witness: Witness,
    pub height: Height,

    // General
    pub block_parent: Option<Multihash>,
    pub children: HashSet<Multihash>,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PeerId>,
    pub related_token: HashMap<Multihash, Token>,
    pub unconflicted_tokens: HashMap<Multihash, Option<Token>>,

    // Checkpoint only
    pub checkpoint_parent: Option<Multihash>,

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
}

pub struct Graph<V> {
    entries: DashMap<Multihash, Entry>,
    invalidated: DashSet<Multihash>,

    main_head: ParkingLock<Multihash>,
    checkpoint: ParkingLock<Multihash>,

    difficulty: AtomicU64,

    peer: PeerId,
    config: Config,

    _marker: std::marker::PhantomData<V>,
}

impl UpdateResult {
    pub fn from_invalidated(invalidated: Vec<PeerId>) -> Self {
        if invalidated.is_empty() {
            UpdateResult::Noop
        } else {
            UpdateResult::Invalidated(invalidated)
        }
    }

    pub fn from_missing(missing: Vec<Multihash>) -> Self {
        if missing.is_empty() {
            UpdateResult::Noop
        } else {
            UpdateResult::Missing(missing)
        }
    }

    pub fn is_noop(&self) -> bool {
        matches!(self, UpdateResult::Noop)
    }
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
    pub fn empty(peer: PeerId, config: Config) -> Self {
        let entry = Entry::genesis();
        let hash = entry.hash();
        let difficulty = AtomicU64::new(config.init_vdf_difficulty);

        Self {
            entries: DashMap::from_iter([(hash, entry)]),
            invalidated: DashSet::new(),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            difficulty,
            peer,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn upsert(&self, atom: Atom, witness: Witness) -> UpdateResult {
        let hash = atom.hash();

        if self.contains(&hash) || self.invalidated.contains(&hash) {
            return UpdateResult::Noop;
        }

        self.entries.insert(hash, Entry::new(atom, witness));

        let mut missing = Vec::new();
        if !self.link_parents(hash, &mut missing) {
            let mut invalidated = Vec::new();
            self.remove_subgraph(hash, &mut invalidated);
            return UpdateResult::from_invalidated(invalidated);
        }

        if !missing.is_empty() {
            return UpdateResult::from_missing(missing);
        }

        if self.entries.get(&hash).unwrap().pending_parents == 0 {
            let mut invalidated = Vec::new();
            self.on_all_parent_valid(hash, &mut invalidated);
            return UpdateResult::from_invalidated(invalidated);
        }

        UpdateResult::Noop
    }

    fn checkpoint_height(&self) -> Height {
        self.entries
            .get(&self.checkpoint.read())
            .map_or(0, |e| e.height)
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn link_parents(&self, hash: Multihash, missing: &mut Vec<Multihash>) -> bool {
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
                    missing.push(h);
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
        let (bp, h) = if parent.is_block {
            (parent.hash(), parent.height.saturating_add(1))
        } else {
            let bp = parent.block_parent.expect("Block parent must exist");
            (bp, parent.height)
        };

        if let Some(prev_bp) = cur.block_parent {
            if prev_bp != bp || cur.height != h {
                return false;
            }
        } else {
            cur.block_parent = Some(bp);
            cur.height = h;
        }

        true
    }

    fn remove_subgraph(&self, hash: Multihash, invalidated: &mut Vec<PeerId>) {
        let mut stk = vec![hash];

        while let Some(u) = stk.pop() {
            if !self.invalidated.insert(u) {
                continue;
            }

            let Some((_, entry)) = self.entries.remove(&u) else {
                continue;
            };

            stk.extend(entry.children);

            if !entry.is_missing {
                invalidated.push(entry.atom.peer);
            }
        }
    }

    fn on_all_parent_valid(&self, hash: Multihash, invalidated: &mut Vec<PeerId>) {
        let mut queue = VecDeque::new();
        queue.push_back(hash);

        while let Some(h) = queue.pop_front() {
            let cp_h = self.checkpoint_height();
            let e_h = self.atom_height(h);

            if e_h <= cp_h {
                self.remove_subgraph(h, invalidated);
                continue;
            }

            let mut state = HashMap::new();
            let mut publishers = HashSet::new();

            if !self.try_final_validate(h, &mut state, &mut publishers) {
                self.remove_subgraph(h, invalidated);
                continue;
            }

            self.on_valid(h, state, publishers);

            let entry = self.entries.get(&h).expect("Entry must exist");

            entry.children.iter().for_each(|ch| {
                let mut c = self.entries.get_mut(ch).expect("Child entry must exist");

                if !Self::on_parent_valid(&mut c, &entry) {
                    self.remove_subgraph(*ch, invalidated);
                    return;
                }

                c.pending_parents -= 1;
                if c.pending_parents == 0 {
                    queue.push_back(*ch);
                }
            });
        }
    }

    fn atom_height(&self, hash: Multihash) -> Height {
        self.entries.get(&hash).expect("Entry must exist").height
    }

    fn try_final_validate(
        &self,
        hash: Multihash,
        state: &mut HashMap<Multihash, Option<Token>>,
        publishers: &mut HashSet<PeerId>,
    ) -> bool {
        let (mut bp_e, parents) = {
            let e = self.entries.get(&hash).expect("Entry must exist");
            let bp = e.block_parent.expect("Block parent must exist");
            let bp_e = self.entries.get_mut(&bp).expect("Block parent must exist");
            let mut parents = e.witness.atoms.clone();
            parents.remove(&bp);
            (bp_e, parents)
        };

        if parents.is_empty() {
            return self.execute_atom(&hash, &mut bp_e.trie, state, publishers, false);
        }

        self.topological_sort(parents.into_iter())
            .into_iter()
            .all(|h| self.execute_atom(&h, &mut bp_e.trie, state, publishers, true))
            && self.execute_atom(&hash, &mut bp_e.trie, state, publishers, false)
    }

    fn topological_sort(&self, hashes: impl Iterator<Item = Multihash>) -> Vec<Multihash> {
        let mut indeg = HashMap::<_, u32>::new();
        let mut adj = HashMap::<_, Vec<_>>::new();

        let hashes: HashSet<_> = hashes.collect();

        hashes.iter().for_each(|&h| {
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
        });

        let key = |x: Multihash| {
            let h = self.entries.get(&x).expect("Entry must exist").height;
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

    fn on_valid(
        &self,
        hash: Multihash,
        state: HashMap<Multihash, Option<Token>>,
        publishers: HashSet<PeerId>,
    ) {
        let mut e = self.entries.get_mut(&hash).expect("Entry must exist");
        let bp = e.block_parent.expect("Block parent must exist");
        let mut bp_e = self.entries.get_mut(&bp).expect("Block parent must exist");

        if (e.witness.atoms.len() as u32) < self.config.block_threshold {
            let is_conflict = state
                .keys()
                .any(|k| bp_e.unconflicted_tokens.contains_key(k));

            if is_conflict {
                bp_e.children.remove(&hash);
            } else {
                bp_e.unconflicted_tokens.extend(state);
            }

            return;
        }

        let mut trie = bp_e.trie.clone();
        let mut related = bp_e.related_token.clone();

        state.into_iter().for_each(|(k, t)| {
            if let Some(t) = t.as_ref() {
                trie.insert(&k.to_vec(), t.to_vec());
                if V::is_related(&t.script_pk, &self.peer) {
                    related.insert(k, t.clone());
                }
            } else {
                trie.remove(&k.to_vec());
                related.remove(&k);
            }
        });

        e.is_block = true;
        e.trie = trie;
        e.related_token = related;

        drop(e);
        drop(bp_e);

        self.update_publishers(bp, &publishers);
        self.recompute_main_chain_and_checkpoint();
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
        while cur.height > desired_cp_height {
            let next = &cur.block_parent.expect("Block parent must exist");
            cur = self.entries.get(next).expect("Entry must exist");
        }

        debug_assert_eq!(cur.height, desired_cp_height);
        let new_cp = *cur.key();

        {
            let mut new_cp_e = self
                .entries
                .get_mut(&new_cp)
                .expect("Checkpoint entry must exist");
            new_cp_e.checkpoint_parent = Some(old_cp);
        }

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
        let mut e = self
            .entries
            .get_mut(&cp)
            .expect("Checkpoint entry must exist");

        let keys = e
            .related_token
            .keys()
            .map(|k| k.to_vec())
            .collect::<Vec<_>>();

        e.trie.retain(keys.iter());
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

    pub fn tokens(&self) -> HashMap<Multihash, Token> {
        let h = *self.main_head.read();
        let e = self.entries.get(&h).expect("Head entry must exist");

        let mut related = e.related_token.clone();
        e.unconflicted_tokens.iter().for_each(|(k, v)| {
            if let Some(t) = v.as_ref() {
                if V::is_related(&t.script_pk, &self.peer) {
                    related.insert(*k, t.clone());
                }
            } else {
                related.remove(k);
            }
        });

        related
    }

    pub fn head(&self) -> Multihash {
        *self.main_head.read()
    }

    pub fn get_children(&self, h: &Multihash) -> HashSet<Multihash> {
        let e = self.entries.get(h).expect("Entry must exist");

        debug_assert!(e.is_block);

        e.children
            .iter()
            .filter_map(|h| {
                self.entries
                    .get(h)
                    .is_some_and(|e| !e.is_missing && !e.is_block)
                    .then_some(*h)
            })
            .collect()
    }

    pub fn generate_proofs<'a>(
        &self,
        token_ids: impl Iterator<Item = &'a Multihash>,
        h: &Multihash,
    ) -> HashMap<Multihash, Vec<u8>> {
        let e = self.entries.get(h).expect("Entry must exist");
        e.trie
            .generate_guide(token_ids.map(|id| id.to_vec()))
            .expect("Proofs must be generated")
    }
}
