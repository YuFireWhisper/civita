use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
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

pub enum StorageMode {
    General { peer_id: PeerId },
    Archive { retain_checkpoints: u32 },
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    // Basic information
    pub atom: Atom,
    pub witness: Witness,
    pub height: Height,

    // General
    pub block_parent: Multihash,
    pub children: HashSet<Multihash>,
    pub validated: bool,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PeerId>,
    pub related_token: HashMap<PeerId, HashMap<Multihash, Token>>,
    pub unconflicted_tokens: HashMap<Multihash, Option<Token>>,

    // Checkpoint only
    pub checkpoint_parent: Option<Multihash>,
    pub next_height: Height,

    // Pending only
    pub pending_parents: AtomicU32,
    #[derivative(Default(value = "true"))]
    pub is_missing: bool,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    #[derivative(Default(value = "1000"))]
    pub block_threshold: u32,

    #[derivative(Default(value = "10"))]
    pub checkpoint_distance: Height,

    #[derivative(Default(value = "60_000"))]
    pub target_block_time_ms: u64,

    #[derivative(Default(value = "50000"))]
    pub init_vdf_difficulty: u64,

    #[derivative(Default(value = "0.1"))]
    pub max_difficulty_adjustment: f32,

    #[derivative(Default(value = "StorageMode::Archive { retain_checkpoints: 1 }"))]
    pub storage_mode: StorageMode,
}

pub struct Graph<V> {
    entries: DashMap<Multihash, Entry>,
    invalidated: DashSet<Multihash>,

    main_head: ParkingLock<Multihash>,
    checkpoint: ParkingLock<Multihash>,

    difficulty: AtomicU64,

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
        let pending_parents = AtomicU32::new(witness.atoms.len() as u32);

        Self {
            atom,
            witness,
            pending_parents,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn genesis(distance: Height) -> Self {
        Self {
            is_block: true,
            trie: Trie::default(),
            is_missing: false,
            next_height: distance * 2,
            ..Default::default()
        }
    }

    pub fn hash(&self) -> Multihash {
        self.atom.hash()
    }
}

impl<V: Validator> Graph<V> {
    pub fn empty(config: Config) -> Self {
        let entry = Entry::genesis(config.checkpoint_distance as Height);
        let hash = entry.hash();
        let difficulty = AtomicU64::new(config.init_vdf_difficulty);

        Self {
            entries: DashMap::from_iter([(hash, entry)]),
            invalidated: DashSet::new(),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn upsert(&self, atom: Atom, witness: Witness) -> UpdateResult {
        let hash = atom.hash();

        if self.contains(&hash) || self.invalidated.contains(&hash) {
            return UpdateResult::Noop;
        }

        // Parent should have one and only one block parent, and should not contain itself
        if witness.atoms.is_empty() || witness.atoms.contains(&hash) {
            return UpdateResult::from_invalidated(vec![atom.peer]);
        }

        self.entries.insert(hash, Entry::new(atom, witness));

        let result = self.link_parents(hash);

        if !result.is_noop() {
            return result;
        }

        if self
            .entries
            .get(&hash)
            .unwrap()
            .pending_parents
            .load(Ordering::Relaxed)
            == 0
        {
            let mut invalidated = Vec::new();
            self.validate(hash, &mut invalidated);
            return UpdateResult::from_invalidated(invalidated);
        }

        UpdateResult::Noop
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn link_parents(&self, hash: Multihash) -> UpdateResult {
        let cur = self.entries.get_mut(&hash).expect("Entry must exist");
        let mut missing = Vec::new();

        if !cur.witness.atoms.iter().all(|h| {
            if self.invalidated.contains(h) {
                return false;
            }

            let mut p = self.entries.entry(*h).or_insert_with(|| {
                missing.push(*h);
                Entry::default()
            });

            p.children.insert(hash);

            if !p.is_missing && p.pending_parents.load(Ordering::Relaxed) == 0 {
                cur.pending_parents.fetch_sub(1, Ordering::Relaxed);
            }

            true
        }) {
            let mut invalidated = Vec::new();
            self.remove_subgraph(hash, &mut invalidated);
            return UpdateResult::from_invalidated(invalidated);
        }

        UpdateResult::from_missing(missing)
    }

    fn validate(&self, hash: Multihash, invalidated: &mut Vec<PeerId>) {
        let e = self.entries.get(&hash).expect("Entry must exist");

        if e.validated
            || e.is_missing
            || e.pending_parents.load(Ordering::Relaxed) != 0
            || e.height < self.checkpoint_height()
        {
            return;
        }

        let bp_h = e
            .witness
            .atoms
            .iter()
            .try_fold(None, |acc, h| {
                let p = self.entries.get(h).unwrap();
                let exp = if p.is_block { *h } else { p.block_parent };
                match acc {
                    None => Some(Some(exp)),
                    Some(prev) if prev == exp => Some(Some(exp)),
                    Some(_) => None,
                }
            })
            .flatten();

        let Some(bp) = bp_h else {
            drop(e);
            self.remove_subgraph(hash, invalidated);
            return;
        };

        let mut bp = self.entries.get_mut(&bp).expect("Block parent must exist");
        let trie = &mut bp.trie;
        let order = self.topological_sort(e.witness.atoms.iter().cloned());
        let mut state = HashMap::new();
        let mut publishers = HashSet::new();

        if !self.try_execute_atoms(&order, trie, &mut state, &mut publishers) {
            drop(e);
            self.remove_subgraph(hash, invalidated);
            return;
        }

        drop(e);
        self.update_validate_atom(hash, state, publishers);

        let e = self.entries.get(&hash).unwrap();
        e.children.iter().for_each(|ch| {
            let c = self.entries.get_mut(ch).expect("Child entry must exist");
            c.pending_parents.fetch_sub(1, Ordering::Relaxed);
            self.validate(*ch, invalidated);
        });
    }

    fn checkpoint_height(&self) -> Height {
        self.entries
            .get(&self.checkpoint.read())
            .map_or(0, |e| e.height)
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

    fn try_execute_atoms(
        &self,
        atoms: &[Multihash],
        trie: &mut Trie,
        state: &mut HashMap<Multihash, Option<Token>>,
        publishers: &mut HashSet<PeerId>,
    ) -> bool {
        atoms.iter().all(|h| {
            let e = self.entries.get(h).unwrap();
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

                if !e.validated
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

            if !e.validated
                && !V::validate_conversion(
                    cmd.code,
                    inputs.values(),
                    cmd.consumed.iter(),
                    &cmd.created,
                )
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
                let data = (h.to_vec(), i as u32).to_vec();
                let hash = Hasher::digest(&data);
                state.insert(hash, Some(t));
            });

            true
        })
    }

    fn update_validate_atom(
        &self,
        hash: Multihash,
        state: HashMap<Multihash, Option<Token>>,
        publishers: HashSet<PeerId>,
    ) {
        let mut e = self.entries.get_mut(&hash).unwrap();

        e.validated = true;

        if (e.witness.atoms.len() as u32) < self.config.block_threshold {
            let mut bp_e = self.entries.get_mut(&e.block_parent).unwrap();

            let is_conflict = state
                .keys()
                .any(|k| bp_e.unconflicted_tokens.contains_key(k));

            if is_conflict {
                bp_e.children.remove(e.key());
            } else {
                bp_e.unconflicted_tokens.extend(state);
            }

            return;
        }

        let (mut trie, mut related_by_peer) = {
            let bp_e = self.entries.get(&e.block_parent).unwrap();
            (bp_e.trie.clone(), bp_e.related_token.clone())
        };

        fn remove_token_id(
            k: &Multihash,
            trie: &mut Trie,
            related_by_peer: &mut HashMap<PeerId, HashMap<Multihash, Token>>,
        ) {
            trie.remove(&k.to_vec());
            related_by_peer.values_mut().for_each(|m| {
                m.remove(k);
            });
        }

        fn insert_token_for_peer(
            peer: &PeerId,
            k: &Multihash,
            t: &Token,
            trie: &mut Trie,
            related_by_peer: &mut HashMap<PeerId, HashMap<Multihash, Token>>,
        ) {
            trie.insert(&k.to_vec(), t.to_vec());
            related_by_peer
                .entry(*peer)
                .or_default()
                .insert(*k, t.clone());
        }

        state.into_iter().for_each(|(k, t)| {
            let Some(token) = t.as_ref() else {
                remove_token_id(&k, &mut trie, &mut related_by_peer);
                return;
            };

            trie.insert(&k.to_vec(), t.to_vec());

            match &self.config.storage_mode {
                StorageMode::General { peer_id } => {
                    if V::is_related(&token.script_pk, peer_id) {
                        insert_token_for_peer(peer_id, &k, token, &mut trie, &mut related_by_peer);
                    }
                }
                StorageMode::Archive { .. } => {
                    let peers = V::related_peers(&token.script_pk);
                    peers.iter().for_each(|p| {
                        insert_token_for_peer(p, &k, token, &mut trie, &mut related_by_peer);
                    });
                }
            }
        });

        e.is_block = true;
        e.trie = trie;
        e.related_token = related_by_peer;

        self.update_publishers(e.block_parent, &publishers);
        self.recompute_main_chain_and_checkpoint();
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

    fn update_publishers(&self, mut cur: Multihash, publishers: &HashSet<PeerId>) {
        let cp = *self.checkpoint.read();

        loop {
            let mut e = self.entries.get_mut(&cur).expect("Entry must exist");
            e.publishers.extend(publishers.iter().cloned());

            if cp == cur {
                break;
            }

            cur = e.block_parent;
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
        let exp = self.entries.get(&old_cp).unwrap().next_height;
        let height = self.entries.get(&head_hash).unwrap().height;

        if height < exp {
            return;
        }

        let target = {
            let target_height = height - self.config.checkpoint_distance as Height;
            let mut cur = self.entries.get(&head_hash).unwrap();
            while cur.height > target_height {
                cur = self.entries.get(&cur.block_parent).unwrap();
            }
            *cur.key()
        };

        {
            let mut e = self.entries.get_mut(&target).unwrap();
            e.next_height = height + self.config.checkpoint_distance as Height;
            e.checkpoint_parent = Some(old_cp);
        }

        *self.checkpoint.write() = target;

        let (target, block_times, keep) = self.scan_from_head(head_hash, old_cp, height);
        self.adjust_difficulty(block_times);
        self.prune_trie(target);
        self.prune_graph(target, &keep);
    }

    fn scan_from_head(
        &self,
        hash: Multihash,
        prev_cp: Multihash,
        target_height: Height,
    ) -> (Multihash, Vec<u64>, HashSet<Multihash>) {
        let mut cur = hash;
        let mut target = None;
        let mut times: Vec<u64> = Vec::new();
        let mut keep: HashSet<Multihash> = HashSet::new();
        let mut stop_keep = false;

        loop {
            let cur_e = self.entries.get(&cur).expect("Entry must exist");

            if target.is_none() && cur_e.height <= target_height {
                target = Some(cur);
            }

            if !stop_keep {
                keep.extend(cur_e.witness.atoms.iter());
                if cur_e
                    .checkpoint_parent
                    .is_none_or(|p| p == cur_e.block_parent)
                {
                    stop_keep = true;
                }
            }

            if cur == prev_cp {
                break;
            }

            let parent = cur_e.block_parent;
            let p_e = self.entries.get(&parent).expect("Parent entry must exist");
            let dt = cur_e.atom.timestamp.saturating_sub(p_e.atom.timestamp);
            if dt > 0 {
                times.push(dt);
            }

            cur = parent;
        }

        (target.expect("Target must be found"), times, keep)
    }

    fn adjust_difficulty(&self, mut times: Vec<u64>) {
        use std::sync::atomic::Ordering;

        if times.is_empty() {
            return;
        }

        let median = {
            let mid = times.len() / 2;

            let median = if times.len() == 1 {
                times[0] as f32
            } else {
                let (_, m, _) = times.select_nth_unstable(mid);
                *m as f32
            };

            if median == 0.0 {
                return;
            }

            median
        };

        let target = self.config.target_block_time_ms as f32;
        let ratio_raw = target / median;
        let ratio = ratio_raw.clamp(
            1.0 / self.config.max_difficulty_adjustment,
            self.config.max_difficulty_adjustment,
        );

        let old = self.difficulty.load(Ordering::Relaxed) as f32;
        let new = ((old * ratio) as u64).max(1);
        self.difficulty.store(new, Ordering::Relaxed);
    }

    fn prune_graph(&self, new_cp: Multihash, keep: &HashSet<Multihash>) {
        let cp_height = self.entries.get(&new_cp).unwrap().height;

        let retain = match self.config.storage_mode {
            StorageMode::General { .. } => 1,
            StorageMode::Archive { retain_checkpoints } => retain_checkpoints,
        };

        let cutoff_height = if retain == 0 {
            None
        } else {
            self.find_cutoff_height(new_cp, retain)
        };

        let last = cp_height.saturating_sub(self.config.checkpoint_distance);

        self.entries
            .iter()
            .filter_map(|e| {
                let h = e.value().height;
                let key = *e.key();

                let rm_by_storage = cutoff_height.is_some_and(|c| h < c);
                let rm_by_graph = h < last && h <= cp_height && !keep.contains(&key);

                (rm_by_storage || rm_by_graph).then_some(key)
            })
            .for_each(|k| {
                self.entries.remove(&k);
                self.invalidated.remove(&k);
            });

        self.entries.iter_mut().for_each(|mut e| {
            e.children.retain(|ch| self.entries.contains_key(ch));
        });
    }

    fn prune_trie(&self, cp: Multihash) {
        let mut e = self.entries.get_mut(&cp).unwrap();

        let keys = e
            .related_token
            .values()
            .flat_map(|m| m.keys())
            .map(|k| k.to_vec())
            .collect::<Vec<_>>();

        e.trie.retain(keys.iter());
    }

    fn find_cutoff_height(&self, mut cur: Multihash, retain: u32) -> Option<Height> {
        let mut idx = 1u32;

        loop {
            if idx == retain {
                let e = self.entries.get(&cur).unwrap();
                return Some(e.height);
            }

            let e = self.entries.get(&cur).unwrap();

            match e.checkpoint_parent {
                Some(p) => {
                    cur = p;
                    idx += 1;
                }
                None => {
                    let e = self.entries.get(&cur).unwrap();
                    return Some(e.height);
                }
            }
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

    pub fn tokens_for(&self, peer: &PeerId) -> HashMap<Multihash, Token> {
        let h = *self.main_head.read();
        let e = self.entries.get(&h).expect("Head entry must exist");

        let mut related = e.related_token.get(peer).cloned().unwrap_or_default();

        e.unconflicted_tokens.iter().for_each(|(k, v)| match v {
            Some(t) => match self.config.storage_mode {
                StorageMode::General { ref peer_id } => {
                    if peer_id == peer && V::is_related(&t.script_pk, peer) {
                        related.insert(*k, t.clone());
                    }
                }
                StorageMode::Archive { .. } => {
                    if V::related_peers(&t.script_pk)
                        .into_iter()
                        .any(|p| &p == peer)
                    {
                        related.insert(*k, t.clone());
                    }
                }
            },
            None => {
                related.remove(k);
            }
        });

        related
    }

    pub fn tokens_all(&self) -> HashMap<PeerId, HashMap<Multihash, Token>> {
        let h = *self.main_head.read();
        let e = self.entries.get(&h).expect("Head entry must exist");

        let mut by_peer = e.related_token.clone();

        e.unconflicted_tokens.iter().for_each(|(k, v)| match v {
            Some(t) => match self.config.storage_mode {
                StorageMode::General { ref peer_id } => {
                    if V::is_related(&t.script_pk, peer_id) {
                        by_peer.entry(*peer_id).or_default().insert(*k, t.clone());
                    }
                }
                StorageMode::Archive { .. } => {
                    for p in V::related_peers(&t.script_pk) {
                        by_peer.entry(p).or_default().insert(*k, t.clone());
                    }
                }
            },
            None => {
                for (_, m) in by_peer.iter_mut() {
                    m.remove(k);
                }
            }
        });

        by_peer
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
