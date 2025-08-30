use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
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

type State = HashMap<Multihash, Option<Token>>;

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum RejectReason {
    Rejected,
    RejectedParent,
    SelfReference,
    MimatchBlockParent,
    InvalidScriptSig,
    InvalidConversion,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum IgnoreReason {
    Accepted,
    Ignored,
    IgnoredParent,
    MimatchCheckpoint,
}

#[derive(Default)]
#[derive(Debug)]
pub struct UpdateResult {
    pub accepted: HashSet<Multihash>,
    pub rejected: HashMap<Multihash, RejectReason>,
    pub ignored: HashMap<Multihash, IgnoreReason>,
    pub missing: HashSet<Multihash>,
}

pub enum StorageMode {
    General { peer_id: PeerId },
    Archive { retain_checkpoints: Option<u32> },
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

    #[derivative(Default(value = "StorageMode::Archive { retain_checkpoints: Some(1) }"))]
    pub storage_mode: StorageMode,
}

#[derive(Serialize)]
pub struct CheckopointInfo {
    pub height: Height,
    pub difficulty: u64,
    pub related_keys: HashSet<Multihash>,
    pub trie_root: Multihash,
    pub trie_guide: HashMap<Multihash, Vec<u8>>,
}

pub struct Graph<V> {
    entries: DashMap<Multihash, Entry>,

    accepted: DashSet<Multihash>,
    rejected: DashSet<Multihash>,
    ignored: DashSet<Multihash>,

    main_head: ParkingLock<Multihash>,
    checkpoint: ParkingLock<Multihash>,

    history: ParkingLock<VecDeque<(Vec<u8>, Vec<u8>)>>,

    difficulty: AtomicU64,

    config: Config,

    _marker: std::marker::PhantomData<V>,
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
    pub fn empty(config: Config) -> Self {
        let entry = Entry::genesis();
        let hash = entry.hash();
        let difficulty = AtomicU64::new(config.init_vdf_difficulty);

        Self {
            entries: DashMap::from_iter([(hash, entry)]),
            accepted: DashSet::from_iter([hash]),
            rejected: DashSet::new(),
            ignored: DashSet::new(),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            history: ParkingLock::new(VecDeque::new()),
            difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn upsert(&self, atom: Atom, witness: Witness) -> UpdateResult {
        let hash = atom.hash();
        let mut result = UpdateResult::default();

        if self.rejected.contains(&hash) {
            self.remove_subgraph_with_reject(hash, RejectReason::Rejected, &mut result);
            return result;
        }

        if self.accepted.contains(&hash) {
            self.remove_subgraph_with_ignore(hash, IgnoreReason::Accepted, &mut result);
            return result;
        }

        if self.ignored.contains(&hash) {
            self.remove_subgraph_with_ignore(hash, IgnoreReason::Ignored, &mut result);
            return result;
        }

        if atom.checkpoint != *self.checkpoint.read() {
            self.remove_subgraph_with_ignore(hash, IgnoreReason::MimatchCheckpoint, &mut result);
            return result;
        }

        // Parent should have one and only one block parent, and should not contain itself
        if witness.atoms.is_empty() || witness.atoms.contains(&hash) {
            self.remove_subgraph_with_reject(hash, RejectReason::SelfReference, &mut result);
            return result;
        }

        self.entries.insert(hash, Entry::new(atom, witness));

        if !self.link_parents(hash, &mut result) {
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
            self.validate(hash, &mut result);
        }

        result
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn link_parents(&self, hash: Multihash, result: &mut UpdateResult) -> bool {
        let cur = self.entries.get_mut(&hash).unwrap();

        for parent in cur.witness.atoms.iter() {
            if self.rejected.contains(parent) {
                self.remove_subgraph_with_reject(hash, RejectReason::RejectedParent, result);
                return false;
            }

            if self.ignored.contains(parent) {
                self.remove_subgraph_with_ignore(hash, IgnoreReason::IgnoredParent, result);
                return false;
            }

            let mut parent = self.entries.entry(*parent).or_insert_with(|| {
                result.missing.insert(*parent);
                Entry::default()
            });

            parent.children.insert(hash);

            if !parent.is_missing && parent.pending_parents.load(Ordering::Relaxed) == 0 {
                cur.pending_parents.fetch_sub(1, Ordering::Relaxed);
            }
        }

        true
    }

    fn validate(&self, hash: Multihash, result: &mut UpdateResult) {
        let entry = self.entries.get(&hash).unwrap();

        if entry.validated {
            return;
        }

        let Some(bp_hash) = self.block_parent_of(entry.witness.atoms.iter()) else {
            drop(entry);
            self.remove_subgraph_with_reject(hash, RejectReason::MimatchBlockParent, result);
            return;
        };

        let order = self.topological_sort(bp_hash, hash, &entry.witness.atoms);
        drop(entry);

        let Some((state, publishers)) = self.try_execute_atoms(
            &order,
            &mut self.entries.get_mut(&bp_hash).unwrap().trie,
            result,
        ) else {
            return;
        };

        self.update_validate_atom(hash, state, publishers);
        result.accepted.insert(hash);

        let e = self.entries.get(&hash).unwrap();
        e.children.iter().for_each(|ch| {
            let c = self.entries.get_mut(ch).unwrap();
            c.pending_parents.fetch_sub(1, Ordering::Relaxed);
            self.validate(*ch, result);
        });
    }

    fn block_parent_of<'a>(
        &self,
        mut hashes: impl Iterator<Item = &'a Multihash>,
    ) -> Option<Multihash> {
        hashes
            .try_fold(None, |acc, h| {
                let p = self.entries.get(h).unwrap();
                let exp = if p.is_block { *h } else { p.block_parent };
                match acc {
                    None => Some(Some(exp)),
                    Some(prev) if prev == exp => Some(Some(exp)),
                    Some(_) => None,
                }
            })
            .flatten()
    }

    fn topological_sort(
        &self,
        start: Multihash,
        end: Multihash,
        hashes: &HashSet<Multihash>,
    ) -> Vec<Multihash> {
        let mut indeg = HashMap::new();

        let mut topo = Vec::with_capacity(hashes.len());
        let mut stk = VecDeque::new();
        stk.push_back(start);

        while let Some(u) = stk.pop_front() {
            self.entries
                .get(&u)
                .unwrap()
                .children
                .iter()
                .filter(|ch| hashes.contains(ch))
                .for_each(|ch| {
                    let d = indeg
                        .entry(*ch)
                        .or_insert(self.entries.get(ch).unwrap().witness.atoms.len());
                    *d -= 1;
                    topo.push(*ch);
                    if d == &0 && ch != &end {
                        stk.push_back(*ch);
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
        result: &mut UpdateResult,
    ) -> Option<(State, HashSet<PeerId>)> {
        let mut state = HashMap::new();
        let mut publishers = HashSet::new();

        for hash in atoms {
            let entry = self.entries.get(hash).unwrap();
            publishers.insert(entry.atom.peer);

            let Some(cmd) = &entry.atom.cmd else {
                continue;
            };

            let Some(inputs) = cmd.input.iter().try_fold(HashMap::new(), |mut acc, hash| {
                let input = state.remove(hash).unwrap_or_else(|| {
                    let key = hash.to_vec();
                    trie.resolve(std::iter::once(&key), &entry.witness.trie_proofs)
                        .then_some(Token::from_slice(&trie.get(&key).unwrap()).unwrap())
                })?;

                if !entry.validated
                    && entry
                        .witness
                        .script_sigs
                        .get(hash)
                        .is_none_or(|sig| V::validate_script_sig(&input.script_pk, sig))
                {
                    return None;
                }

                acc.insert(*hash, input);
                Some(acc)
            }) else {
                self.remove_subgraph_with_reject(*hash, RejectReason::InvalidScriptSig, result);
                return None;
            };

            if !entry.validated
                && !V::validate_conversion(
                    cmd.code,
                    inputs.values(),
                    cmd.consumed.iter(),
                    &cmd.created,
                )
            {
                self.remove_subgraph_with_reject(*hash, RejectReason::InvalidConversion, result);
                return None;
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
                let data = (*hash, i as u32).to_vec();
                let hash = Hasher::digest(&data);
                state.insert(hash, Some(t));
            });
        }

        Some((state, publishers))
    }

    fn update_validate_atom(&self, hash: Multihash, state: State, publishers: HashSet<PeerId>) {
        let mut entry = self.entries.get_mut(&hash).unwrap();

        if (entry.witness.atoms.len() as u32) < self.config.block_threshold {
            let mut bp_e = self.entries.get_mut(&entry.block_parent).unwrap();

            if state
                .keys()
                .any(|k| bp_e.unconflicted_tokens.contains_key(k))
            {
                bp_e.children.remove(entry.key());
            } else {
                bp_e.unconflicted_tokens.extend(state);
            }

            return;
        }

        let (mut trie, mut related_by_peer) = {
            let bp_e = self.entries.get(&entry.block_parent).unwrap();
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

        entry.is_block = true;
        entry.trie = trie;
        entry.related_token = related_by_peer;
        entry.validated = true;

        self.update_publishers(entry.block_parent, &publishers);
        self.recompute_main_chain_and_checkpoint();
    }

    fn remove_subgraph_with_ignore(
        &self,
        hash: Multihash,
        reason: IgnoreReason,
        result: &mut UpdateResult,
    ) {
        let mut stk = VecDeque::new();
        stk.push_back(hash);

        result.ignored.insert(hash, reason);

        while let Some(u) = stk.pop_front() {
            if self.ignored.insert(u) {
                continue;
            }

            let Some((_, entry)) = self.entries.remove(&u) else {
                continue;
            };

            if !entry.is_missing && u != hash {
                result.ignored.insert(u, IgnoreReason::IgnoredParent);
            }

            stk.extend(entry.children);
        }
    }

    fn remove_subgraph_with_reject(
        &self,
        hash: Multihash,
        reason: RejectReason,
        result: &mut UpdateResult,
    ) {
        let mut stk = VecDeque::new();
        stk.push_back(hash);

        result.rejected.insert(hash, reason);

        while let Some(u) = stk.pop_front() {
            if self.rejected.insert(u) {
                continue;
            }

            let Some((_, entry)) = self.entries.remove(&u) else {
                continue;
            };

            if !entry.is_missing && u != hash {
                result.rejected.insert(u, RejectReason::RejectedParent);
            }

            stk.extend(entry.children);
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

    fn maybe_advance_checkpoint(&self, head: Multihash, prev: Multihash) {
        let prev_height = self.entries.get(&prev).unwrap().height;
        let head_height = self.entries.get(&head).unwrap().height;
        let trigger_height = prev_height + self.config.checkpoint_distance * 2;
        let target_height = prev_height + self.config.checkpoint_distance;

        if head_height != trigger_height {
            return;
        }

        let target_hash = {
            let mut cur = head;
            loop {
                let e = self.entries.get(&cur).unwrap();
                if e.height == target_height {
                    break cur;
                }
                cur = e.block_parent;
            }
        };

        let (times, atoms) = self.walk_and_collection(head, target_hash);
        let difficulty = self.adjust_difficulty(times);
        self.clean_to_height(target_height, target_hash);

        {
            let len = match self.config.storage_mode {
                StorageMode::General { .. } => Some(0),
                StorageMode::Archive { retain_checkpoints } => retain_checkpoints,
            };

            if len.is_some_and(|l| l == 0) {
                return;
            }

            if len.is_some_and(|l| self.history.read().len() >= l as usize) {
                let mut h = self.history.write();
                h.pop_front();
            }
        }

        let info = {
            let e = atoms.last().unwrap();
            let related_keys = e
                .related_token
                .values()
                .flat_map(|m| m.keys())
                .cloned()
                .collect::<HashSet<_>>();
            let guide = e
                .trie
                .generate_guide(related_keys.iter().map(|k| k.to_vec()))
                .expect("Guide must be generated");
            CheckopointInfo {
                height: e.height,
                difficulty: self.difficulty(),
                related_keys,
                trie_root: e.trie.root_hash(),
                trie_guide: guide,
            }
        };

        *self.checkpoint.write() = target_hash;
        self.difficulty.store(difficulty, Ordering::Relaxed);
        self.history.write().push_back((
            info.to_vec(),
            atoms
                .into_iter()
                .map(|e| (e.atom, e.witness))
                .collect::<Vec<_>>()
                .to_vec(),
        ));
    }

    fn walk_and_collection(&self, start: Multihash, end: Multihash) -> (Vec<u64>, Vec<Entry>) {
        let mut atoms = Vec::new();
        let mut times = Vec::new();
        let mut cur = start;
        let mut next_time: Option<u64> = None;

        loop {
            let e = self.entries.remove(&cur).unwrap().1;

            if let Some(dt) = next_time {
                let dt = dt.saturating_sub(e.atom.timestamp);
                if dt > 0 {
                    times.push(dt);
                }
            }
            next_time = Some(e.atom.timestamp);

            if cur == end {
                atoms.push(e);
                break;
            }

            cur = e.block_parent;
            atoms.extend(
                e.witness
                    .atoms
                    .iter()
                    .map(|h| self.entries.remove(h).unwrap().1),
            );
            atoms.push(e);
        }

        (times, atoms)
    }

    fn clean_to_height(&self, target: Height, hash: Multihash) {
        self.entries.retain(|k, e| {
            k == &hash || (e.height > target && (!e.validated || e.atom.checkpoint == hash))
        });
    }

    fn adjust_difficulty(&self, mut times: Vec<u64>) -> u64 {
        use std::sync::atomic::Ordering;

        debug_assert!(!times.is_empty());

        let median = {
            let mid = times.len() / 2;

            let median = if times.len() == 1 {
                times[0] as f32
            } else {
                let (_, m, _) = times.select_nth_unstable(mid);
                *m as f32
            };

            median
        };

        let target = self.config.target_block_time_ms as f32;
        let ratio_raw = target / median;
        let ratio = ratio_raw.clamp(
            1.0 / self.config.max_difficulty_adjustment,
            self.config.max_difficulty_adjustment,
        );

        let old = self.difficulty.load(Ordering::Relaxed) as f32;
        ((old * ratio) as u64).max(1)
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

    pub fn checkpoint(&self) -> Multihash {
        *self.checkpoint.read()
    }
}
