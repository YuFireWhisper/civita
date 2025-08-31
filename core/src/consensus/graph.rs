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
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

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
    InvalidVdfProof,
    NotHeaviestChain,
    MissingInput,
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

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PeerId>,
    pub related_token: HashMap<PeerId, HashMap<Multihash, Token>>,
    pub unconfirmed_tokens: HashMap<Multihash, Option<Token>>,

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

    #[derivative(Default(value = "1024"))]
    pub vdf_params: u16,
}

#[derive(Serialize)]
pub struct CheckopointInfo {
    pub atom: Atom,
    pub witness: Witness,
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

    vdf: WesolowskiVDF,
    difficulty: AtomicU64,
    heaviest_weight: AtomicU64,

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

    pub fn validate_script_sig<V: Validator>(&self, id: &Multihash, pk: &[u8]) -> bool {
        self.witness
            .script_sigs
            .get(id)
            .is_none_or(|sig| V::validate_script_sig(pk, sig))
    }

    pub fn validate_conversion<'a, V: Validator>(
        &'a self,
        inputs: impl Iterator<Item = &'a Token>,
    ) -> bool {
        let cmd = self.atom.cmd.as_ref().unwrap();
        V::validate_conversion(cmd.code, inputs, cmd.consumed.iter(), &cmd.created)
    }
}

impl<V: Validator> Graph<V> {
    pub fn empty(config: Config) -> Self {
        let entry = Entry::genesis();
        let hash = entry.hash();
        let difficulty = AtomicU64::new(config.init_vdf_difficulty);
        let vdf = WesolowskiVDFParams(config.vdf_params).new();

        Self {
            entries: DashMap::from_iter([(hash, entry)]),
            accepted: DashSet::from_iter([hash]),
            rejected: DashSet::new(),
            ignored: DashSet::new(),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            history: ParkingLock::new(VecDeque::new()),
            vdf,
            difficulty,
            heaviest_weight: AtomicU64::new(0),
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
        let (bp_hash, order, len) = {
            let entry = self.entries.get(&hash).unwrap();

            if entry.atom.checkpoint != *self.checkpoint.read() {
                drop(entry);
                self.remove_subgraph_with_ignore(hash, IgnoreReason::MimatchCheckpoint, result);
                return;
            }

            if self
                .vdf
                .verify(&hash.to_vec(), self.difficulty(), &entry.witness.vdf_proof)
                .is_err()
            {
                self.remove_subgraph_with_reject(hash, RejectReason::InvalidVdfProof, result);
                return;
            }

            let Some(bp_hash) = self.block_parent_of(entry.witness.atoms.iter()) else {
                drop(entry);
                self.remove_subgraph_with_reject(hash, RejectReason::MimatchBlockParent, result);
                return;
            };

            let order = self.topological_sort(bp_hash, hash, &entry.witness.atoms);
            (bp_hash, order, entry.witness.atoms.len() as u32)
        };

        let trie = &mut self.entries.get_mut(&bp_hash).unwrap().trie;

        let (state, publishers) = match self.try_execute_atoms(&order, trie) {
            Ok(v) => v,
            Err(r) => {
                self.remove_subgraph_with_reject(hash, r, result);
                return;
            }
        };

        {
            let mut entry = self.entries.get_mut(&hash).unwrap();
            entry.block_parent = bp_hash;
            entry.height = self.entries.get(&bp_hash).unwrap().height + 1;
        }

        if len < self.config.block_threshold {
            return;
        }

        if !self.validate_checkpoint_update(hash, &publishers) {
            self.remove_subgraph_with_reject(hash, RejectReason::NotHeaviestChain, result);
            return;
        }

        self.update_unconflicted_tokens(hash, state);
        self.update_publishers(bp_hash, &publishers);
        self.recompute_main_chain_and_checkpoint();

        result.accepted.insert(hash);

        let mut entry = self.entries.get_mut(&hash).unwrap();
        entry.is_block = true;

        let entry = entry.downgrade();
        entry.children.iter().for_each(|ch| {
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
    ) -> Result<(State, HashSet<PeerId>), RejectReason> {
        let mut state = HashMap::new();
        let mut publishers = HashSet::new();

        for hash in atoms {
            let entry = self.entries.get(hash).unwrap();
            publishers.insert(entry.atom.peer);

            let Some(cmd) = &entry.atom.cmd else {
                continue;
            };

            let is_validated = self.accepted.contains(hash);

            let inputs = cmd.input.iter().try_fold(HashMap::new(), |mut acc, hash| {
                let input = state
                    .remove(hash)
                    .unwrap_or_else(|| {
                        let key = hash.to_vec();
                        trie.resolve(std::iter::once(&key), &entry.witness.trie_proofs)
                            .then_some(Token::from_slice(&trie.get(&key).unwrap()).unwrap())
                    })
                    .ok_or(RejectReason::MissingInput)?;

                if !is_validated && !entry.validate_script_sig::<V>(hash, &input.script_pk) {
                    return Err(RejectReason::InvalidScriptSig);
                }

                acc.insert(*hash, input);
                Ok(acc)
            })?;

            if !is_validated && !entry.validate_conversion::<V>(inputs.values()) {
                return Err(RejectReason::InvalidConversion);
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

        Ok((state, publishers))
    }

    fn validate_checkpoint_update(&self, hash: Multihash, publishers: &HashSet<PeerId>) -> bool {
        let target_hash = self.target_checkpoint_of(hash);
        let target_entry = self.entries.get(&target_hash).unwrap();

        let mut p = target_entry.publishers.clone();
        p.extend(publishers.iter().cloned());

        let len = p.len() as u64;
        self.heaviest_weight.fetch_max(len, Ordering::Relaxed) < len
    }

    fn target_checkpoint_of(&self, hash: Multihash) -> Multihash {
        let entry = self.entries.get(&hash).unwrap();
        let target_height = entry.height + self.config.checkpoint_distance;

        let mut cur = hash;
        loop {
            let e = self.entries.get(&cur).unwrap();
            if e.height == target_height {
                break cur;
            }
            cur = e.block_parent;
        }
    }

    fn update_unconflicted_tokens(&self, hash: Multihash, state: State) {
        let (bp_hash, len) = {
            let entry = self.entries.get(&hash).unwrap();
            (entry.block_parent, entry.witness.atoms.len() as u32)
        };

        if len < self.config.block_threshold {
            let mut bp = self.entries.get_mut(&bp_hash).unwrap();
            if state.keys().any(|k| bp.unconfirmed_tokens.contains_key(k)) {
                bp.children.remove(&hash);
            } else {
                bp.unconfirmed_tokens.extend(state);
            }
            return;
        }

        let (mut trie, mut related) = {
            let bp = self.entries.get(&bp_hash).unwrap();
            (bp.trie.clone(), bp.related_token.clone())
        };

        state.into_iter().for_each(|(k, t)| {
            let Some(t) = t else {
                trie.remove(&k.to_vec());
                related.values_mut().for_each(|m| {
                    m.remove(&k);
                });
                return;
            };

            trie.insert(&k.to_vec(), t.to_vec());

            match &self.config.storage_mode {
                StorageMode::General { peer_id } => {
                    if V::is_related(&t.script_pk, peer_id) {
                        related.entry(*peer_id).or_default().insert(k, t);
                    }
                }
                StorageMode::Archive { .. } => {
                    V::related_peers(&t.script_pk).into_iter().for_each(|p| {
                        related.entry(p).or_default().insert(k, t.clone());
                    });
                }
            }
        });

        let mut entry = self.entries.get_mut(&hash).unwrap();
        entry.trie = trie;
        entry.related_token = related;
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
                entry.witness.atoms.iter().for_each(|p| {
                    if let Some(mut pe) = self.entries.get_mut(p) {
                        pe.children.remove(&u);
                    }
                });
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
                entry.witness.atoms.iter().for_each(|p| {
                    if let Some(mut pe) = self.entries.get_mut(p) {
                        pe.children.remove(&u);
                    }
                });
            }

            stk.extend(entry.children);
        }
    }

    fn update_publishers(&self, mut cur: Multihash, publishers: &HashSet<PeerId>) {
        let cp = *self.checkpoint.read();

        loop {
            let mut e = self.entries.get_mut(&cur).unwrap();
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

        if new_head == *self.main_head.read() {
            return;
        }

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
            .map(|h| (self.entries.get(h).unwrap().publishers.len(), h))
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

        let target_height = prev_height + self.config.checkpoint_distance;
        let trigger_height = prev_height + self.config.checkpoint_distance * 2;

        if head_height != trigger_height {
            return;
        }

        let target_hash = self.target_checkpoint_of(head);
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

        let info = self.generate_checkpoint_info(target_hash).to_vec();
        let buf = atoms.into_iter().fold(Vec::new(), |mut acc, e| {
            acc.extend(e.atom.to_vec());
            acc.extend(e.witness.to_vec());
            acc
        });

        *self.checkpoint.write() = target_hash;
        self.difficulty.store(difficulty, Ordering::Relaxed);
        self.history.write().push_back((info.to_vec(), buf));
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
        self.entries
            .retain(|k, e| k == &hash || (e.height > target && e.atom.checkpoint == hash));
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

    fn generate_checkpoint_info(&self, hash: Multihash) -> CheckopointInfo {
        let e = self.entries.get(&hash).expect("Entry must exist");
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
            atom: e.atom.clone(),
            witness: e.witness.clone(),
            height: e.height,
            difficulty: self.difficulty(),
            related_keys,
            trie_root: e.trie.root_hash(),
            trie_guide: guide,
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

        e.unconfirmed_tokens.iter().for_each(|(k, v)| match v {
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

        e.unconfirmed_tokens.iter().for_each(|(k, v)| match v {
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

    pub fn export(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let history = self.history.read();

        if !history.is_empty() {
            buf.extend_from_slice(&history[0].0);
            history.iter().for_each(|(_, atoms)| {
                buf.extend(atoms);
            });
        } else {
            let checkpoint = self.checkpoint();

            let info = self.generate_checkpoint_info(checkpoint).to_vec();
            buf.extend(info);
            self.entries
                .iter()
                .filter(|e| self.accepted.contains(e.key()) && e.key() != &checkpoint)
                .for_each(|e| {
                    buf.extend(e.atom.to_vec());
                    buf.extend(e.witness.to_vec());
                });
        }

        buf
    }

    pub fn import(mut data: &[u8], config: Config) -> Result<Self, civita_serialize::Error> {
        let info = CheckopointInfo::from_reader(&mut data)?;

        let trie = {
            let mut t = Trie::with_root_hash(info.trie_root);
            let keys = info.related_keys.iter().map(|k| k.to_vec());
            if !t.resolve(keys, &info.trie_guide) {
                return Err(civita_serialize::Error("Failed to reconstruct trie".into()));
            }
            t
        };

        let related_token = {
            let mut m: HashMap<_, HashMap<_, _>> = HashMap::new();
            info.related_keys.iter().for_each(|k| {
                let key = k.to_vec();
                let token = Token::from_slice(&trie.get(&key).unwrap()).unwrap();
                match &config.storage_mode {
                    StorageMode::General { peer_id } => {
                        if V::is_related(&token.script_pk, peer_id) {
                            m.entry(*peer_id).or_default().insert(*k, token);
                        }
                    }
                    StorageMode::Archive { .. } => {
                        V::related_peers(&token.script_pk)
                            .into_iter()
                            .for_each(|p| {
                                m.entry(p).or_default().insert(*k, token.clone());
                            });
                    }
                }
            });
            m
        };

        let hash = info.atom.hash();

        let checkpoint = Entry {
            atom: info.atom,
            witness: info.witness,
            height: info.height,
            block_parent: hash,
            is_block: true,
            trie,
            related_token,
            is_missing: false,
            ..Default::default()
        };

        let entries = DashMap::from_iter([(hash, checkpoint)]);
        let difficulty = AtomicU64::new(info.difficulty);
        let vdf = WesolowskiVDFParams(config.vdf_params).new();

        let engine = Self {
            entries,
            accepted: DashSet::from_iter([hash]),
            rejected: DashSet::new(),
            ignored: DashSet::new(),
            main_head: ParkingLock::new(hash),
            checkpoint: ParkingLock::new(hash),
            history: ParkingLock::new(VecDeque::new()),
            vdf,
            difficulty,
            heaviest_weight: AtomicU64::new(0),
            config,
            _marker: std::marker::PhantomData,
        };

        while !data.is_empty() {
            let atom = Atom::from_reader(&mut data)?;
            let witness = Witness::from_reader(&mut data)?;

            if !engine.upsert(atom, witness).rejected.is_empty() {
                return Err(civita_serialize::Error(
                    "Imported data contains invalid atom".into(),
                ));
            }
        }

        Ok(engine)
    }
}
