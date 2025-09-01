use std::collections::{HashMap, HashSet, VecDeque};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use libp2p::PeerId;
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

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum RejectReason {
    Rejected,
    RejectedParent,
    EmptyParents,
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

#[derive(Clone, Copy)]
#[derive(Debug)]
enum Reason {
    Reject(RejectReason),
    Ignore(IgnoreReason),
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
    pub atom: Atom,
    pub witness: Witness,
    pub height: Height,
    pub children: HashSet<usize>,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub publishers: HashSet<PeerId>,
    pub related_token: HashMap<PeerId, HashMap<Multihash, Token>>,
    pub unconfirmed_tokens: HashMap<Multihash, Option<Token>>,

    // Pending only
    pub pending_parents: usize,
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
    index: HashMap<Multihash, usize>,
    entries: Vec<Entry>,
    free: Vec<usize>,

    accepted: HashSet<Multihash>,
    rejected: HashSet<Multihash>,
    ignored: HashSet<Multihash>,

    main_head: usize,
    checkpoint: usize,
    heaviest_weight: u64,

    history: VecDeque<(Vec<u8>, Vec<u8>)>,

    vdf: WesolowskiVDF,
    difficulty: u64,

    config: Config,
    _marker: std::marker::PhantomData<V>,
}

impl Entry {
    pub fn new(atom: Atom, witness: Witness) -> Self {
        Self {
            atom,
            witness,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn genesis() -> Self {
        Self {
            is_block: true,
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

        Self {
            index: HashMap::from_iter([(hash, 0)]),
            entries: vec![entry],
            free: Vec::new(),
            accepted: HashSet::from_iter([hash]),
            rejected: HashSet::new(),
            ignored: HashSet::new(),
            main_head: 0,
            checkpoint: 0,
            history: VecDeque::new(),
            heaviest_weight: 0,
            vdf: WesolowskiVDFParams(config.vdf_params).new(),
            difficulty: config.init_vdf_difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn upsert(&mut self, atom: Atom, witness: Witness) -> UpdateResult {
        let hash = atom.hash();
        let mut result = UpdateResult::default();

        if self.rejected.contains(&hash) {
            result.rejected.insert(hash, RejectReason::Rejected);
            return result;
        }

        if self.accepted.contains(&hash) {
            result.ignored.insert(hash, IgnoreReason::Accepted);
            return result;
        }

        if self.ignored.contains(&hash) {
            result.ignored.insert(hash, IgnoreReason::Ignored);
            return result;
        }

        let idx = self.create_entry(atom, witness);

        // Atoms must have least one block parent
        if self.entries[idx].witness.atoms.is_empty() {
            self.remove_subgraph(idx, RejectReason::EmptyParents, &mut result);
            return result;
        }

        if self.entries[idx].witness.atoms.contains(&hash) {
            self.remove_subgraph(idx, RejectReason::SelfReference, &mut result);
            return result;
        }

        if !self.link_parents(idx, &mut result) {
            return result;
        }

        self.validate(idx, &mut result);

        result
    }

    fn remove_subgraph<T: Into<Reason>>(
        &mut self,
        idx: usize,
        reason: T,
        result: &mut UpdateResult,
    ) {
        let reason = reason.into();

        let mut stk = VecDeque::new();
        let mut parents: HashMap<_, Vec<_>> = HashMap::new();

        stk.push_back(idx);

        while let Some(u) = stk.pop_front() {
            let hash = self.entries[u].hash();

            let already = match reason {
                Reason::Reject(_) => self.rejected.insert(hash),
                Reason::Ignore(_) => self.ignored.insert(hash),
            };

            if already {
                continue;
            }

            let mut entry = std::mem::take(&mut self.entries[u]);

            parents.remove(&u);
            self.index.remove(&hash);
            self.free.push(u);

            if !entry.is_missing && u != idx {
                match reason {
                    Reason::Reject(r) => {
                        result.rejected.insert(hash, r);
                    }
                    Reason::Ignore(r) => {
                        result.ignored.insert(hash, r);
                    }
                };

                entry
                    .witness
                    .atoms
                    .into_iter()
                    .filter_map(|h| self.index.get(&h).copied())
                    .for_each(|i| {
                        parents.entry(i).or_default().push(idx);
                    });
            }

            stk.extend(
                entry
                    .children
                    .drain()
                    .filter(|p| self.index.contains_key(&self.entries[*p].hash())),
            )
        }

        parents.into_iter().for_each(|(i, c)| {
            let e = &mut self.entries[i];
            c.into_iter().for_each(|ch| {
                e.children.remove(&ch);
            });
        });
    }

    fn create_entry(&mut self, atom: Atom, witness: Witness) -> usize {
        let hash = atom.hash();

        if let Some(&idx) = self.index.get(&hash) {
            let entry = &mut self.entries[idx];
            entry.atom = atom;
            entry.witness = witness;
            entry.is_missing = false;
            return idx;
        }

        if let Some(idx) = self.free.pop() {
            self.entries[idx] = Entry::new(atom, witness);
            self.index.insert(hash, idx);
            return idx;
        }

        let idx = self.entries.len();
        self.entries.push(Entry::new(atom, witness));
        self.index.insert(hash, idx);

        idx
    }

    pub fn contains(&self, h: &Multihash) -> bool {
        self.index
            .get(h)
            .is_some_and(|&i| !self.entries[i].is_missing)
    }

    fn link_parents(&mut self, idx: usize, result: &mut UpdateResult) -> bool {
        let cur = unsafe {
            let ptr = self.entries.as_mut_ptr();
            &mut *ptr.add(idx)
        };

        for p_hash in &cur.witness.atoms {
            if self.rejected.contains(p_hash) {
                self.remove_subgraph(idx, RejectReason::RejectedParent, result);
                return false;
            }

            if self.ignored.contains(p_hash) {
                self.remove_subgraph(idx, IgnoreReason::IgnoredParent, result);
                return false;
            }

            let pidx = self.index.get(p_hash).copied().unwrap_or_else(|| {
                let idx = self.free.pop().unwrap_or(self.entries.len());
                self.entries.push(Entry::default());
                self.index.insert(*p_hash, idx);
                result.missing.insert(*p_hash);
                idx
            });

            let parent = &mut self.entries[pidx];
            parent.children.insert(idx);

            if !parent.is_missing && parent.pending_parents == 0 {
                cur.pending_parents -= 1;
            }
        }

        true
    }

    fn validate(&mut self, idx: usize, result: &mut UpdateResult) {
        let cur = &self.entries[idx];
        let hash = cur.hash();

        if cur.pending_parents != 0 {
            return;
        }

        if self.entries[idx].atom.checkpoint != self.entries[self.checkpoint].hash() {
            self.remove_subgraph(idx, IgnoreReason::MimatchCheckpoint, result);
            return;
        }

        if self
            .vdf
            .verify(&hash.to_vec(), self.difficulty, &cur.witness.vdf_proof)
            .is_err()
        {
            self.remove_subgraph(idx, RejectReason::InvalidVdfProof, result);
            return;
        }

        if !cur
            .witness
            .atoms
            .iter()
            .all(|h| self.entries[self.index[h]].witness.atoms[0] == cur.witness.atoms[0])
        {
            self.remove_subgraph(idx, RejectReason::MimatchBlockParent, result);
            return;
        }

        let bp_idx = self.index[&cur.witness.atoms[0]];

        if cur.witness.atoms.len() < self.config.block_threshold as usize {
            let root_hash = self.entries[bp_idx].trie.root_hash();
            if let Err(e) = self.execute_atoms_with_hash(idx, root_hash) {
                self.remove_subgraph(idx, e, result);
                return;
            }

            let (cur, bp) = self.split_entries(idx, bp_idx);

            if let Some(cmd) = &cur.atom.cmd {
                if cmd
                    .consumed
                    .iter()
                    .any(|id| bp.unconfirmed_tokens.contains_key(id))
                {
                    bp.children.remove(&idx);
                } else {
                    bp.unconfirmed_tokens.extend(
                        cmd.created
                            .iter()
                            .cloned()
                            .enumerate()
                            .map(|(i, t)| {
                                let data = (cur.hash(), i as u32).to_vec();
                                let id = Hasher::digest(&data);
                                (id, Some(t))
                            })
                            .chain(cmd.consumed.iter().copied().map(|id| (id, None))),
                    );
                }
            }

            cur.height = bp.height + 1;
            result.accepted.insert(hash);
            return;
        }

        let mut trie = self.entries[bp_idx].trie.clone();
        let mut related = self.entries[bp_idx].related_token.clone();
        let publishers = match self.execute_atoms_with_trie(idx, &mut trie, &mut related) {
            Ok(v) => v,
            Err(r) => {
                self.remove_subgraph(idx, r, result);
                return;
            }
        };

        if !self.validate_checkpoint_update(idx, &publishers) {
            self.remove_subgraph(idx, RejectReason::NotHeaviestChain, result);
            return;
        }

        self.update_publishers(bp_idx, &publishers);
        self.recompute_main_chain_and_checkpoint();

        result.accepted.insert(hash);

        {
            let cur = &mut self.entries[idx];
            cur.is_block = true;
            cur.trie = trie;
            cur.related_token = related;
        }

        let cur = unsafe {
            let ptr = self.entries.as_mut_ptr();
            &mut *ptr.add(idx)
        };

        cur.children.iter().copied().for_each(|i| {
            self.entries[i].pending_parents -= 1;
            self.validate(i, result);
        });
    }

    fn split_entries(&mut self, cur: usize, parent: usize) -> (&mut Entry, &mut Entry) {
        if cur < parent {
            let (l, r) = self.entries.split_at_mut(parent);
            (&mut l[cur], &mut r[0])
        } else {
            let (l, r) = self.entries.split_at_mut(cur);
            (&mut r[0], &mut l[parent])
        }
    }

    fn execute_atoms_with_hash(
        &self,
        idx: usize,
        root_hash: Multihash,
    ) -> Result<(), RejectReason> {
        let mut state = HashMap::new();
        let atoms = &self.entries[idx].witness.atoms[1..];

        for idx in atoms
            .iter()
            .map(|idx| self.index[idx])
            .chain(std::iter::once(idx))
        {
            let cur = &self.entries[idx];
            let is_validated = self.accepted.contains(&cur.hash());

            let Some(cmd) = &cur.atom.cmd else {
                continue;
            };

            let inputs = cmd.input.iter().try_fold(HashMap::new(), |mut acc, hash| {
                let token = state
                    .remove(hash)
                    .or_else(|| {
                        let key = hash.to_vec();
                        Trie::verify_proof(root_hash, &key, &cur.witness.trie_proofs)
                            .ok()?
                            .map(|v| Token::from_slice(&v).unwrap())
                            .into()
                    })
                    .flatten()
                    .ok_or(RejectReason::MissingInput)?;

                if !is_validated && !cur.validate_script_sig::<V>(hash, &token.script_pk) {
                    return Err(RejectReason::InvalidScriptSig);
                }

                acc.insert(*hash, token);
                Ok(acc)
            })?;

            if !is_validated && !cur.validate_conversion::<V>(inputs.values()) {
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
                let data = (cur.hash(), i as u32).to_vec();
                let hash = Hasher::digest(&data);
                state.insert(hash, Some(t));
            });
        }

        Ok(())
    }

    fn execute_atoms_with_trie(
        &self,
        idx: usize,
        trie: &mut Trie,
        related: &mut HashMap<PeerId, HashMap<Multihash, Token>>,
    ) -> Result<HashSet<PeerId>, RejectReason> {
        let mut state = HashMap::new();
        let mut publishers = HashSet::new();

        let atoms = &self.entries[idx].witness.atoms[1..];

        for idx in atoms
            .iter()
            .map(|idx| self.index[idx])
            .chain(std::iter::once(idx))
        {
            let cur = &self.entries[idx];
            let is_validated = self.accepted.contains(&cur.hash());

            if let Some(cmd) = &cur.atom.cmd {
                let inputs = cmd.input.iter().try_fold(HashMap::new(), |mut acc, hash| {
                    let token = state
                        .remove(hash)
                        .or_else(|| {
                            let key = hash.to_vec();
                            trie.resolve(std::iter::once(&key), &cur.witness.trie_proofs)
                                .then_some(Some(
                                    Token::from_slice(&trie.get(&key).unwrap()).unwrap(),
                                ))
                        })
                        .flatten()
                        .ok_or(RejectReason::MissingInput)?;

                    if !is_validated && !cur.validate_script_sig::<V>(hash, &token.script_pk) {
                        return Err(RejectReason::InvalidScriptSig);
                    }

                    acc.insert(*hash, token);

                    Ok(acc)
                })?;

                if !is_validated && !cur.validate_conversion::<V>(inputs.values()) {
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
                    let data = (cur.hash(), i as u32).to_vec();
                    let hash = Hasher::digest(&data);
                    state.insert(hash, Some(t));
                });
            }

            publishers.insert(cur.atom.peer);
        }

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

        Ok(publishers)
    }

    fn validate_checkpoint_update(&mut self, idx: usize, publishers: &HashSet<PeerId>) -> bool {
        let target_idx = self.target_checkpoint_of(idx);

        let publishers = self.entries[target_idx]
            .publishers
            .iter()
            .chain(publishers.iter())
            .cloned()
            .collect::<HashSet<_>>();

        let len = publishers.len() as u64;
        self.heaviest_weight = self.heaviest_weight.max(len);
        len > self.heaviest_weight
    }

    fn target_checkpoint_of(&self, mut cur: usize) -> usize {
        let target_height = self.entries[cur].height + self.config.checkpoint_distance;
        loop {
            let e = &self.entries[cur];
            if e.height == target_height {
                break cur;
            }
            cur = self.index[&e.witness.atoms[0]];
        }
    }

    fn update_publishers(&mut self, mut cur: usize, publishers: &HashSet<PeerId>) {
        loop {
            let e = &mut self.entries[cur];
            e.publishers.extend(publishers.iter().cloned());

            if cur == self.checkpoint {
                break;
            }

            cur = self.index[&e.witness.atoms[0]];
        }
    }

    fn recompute_main_chain_and_checkpoint(&mut self) {
        let start = self.checkpoint;
        let new_head = self.ghost_select(start);

        if new_head == self.main_head {
            return;
        }

        self.main_head = new_head;
        self.maybe_advance_checkpoint();
    }

    fn ghost_select(&self, mut cur: usize) -> usize {
        while let Some(next) = self.entries[cur]
            .children
            .iter()
            .copied()
            .map(|c| (self.entries[c].publishers.len(), c))
            .max()
            .map(|(.., c)| c)
        {
            cur = next;
        }

        cur
    }

    fn maybe_advance_checkpoint(&mut self) {
        let prev_height = self.entries[self.checkpoint].height;
        let head_height = self.entries[self.main_head].height;
        let target_height = prev_height + self.config.checkpoint_distance;
        let trigger_height = prev_height + self.config.checkpoint_distance * 2;

        if head_height != trigger_height {
            return;
        }

        let target_idx = self.target_checkpoint_of(self.main_head);
        let (times, atoms) = self.walk_and_collection(self.main_head, target_idx);
        let difficulty = self.adjust_difficulty(times);
        self.clean_to_height(target_height, target_idx);

        {
            let len = match self.config.storage_mode {
                StorageMode::General { .. } => Some(0),
                StorageMode::Archive { retain_checkpoints } => retain_checkpoints,
            };

            if len.is_some_and(|l| l == 0) {
                return;
            }

            if len.is_some_and(|l| self.history.len() >= l as usize) {
                self.history.pop_front();
            }
        }

        let info = self.generate_checkpoint_info(target_idx).to_vec();
        let buf = atoms.into_iter().fold(Vec::new(), |mut acc, e| {
            acc.extend(e.atom.to_vec());
            acc.extend(e.witness.to_vec());
            acc
        });

        self.checkpoint = target_idx;
        self.difficulty = difficulty;
        self.history.push_back((info.to_vec(), buf));
    }

    fn walk_and_collection(&mut self, start: usize, end: usize) -> (Vec<u64>, Vec<Entry>) {
        let mut atoms = Vec::new();
        let mut times = Vec::new();
        let mut cur = start;
        let mut next_time: Option<u64> = None;

        loop {
            let e = std::mem::take(&mut self.entries[cur]);
            self.index.remove(&e.hash());
            self.free.push(cur);

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

            cur = self.index[&e.witness.atoms[0]];
            atoms.extend(e.witness.atoms.iter().copied().map(|h| {
                let e = std::mem::take(&mut self.entries[self.index[&h]]);
                self.index.remove(&e.hash());
                self.free.push(self.index[&h]);
                e
            }));
            atoms.push(e);
        }

        (times, atoms)
    }

    fn clean_to_height(&mut self, target: Height, idx: usize) {
        let hash = self.entries[idx].hash();
        self.entries.iter_mut().for_each(|e| {
            let e_hash = e.hash();
            if e.height <= target && e_hash != hash {
                std::mem::take(e);
                self.index.remove(&e_hash);
                self.free.push(self.index[&e_hash]);
            }
        });
    }

    fn adjust_difficulty(&self, mut times: Vec<u64>) -> u64 {
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

        ((self.difficulty as f32 * ratio) as u64).max(1)
    }

    fn generate_checkpoint_info(&self, idx: usize) -> CheckopointInfo {
        let e = &self.entries[idx];
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
        self.difficulty
    }

    pub fn get(&self, h: &Multihash) -> Option<(Atom, Witness)> {
        self.index.get(h).and_then(|&i| {
            let e = &self.entries[i];
            (!e.is_missing).then(|| (e.atom.clone(), e.witness.clone()))
        })
    }

    pub fn tokens_for(&self, peer: &PeerId) -> HashMap<Multihash, Token> {
        let h = self.main_head;
        let e = &self.entries[h];

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
        let h = self.main_head;
        let e = &self.entries[h];

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
        self.entries[self.main_head].hash()
    }

    pub fn get_children(&self, h: &Multihash) -> HashSet<Multihash> {
        let e = &self.entries[self.index[h]];

        debug_assert!(e.is_block);

        e.children
            .iter()
            .copied()
            .filter_map(|idx| {
                let e = &self.entries[idx];
                (e.is_block && !e.is_missing).then_some(e.hash())
            })
            .collect()
    }

    pub fn generate_proofs<'a>(
        &self,
        token_ids: impl Iterator<Item = &'a Multihash>,
        h: &Multihash,
    ) -> HashMap<Multihash, Vec<u8>> {
        let e = &self.entries[self.index[h]];
        e.trie
            .generate_guide(token_ids.map(|id| id.to_vec()))
            .expect("Proofs must be generated")
    }

    pub fn checkpoint(&self) -> Multihash {
        self.entries[self.checkpoint].hash()
    }

    pub fn export(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let history = &self.history;

        if !history.is_empty() {
            buf.extend_from_slice(&history[0].0);
            history.iter().for_each(|(_, atoms)| {
                buf.extend(atoms);
            });
        } else {
            let info = self.generate_checkpoint_info(self.checkpoint).to_vec();
            buf.extend(info);
            let checkpoint_hash = self.entries[self.checkpoint].hash();
            self.entries
                .iter()
                .filter(|e| {
                    let hash = e.hash();
                    self.accepted.contains(&hash) && hash != checkpoint_hash
                })
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
            is_block: true,
            trie,
            related_token,
            is_missing: false,
            ..Default::default()
        };

        let index = HashMap::from_iter([(hash, 0)]);
        let entries = vec![checkpoint];
        let vdf = WesolowskiVDFParams(config.vdf_params).new();

        let mut engine = Self {
            index,
            entries,
            free: Vec::new(),
            accepted: HashSet::from_iter([hash]),
            rejected: HashSet::new(),
            ignored: HashSet::new(),
            main_head: 0,
            checkpoint: 0,
            history: VecDeque::new(),
            vdf,
            difficulty: info.difficulty,
            heaviest_weight: 0,
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

impl From<RejectReason> for Reason {
    fn from(r: RejectReason) -> Self {
        Reason::Reject(r)
    }
}

impl From<IgnoreReason> for Reason {
    fn from(r: IgnoreReason) -> Self {
        Reason::Ignore(r)
    }
}
