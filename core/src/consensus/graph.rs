use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::SystemTime,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use libp2p::PeerId;
use num_bigint::BigUint;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::validator::Validator,
    crypto::{hasher::Hasher, Multihash},
    ty::{
        atom::{Atom, Command, Height, Input},
        token::Token,
    },
    utils::mmr::Mmr,
};

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum RejectReason {
    AlreadyDismissed,
    DismissedParent,
    HeightBelowCheckpoint,
    SelfReference,
    ParentInAtoms,
    CheckpointMismatch,
    BlockInAtoms,
    InvalidTokenId,
    InvalidHeight,
    InvalidScriptSig,
    InvalidConversion,
    InvalidNonce,
    InvalidProof,
    MissingInput,
    MissingProof,
    DoubleSpend,
    EmptyInput,
}

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum CreationError {
    #[error("One or more input tokens are already consumed")]
    InputConsumed,

    #[error("Failed to generate trie guide for input tokens")]
    FailedToGenerateGuide,

    #[error("No input tokens provided")]
    NoInput,

    #[error("Unknown token id")]
    UnknownTokenId,

    #[error("Failed to prove input token in MMR")]
    FailedToProveInput,

    #[error("Missing script signature for input token")]
    MissingScriptSig,
}

#[derive(Default)]
#[derive(Debug)]
pub struct UpdateResult {
    pub accepted: HashSet<Multihash>,
    pub rejected: HashMap<Multihash, RejectReason>,
    pub missing: HashSet<Multihash>,
}

#[derive(Clone, Copy)]
pub enum StorageMode {
    General(PeerId),
    Archive(u32),
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    pub atom: Atom,
    pub children: HashSet<Multihash>,

    // Block only
    pub is_block: bool,
    pub mmr: Mmr,

    pub confirmed_indices: HashMap<PeerId, HashMap<Multihash, BigUint>>,
    pub confirmed_tokens: HashMap<BigUint, Token>,

    pub unconfirmed_tokens: HashMap<Multihash, Option<Token>>,

    pub cmd_hashes: HashSet<Multihash>,

    // Pending only
    pub pending_parents: usize,
    #[derivative(Default(value = "true"))]
    pub is_missing: bool,
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    #[derivative(Default(value = "1000"))]
    pub block_threshold: u32,

    #[derivative(Default(value = "10"))]
    pub checkpoint_distance: Height,

    #[derivative(Default(value = "60"))]
    pub target_block_time: u64,

    #[derivative(Default(value = "50000"))]
    pub init_vdf_difficulty: u64,

    #[derivative(Default(value = "0.1"))]
    pub max_difficulty_adjustment: f32,

    #[derivative(Default(value = "StorageMode::Archive(1)"))]
    pub storage_mode: StorageMode,

    #[derivative(Default(value = "1024"))]
    pub vdf_params: u16,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub atom: Atom,
    pub difficulty: u64,
    pub mmr: Mmr,
    pub tokens: HashMap<BigUint, Token>,
}

pub struct Graph<V> {
    entries: HashMap<Multihash, Entry>,
    dismissed: HashSet<Multihash>,

    main_head: Multihash,
    checkpoint: Multihash,
    checkpoint_height: Height,

    history: VecDeque<(Vec<u8>, Vec<u8>)>,

    vdf: WesolowskiVDF,
    difficulty: u64,

    config: Config,
    _marker: std::marker::PhantomData<V>,
}

impl Entry {
    pub fn new(atom: Atom) -> Self {
        Self {
            atom,
            is_missing: false,
            ..Default::default()
        }
    }
}

impl Snapshot {
    pub fn new(atom: Atom, difficulty: u64, mmr: Mmr, tokens: HashMap<BigUint, Token>) -> Self {
        Self {
            atom,
            difficulty,
            mmr,
            tokens,
        }
    }
}

impl<V: Validator> Graph<V> {
    pub fn empty(config: Config) -> Self {
        Self::with_genesis(Atom::default(), Mmr::default(), HashMap::new(), config)
    }

    pub fn with_genesis(
        atom: Atom,
        mmr: Mmr,
        tokens: HashMap<BigUint, Token>,
        config: Config,
    ) -> Self {
        let hash = atom.hash;

        let entry = {
            let indices = Self::resolve_related(&mmr, &tokens, &config.storage_mode);

            Entry {
                atom,
                is_block: true,
                mmr,
                confirmed_indices: indices,
                confirmed_tokens: tokens.clone(),
                is_missing: false,
                ..Default::default()
            }
        };

        let snapshot = Snapshot::new(
            entry.atom.clone(),
            config.init_vdf_difficulty,
            entry.mmr.clone(),
            tokens,
        );
        let history = VecDeque::from_iter([(snapshot.to_vec(), Vec::new())]);

        Self {
            entries: HashMap::from_iter([(hash, entry)]),
            dismissed: HashSet::new(),
            main_head: hash,
            checkpoint: hash,
            checkpoint_height: 0,
            history,
            vdf: WesolowskiVDFParams(config.vdf_params).new(),
            difficulty: config.init_vdf_difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    fn resolve_related(
        mmr: &Mmr,
        tokens: &HashMap<BigUint, Token>,
        mode: &StorageMode,
    ) -> HashMap<PeerId, HashMap<Multihash, BigUint>> {
        let target = match mode {
            StorageMode::General(p) => Some(*p),
            StorageMode::Archive(..) => None,
        };

        let mut indices: HashMap<_, HashMap<_, _>> = HashMap::new();

        mmr.leaves().into_iter().for_each(|idx| {
            let token = tokens.get(&idx).expect("MMR must be consistent");

            if let Some(p) = target {
                if V::is_related(&token.script_pk, &p) {
                    indices.entry(p).or_default().insert(token.id, idx.clone());
                }
            } else {
                V::related_peers(&token.script_pk)
                    .into_iter()
                    .for_each(|p| {
                        indices.entry(p).or_default().insert(token.id, idx.clone());
                    });
            }
        });

        indices
    }

    pub fn upsert(&mut self, atom: Atom) -> Option<UpdateResult> {
        let mut result = UpdateResult::default();
        let hash = atom.hash;

        if self.contains(&hash) {
            return None;
        }

        match self.entries.get_mut(&hash) {
            Some(e) => {
                e.atom = atom;
                e.is_missing = false;
            }
            None => {
                self.entries.insert(hash, Entry::new(atom));
            }
        };

        if let Err(r) = self.basic_validation(&hash) {
            self.remove_subgraph(hash, r, &mut result);
            return Some(result);
        }

        match self.validate_parents(hash) {
            Ok(missing) => {
                if !missing.is_empty() {
                    self.entries.get_mut(&hash).unwrap().pending_parents = missing.len();
                    result.missing = missing;
                    return Some(result);
                }
            }
            Err(r) => {
                self.remove_subgraph(hash, r, &mut result);
                return Some(result);
            }
        }

        if let Err(r) = self.final_validation(hash) {
            self.remove_subgraph(hash, r, &mut result);
            return Some(result);
        }

        result.accepted.insert(hash);

        for child in self.entries[&hash].children.clone() {
            let child_entry = self.entries.get_mut(&child).unwrap();
            child_entry.pending_parents -= 1;

            if child_entry.pending_parents == 0 {
                if let Err(r) = self.final_validation(child) {
                    self.remove_subgraph(child, r, &mut result);
                } else {
                    result.accepted.insert(child);
                }
            }
        }

        Some(result)
    }

    fn contains(&self, h: &Multihash) -> bool {
        !self.dismissed.contains(h) && self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn basic_validation(&self, hash: &Multihash) -> Result<(), RejectReason> {
        let atom = &self.entries[hash].atom;

        if self.dismissed.contains(hash) {
            return Err(RejectReason::AlreadyDismissed);
        }

        if atom.height < self.checkpoint_height {
            return Err(RejectReason::HeightBelowCheckpoint);
        }

        if &atom.parent == hash {
            return Err(RejectReason::SelfReference);
        }

        if atom.atoms.contains(hash) {
            return Err(RejectReason::SelfReference);
        }

        if atom.atoms.contains(&atom.parent) {
            return Err(RejectReason::ParentInAtoms);
        }

        Ok(())
    }

    fn remove_subgraph(
        &mut self,
        hash: Multihash,
        reason: RejectReason,
        result: &mut UpdateResult,
    ) {
        if !self.dismissed.insert(hash) {
            return;
        }

        result.rejected.insert(hash, reason);

        let Some(entry) = self.entries.remove(&hash) else {
            return;
        };

        let mut stk = VecDeque::new();
        stk.extend(entry.children);

        while let Some(u) = stk.pop_front() {
            if !self.dismissed.insert(u) {
                continue;
            }

            let Some(entry) = self.entries.remove(&u) else {
                continue;
            };

            if !entry.is_missing {
                result.rejected.insert(u, RejectReason::DismissedParent);
            }

            entry.children.into_iter().for_each(|p| {
                stk.push_back(p);
            });
        }
    }

    fn validate_parents(&mut self, hash: Multihash) -> Result<HashSet<Multihash>, RejectReason> {
        let mut missing = HashSet::new();

        let parents = {
            let atom = &self.entries[&hash].atom;
            let mut atoms = atom.atoms.clone();
            atoms.push(atom.parent);
            atoms
        };

        for parent in parents {
            if self.dismissed.contains(&parent) {
                return Err(RejectReason::DismissedParent);
            }

            let parent = self.entries.entry(parent).or_insert_with(|| {
                missing.insert(parent);
                Entry::default()
            });

            parent.children.insert(hash);
        }

        Ok(missing)
    }

    fn final_validation(&mut self, hash: Multihash) -> Result<(), RejectReason> {
        let atom = &self.entries[&hash].atom;

        if atom.checkpoint != self.checkpoint {
            return Err(RejectReason::CheckpointMismatch);
        }

        if atom.height != self.entries[&atom.parent].atom.height + 1 {
            return Err(RejectReason::InvalidHeight);
        }

        if atom.atoms.iter().any(|h| self.entries[h].is_block) {
            return Err(RejectReason::BlockInAtoms);
        }

        if self
            .vdf
            .verify(&hash.to_vec(), self.difficulty, &atom.nonce)
            .is_err()
        {
            return Err(RejectReason::InvalidNonce);
        }

        let is_block = self.validate_execution(&hash)?;

        self.history
            .iter_mut()
            .last()
            .unwrap()
            .1
            .extend(self.entries[&hash].atom.to_vec());

        if !is_block {
            return Ok(());
        }

        self.update_weight(hash);
        self.recompute_main_chain_and_checkpoint();

        Ok(())
    }

    fn validate_execution(&mut self, target_hash: &Multihash) -> Result<bool, RejectReason> {
        let mut created: Vec<Token> = Vec::new();
        let mut consumed: HashMap<Multihash, BigUint> = HashMap::new();

        let mut excluded = false;
        let mut cmd_hashes = HashSet::new();
        let parent_hash = self.entries[target_hash].atom.parent;
        let mut mmr = self.entries[&parent_hash].mmr.clone();

        for hash in self.entries[target_hash]
            .atom
            .atoms
            .clone()
            .iter()
            .chain(std::iter::once(target_hash))
        {
            let (cur, parent) = self.get_two_entries_mut(hash, &parent_hash);

            let Some(cmd) = &cur.atom.cmd else {
                continue;
            };

            if cmd.inputs.is_empty() {
                return Err(RejectReason::EmptyInput);
            }

            cmd_hashes.insert(*hash);

            let inputs = cmd
                .inputs
                .iter()
                .cloned()
                .try_fold(Vec::new(), |mut acc, input| match input {
                    Input::Confirmed(token, idx, proof, sig) => {
                        if consumed.insert(token.id, idx.clone()).is_some() {
                            return Err(RejectReason::DoubleSpend);
                        }

                        if !mmr.delete(idx, token.id, &proof) {
                            return Err(RejectReason::InvalidProof);
                        }

                        if hash == target_hash && !V::validate_script_sig(&sig, &token.script_pk) {
                            return Err(RejectReason::InvalidScriptSig);
                        }

                        excluded |= parent
                            .unconfirmed_tokens
                            .get(&token.id)
                            .is_some_and(|t| t.is_none());

                        acc.push(token);
                        Ok(acc)
                    }
                    Input::Unconfirmed(token_id, sig) => {
                        let Some(token) = created
                            .binary_search_by_key(&&token_id, |t| &t.id)
                            .ok()
                            .map(|i| created.remove(i))
                        else {
                            return Err(RejectReason::MissingInput);
                        };

                        if hash == target_hash && !V::validate_script_sig(&sig, &token.script_pk) {
                            return Err(RejectReason::InvalidScriptSig);
                        }

                        excluded |= parent
                            .unconfirmed_tokens
                            .get(&token.id)
                            .is_some_and(|t| t.is_none());

                        acc.push(token);

                        Ok(acc)
                    }
                })?;

            if hash == target_hash {
                if !Self::is_token_id_valid(*cmd.inputs[0].id(), &cmd.created) {
                    return Err(RejectReason::InvalidTokenId);
                }

                if !V::validate_conversion(cmd.code, &inputs, &cmd.created) {
                    return Err(RejectReason::InvalidConversion);
                }
            }

            cmd.created.iter().cloned().for_each(|token| {
                created.push(token);
            });
        }

        let threshold = self.config.block_threshold as usize;

        let (target, parent) = self.get_two_entries_mut(target_hash, &parent_hash);

        if target.atom.atoms.len() + 1 < threshold {
            if excluded {
                parent.children.remove(target_hash);
            } else {
                parent
                    .unconfirmed_tokens
                    .extend(consumed.into_keys().map(|id| (id, None)));
            }
            return Ok(false);
        }

        let mut confirmed_indices = parent.confirmed_indices.clone();
        let mut confirmed_tokens = parent.confirmed_tokens.clone();

        consumed.into_iter().for_each(|(id, idx)| {
            confirmed_tokens.remove(&idx);
            confirmed_indices.values_mut().for_each(|v| {
                v.remove(&id);
            });
        });

        created.into_iter().for_each(|token| {
            let idx = mmr.append(token.id);

            match &self.config.storage_mode {
                StorageMode::General(p) => {
                    if V::is_related(&token.script_pk, p) {
                        confirmed_indices
                            .entry(*p)
                            .or_default()
                            .insert(token.id, idx.clone());
                        confirmed_tokens.insert(idx, token);
                    }
                }
                StorageMode::Archive(..) => {
                    V::related_peers(&token.script_pk)
                        .into_iter()
                        .for_each(|p| {
                            confirmed_indices
                                .entry(p)
                                .or_default()
                                .insert(token.id, idx.clone());
                            confirmed_tokens.insert(idx.clone(), token.clone());
                        });
                }
            }
        });

        mmr.commit();
        mmr.prune(confirmed_indices.values().flat_map(|m| m.values()).cloned());

        let cur = self.entries.get_mut(target_hash).unwrap();
        cur.mmr = mmr;
        cur.confirmed_indices = confirmed_indices;
        cur.confirmed_tokens = confirmed_tokens;
        cur.cmd_hashes = cmd_hashes;
        cur.is_block = true;

        Ok(true)
    }

    fn get_two_entries_mut(&mut self, a: &Multihash, b: &Multihash) -> (&mut Entry, &mut Entry) {
        match self.entries.get_disjoint_mut([a, b]) {
            [Some(e1), Some(e2)] => (e1, e2),
            _ => unreachable!(),
        }
    }

    fn is_token_id_valid(first_input: Multihash, tokens: &[Token]) -> bool {
        tokens
            .iter()
            .enumerate()
            .all(|(i, t)| Hasher::validate(&t.id, &(first_input, i as u32).to_vec()))
    }

    fn update_weight(&mut self, start: Multihash) {
        let (cmds, mut cur) = {
            let e = self.entries.get(&start).unwrap();
            (e.cmd_hashes.clone(), e.atom.parent)
        };

        while cur != self.checkpoint {
            let entry = self.entries.get_mut(&cur).unwrap();
            entry.cmd_hashes.extend(cmds.iter().copied());
            cur = entry.atom.parent;
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

    fn ghost_select(&self, mut cur: Multihash) -> Multihash {
        while let Some(next) = self
            .entries
            .get(&cur)
            .unwrap()
            .children
            .iter()
            .copied()
            .map(|c| (self.entries[&c].cmd_hashes.len(), c))
            .max()
            .map(|(.., c)| c)
        {
            cur = next;
        }

        cur
    }

    fn maybe_advance_checkpoint(&mut self) {
        let prev_height = self.entries[&self.checkpoint].atom.height;
        let head_height = self.entries[&self.main_head].atom.height;

        if head_height != prev_height + self.config.checkpoint_distance * 2 {
            return;
        }

        let next_height = prev_height + self.config.checkpoint_distance;
        let next_hash = self.get_block_at_height(self.main_head, next_height);

        let times = self.collect_times(next_hash, self.checkpoint);
        let difficulty = self.adjust_difficulty(times);

        self.entries.retain(|_, e| e.atom.checkpoint == next_hash);

        let snapshot = {
            let entry = &self.entries[&next_hash];
            Snapshot {
                atom: entry.atom.clone(),
                difficulty,
                mmr: entry.mmr.clone(),
                tokens: entry.confirmed_tokens.clone(),
            }
        };

        {
            let len = match self.config.storage_mode {
                StorageMode::General(..) => 1,
                StorageMode::Archive(l) => l,
            };

            if len != 0 && self.history.len() >= len as usize {
                self.history.pop_front();
            }
        }

        self.history.push_back((snapshot.to_vec(), Vec::new()));
        self.checkpoint_height = next_height;
        self.checkpoint = next_hash;
        self.difficulty = difficulty;
    }

    fn get_block_at_height(&self, mut cur: Multihash, height: Height) -> Multihash {
        loop {
            let e = &self.entries[&cur];
            if e.atom.height == height {
                break e.atom.hash;
            }
            cur = e.atom.parent;
        }
    }

    fn collect_times(&mut self, start: Multihash, end: Multihash) -> Vec<u64> {
        let mut times = Vec::new();

        let (mut cur, mut next_time) = {
            let entry = &self.entries[&start];
            (entry.atom.parent, entry.atom.timestamp)
        };

        loop {
            let entry = &self.entries[&cur];

            let dt = next_time.saturating_sub(entry.atom.timestamp);
            if dt > 0 {
                times.push(dt);
            }

            next_time = entry.atom.timestamp;
            cur = entry.atom.parent;

            if cur == end {
                break;
            }
        }

        times
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

        let target = self.config.target_block_time as f32;
        let ratio_raw = target / median;
        let ratio = ratio_raw.clamp(
            1.0 / self.config.max_difficulty_adjustment,
            self.config.max_difficulty_adjustment,
        );

        ((self.difficulty as f32 * ratio) as u64).max(1)
    }

    pub fn get(&self, h: &Multihash) -> Option<&Atom> {
        self.entries
            .get(h)
            .and_then(|e| (!e.is_missing).then_some(&e.atom))
    }

    pub fn tokens_for(&self, peer: &PeerId) -> Vec<Token> {
        let entry = &self.entries[&self.main_head];

        let mut tokens: Vec<_> = entry
            .confirmed_indices
            .get(peer)
            .map(|idxs| {
                idxs.values()
                    .map(|i| entry.confirmed_tokens[i].clone())
                    .collect()
            })
            .unwrap_or_default();

        entry.unconfirmed_tokens.iter().for_each(|(k, v)| match v {
            Some(t) => match &self.config.storage_mode {
                StorageMode::General(p) => {
                    if p == peer && V::is_related(&t.script_pk, peer) {
                        tokens.push(t.clone());
                    }
                }
                StorageMode::Archive(..) => {
                    if V::related_peers(&t.script_pk).binary_search(peer).is_ok() {
                        tokens.push(t.clone());
                    }
                }
            },
            None => {
                if let Ok(i) = tokens.binary_search_by_key(k, |t| t.id) {
                    tokens.remove(i);
                }
            }
        });

        tokens
    }

    pub fn export(&self, peer_id: Option<PeerId>) -> Option<Vec<u8>> {
        if let StorageMode::General(p) = &self.config.storage_mode {
            if peer_id.is_none_or(|id| &id != p) {
                return None;
            }
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.history[0].0);
        self.history.iter().for_each(|(_, atoms)| {
            buf.extend(atoms);
        });

        Some(buf)
    }

    pub fn import(mut data: &[u8], config: Config) -> Result<Self, civita_serialize::Error> {
        let info = Snapshot::from_reader(&mut data)?;

        let hash = info.atom.hash;
        let height = info.atom.height;
        let history = VecDeque::from_iter([(info.to_vec(), Vec::new())]);

        let entry = {
            let confirmed_indices =
                Self::resolve_related(&info.mmr, &info.tokens, &config.storage_mode);

            Entry {
                atom: info.atom,
                is_block: true,
                mmr: info.mmr,
                confirmed_indices,
                confirmed_tokens: info.tokens,
                is_missing: false,
                ..Default::default()
            }
        };

        let mut graph = Self {
            entries: HashMap::from_iter([(hash, entry)]),
            dismissed: HashSet::new(),
            main_head: hash,
            checkpoint: hash,
            checkpoint_height: height,
            history,
            vdf: WesolowskiVDFParams(config.vdf_params).new(),
            difficulty: info.difficulty,
            config,
            _marker: std::marker::PhantomData,
        };

        while !data.is_empty() {
            let atom = Atom::from_reader(&mut data)?;
            if !graph.upsert(atom).is_some_and(|r| r.rejected.is_empty()) {
                return Err(civita_serialize::Error(
                    "Imported data contains invalid atom".into(),
                ));
            }
        }

        Ok(graph)
    }

    pub fn create_command<I>(
        &self,
        code: u8,
        iter: I,
        created: Vec<Token>,
        peer: &PeerId,
    ) -> Result<Command, CreationError>
    where
        I: IntoIterator<Item = (Multihash, Vec<u8>)>,
    {
        let head = &self.entries[&self.main_head];
        let map = &head.confirmed_indices[peer];

        let inputs = iter
            .into_iter()
            .try_fold(Vec::new(), |mut inputs, (id, sig)| {
                let idx = map.get(&id).ok_or(CreationError::UnknownTokenId)?;

                match head.confirmed_tokens.get(idx) {
                    Some(token) => {
                        let proof = head
                            .mmr
                            .prove(idx.clone())
                            .ok_or(CreationError::FailedToProveInput)?;
                        inputs.push(Input::Confirmed(token.clone(), idx.clone(), proof, sig));
                        Ok(inputs)
                    }
                    None => {
                        let Some(token) = head.unconfirmed_tokens.get(&id) else {
                            return Err(CreationError::UnknownTokenId);
                        };

                        if token.is_none() {
                            return Err(CreationError::InputConsumed);
                        }

                        inputs.push(Input::Unconfirmed(id, sig));
                        Ok(inputs)
                    }
                }
            })?;

        Ok(Command {
            code,
            inputs,
            created,
        })
    }

    pub fn create_atom(&self, cmd: Option<Command>) -> Result<JoinHandle<Atom>, CreationError> {
        let mut atom = Atom {
            hash: Multihash::default(),
            parent: self.main_head,
            checkpoint: self.checkpoint,
            height: self.entries[&self.main_head].atom.height + 1,
            nonce: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cmd,
            atoms: self.get_children(self.main_head),
        };

        let vdf = self.vdf.clone();
        let difficulty = self.difficulty;

        Ok(tokio::spawn(async move {
            atom.nonce = vdf
                .solve(&atom.vdf_input(), difficulty)
                .expect("VDF must be solved");
            atom.hash = Hasher::digest(&atom.hash_input());
            atom
        }))
    }

    fn get_children(&self, h: Multihash) -> Vec<Multihash> {
        let entry = &self.entries[&h];

        let mut indeg: HashMap<_, usize> = HashMap::from_iter(
            entry
                .children
                .iter()
                .filter(|c| self.contains(c))
                .map(|c| (*c, self.entries[c].atom.atoms.len())),
        );

        let mut result = Vec::with_capacity(indeg.len());
        let mut stk = VecDeque::from_iter(
            indeg
                .iter()
                .filter(|(_, &d)| d == 0)
                .map(|(k, _)| *k)
                .collect::<VecDeque<_>>(),
        );

        while let Some(u) = stk.pop_front() {
            result.push(u);
            self.entries[&u].children.iter().for_each(|c| {
                if let Some(d) = indeg.get_mut(c) {
                    *d -= 1;
                    if *d == 0 {
                        stk.push_back(*c);
                    }
                }
            });
        }

        result
    }
}
