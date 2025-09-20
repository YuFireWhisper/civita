use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::SystemTime,
};

use bincode::error::DecodeError;
use derivative::Derivative;
use libp2p::PeerId;
use multihash_derive::MultihashDigest;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::{graph::storage::Storage, validator::Validator},
    crypto::{hasher::Hasher, Multihash},
    ty::{
        atom::{Atom, Command, Height, Input},
        token::Token,
    },
    utils::mmr::Mmr,
};

mod storage;

pub use storage::Mode as StorageMode;

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
pub enum Error {
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

    #[error("Storage is empty")]
    EmptyStorage,

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error("Invalid atoms")]
    InvalidAtoms,

    #[error("Invalid tokens")]
    InvalidTokens,
}

#[derive(Default)]
#[derive(Debug)]
pub struct UpdateResult {
    pub accepted: HashSet<Multihash>,
    pub rejected: HashMap<Multihash, RejectReason>,
    pub missing: HashSet<Multihash>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    pub atom: Atom,
    pub children: HashSet<Multihash>,

    // Block only
    pub is_block: bool,
    pub mmr: Mmr<Token>,

    pub confirmed: HashMap<PeerId, HashSet<Multihash>>,
    pub unconfirmed: HashMap<Multihash, Option<Token>>,

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

pub struct Graph<V> {
    entries: HashMap<Multihash, Entry>,
    dismissed: HashSet<Multihash>,

    main_head: Multihash,
    checkpoint: Multihash,
    checkpoint_height: Height,

    storage: Storage,

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

impl<V: Validator> Graph<V> {
    pub fn new<I>(
        atom: Atom,
        difficulty: u64,
        mmr: Mmr<Token>,
        atoms: I,
        config: Config,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Atom>,
    {
        let mut graph = {
            let entry = {
                let indices = Self::resolve_related(&mmr, &config.storage_mode)
                    .ok_or(Error::InvalidTokens)?;
                Entry {
                    atom: atom.clone(),
                    is_block: true,
                    mmr: mmr.clone(),
                    confirmed: indices,
                    is_missing: false,
                    ..Default::default()
                }
            };

            let vec = bincode::serde::encode_to_vec(&atom, bincode::config::standard()).unwrap();
            let storage = Storage {
                difficulty,
                mmr,
                atoms: BTreeMap::from_iter([(atom.height, HashMap::from_iter([(atom.hash, vec)]))]),
                others: VecDeque::new(),
                mode: config.storage_mode,
            };

            Self {
                entries: HashMap::from_iter([(atom.hash, entry)]),
                dismissed: HashSet::new(),
                main_head: atom.hash,
                checkpoint: atom.hash,
                checkpoint_height: atom.height,
                storage,
                vdf: WesolowskiVDFParams(config.vdf_params).new(),
                difficulty,
                config,
                _marker: std::marker::PhantomData,
            }
        };

        if atoms
            .into_iter()
            .any(|a| graph.upsert(a).is_none_or(|r| !r.rejected.is_empty()))
        {
            return Err(Error::InvalidAtoms);
        }

        Ok(graph)
    }

    fn resolve_related(
        mmr: &Mmr<Token>,
        mode: &StorageMode,
    ) -> Option<HashMap<PeerId, HashSet<Multihash>>> {
        let target = match mode {
            StorageMode::General(p) => Some(*p),
            StorageMode::Archive(..) => None,
        };

        mmr.leaves()
            .try_fold(HashMap::<_, HashSet<_>>::new(), |mut acc, (_, token)| {
                if let Some(p) = target {
                    if V::is_related(&token.script_pk, &p) {
                        acc.entry(p).or_default().insert(token.id);
                    }
                } else {
                    V::related_peers(&token.script_pk)
                        .into_iter()
                        .for_each(|p| {
                            acc.entry(p).or_default().insert(token.id);
                        });
                }

                Some(acc)
            })
    }

    pub fn empty(config: Config) -> Self {
        Self::with_genesis(Atom::default(), Mmr::default(), config)
    }

    pub fn with_genesis(atom: Atom, mmr: Mmr<Token>, config: Config) -> Self {
        Self::new(atom, config.init_vdf_difficulty, mmr, Vec::new(), config).unwrap()
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

        for hash in parents {
            if self.dismissed.contains(&hash) {
                return Err(RejectReason::DismissedParent);
            }

            let parent = self.entries.entry(hash).or_default();

            if parent.is_missing {
                missing.insert(hash);
            }

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

        if std::panic::catch_unwind(|| {
            self.vdf
                .verify(&atom.vdf_input(), self.difficulty, &atom.nonce)
        })
        .is_err()
        {
            return Err(RejectReason::InvalidNonce);
        }

        let is_block = self.validate_execution(&hash)?;

        self.storage.push_atom(&self.entries[&hash].atom);

        if !is_block {
            return Ok(());
        }

        self.update_weight(hash);
        self.recompute_main_chain_and_checkpoint();

        Ok(())
    }

    fn validate_execution(&mut self, target_hash: &Multihash) -> Result<bool, RejectReason> {
        let mut created: Vec<Token> = Vec::new();
        let mut consumed = HashSet::new();

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
                    Input::Confirmed(token, proof, sig) => {
                        if !consumed.insert(token.id) {
                            return Err(RejectReason::DoubleSpend);
                        }

                        if !mmr.delete(token.id, &proof) {
                            return Err(RejectReason::InvalidProof);
                        }

                        if hash == target_hash && !V::validate_script_sig(&sig, &token.script_pk) {
                            return Err(RejectReason::InvalidScriptSig);
                        }

                        excluded |= parent
                            .unconfirmed
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
                            .unconfirmed
                            .get(&token.id)
                            .is_some_and(|t| t.is_none());

                        acc.push(token);

                        Ok(acc)
                    }
                })?;

            if hash == target_hash {
                if cmd
                    .created
                    .iter()
                    .enumerate()
                    .any(|(i, t)| !t.validate_id(cmd.inputs[0].id(), i as u32))
                {
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
                let iter = consumed.into_iter().map(|id| (id, None));
                parent.unconfirmed.extend(iter);
            }
            return Ok(false);
        }

        let mut confirmed = parent.confirmed.clone();

        consumed.into_iter().for_each(|id| {
            confirmed.values_mut().for_each(|v| {
                v.remove(&id);
            });
        });

        created.into_iter().for_each(|token| {
            match &self.config.storage_mode {
                StorageMode::General(p) => {
                    if V::is_related(&token.script_pk, p) {
                        confirmed.entry(*p).or_default().insert(token.id);
                    }
                }
                StorageMode::Archive(..) => {
                    V::related_peers(&token.script_pk)
                        .into_iter()
                        .for_each(|p| {
                            confirmed.entry(p).or_default().insert(token.id);
                        });
                }
            }
            mmr.append(token.id, token);
        });

        mmr.commit();
        mmr.prune(confirmed.values().flat_map(|m| m.iter()).cloned());

        let cur = self.entries.get_mut(target_hash).unwrap();
        cur.mmr = mmr;
        cur.confirmed = confirmed;
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

        let (times, hashes) = self.collect_times_and_hashes(next_hash, self.checkpoint);
        let difficulty = self.adjust_difficulty(times);

        self.storage
            .finalize(&hashes, difficulty, self.entries[&next_hash].mmr.clone());
        self.entries.retain(|_, e| e.atom.checkpoint == next_hash);
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

    fn collect_times_and_hashes(
        &mut self,
        start: Multihash,
        end: Multihash,
    ) -> (Vec<u64>, Vec<Multihash>) {
        let mut times = Vec::new();
        let mut hashes = vec![start];

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

            hashes.push(cur);
        }

        (times, hashes)
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
        let mmr = &entry.mmr;

        match self.config.storage_mode {
            StorageMode::General(p) => {
                debug_assert_eq!(&p, peer);
                mmr.leaves()
                    .filter(|(h, _)| !entry.unconfirmed.contains_key(h))
                    .map(|(_, t)| t.clone())
                    .chain(
                        entry
                            .unconfirmed
                            .iter()
                            .filter_map(|(h, t)| t.as_ref().map(|t| (h, t)))
                            .filter(|(_, t)| V::is_related(&t.script_pk, peer))
                            .map(|(_, t)| t.clone()),
                    )
                    .collect()
            }
            StorageMode::Archive(..) => entry
                .confirmed
                .get(peer)
                .into_iter()
                .flat_map(|hs| {
                    hs.iter()
                        .filter(|h| !entry.unconfirmed.contains_key(h))
                        .map(|h| mmr.get(h).cloned().unwrap())
                })
                .chain(
                    entry
                        .unconfirmed
                        .iter()
                        .filter_map(|(h, t)| t.as_ref().map(|t| (h, t)))
                        .filter(|(_, t)| V::is_related(&t.script_pk, peer))
                        .map(|(_, t)| t.clone()),
                )
                .collect(),
        }
    }

    pub fn export(&self, peer_id: Option<PeerId>) -> Option<Vec<u8>> {
        self.storage.export(peer_id.map(|p| {
            self.entries[&self.checkpoint]
                .confirmed
                .get(&p)
                .map(|m| m.iter().cloned())
                .unwrap_or_default()
        }))
    }

    pub fn import(data: &[u8], config: Config) -> Result<Self, Error> {
        Storage::import(data, config)
    }

    pub fn create_command(
        &self,
        code: u8,
        inputs: impl IntoIterator<Item = (Multihash, impl Into<Vec<u8>>)>,
        created: impl IntoIterator<Item = (impl Into<Vec<u8>>, impl Into<Vec<u8>>)>,
    ) -> Result<Command, Error> {
        let head = &self.entries[&self.main_head];

        let inputs = inputs
            .into_iter()
            .try_fold(Vec::new(), |mut acc, (id, sig)| {
                match head.mmr.get(&id) {
                    Some(token) => {
                        let proof = head.mmr.prove(id).ok_or(Error::FailedToProveInput)?;
                        acc.push(Input::Confirmed(token.clone(), proof, sig.into()));
                    }
                    None => {
                        head.unconfirmed
                            .get(&id)
                            .ok_or(Error::UnknownTokenId)?
                            .as_ref()
                            .ok_or(Error::InputConsumed)?;
                        acc.push(Input::Unconfirmed(id, sig.into()));
                    }
                }
                Ok::<_, Error>(acc)
            })?;

        let first_input_id = inputs.first().ok_or(Error::NoInput)?.id();
        let created = created
            .into_iter()
            .enumerate()
            .map(|(idx, (pk, sig))| Token::new(first_input_id, idx as u32, pk, sig))
            .collect();

        Ok(Command {
            code,
            inputs,
            created,
        })
    }

    pub fn create_atom(&self, cmd: Option<Command>) -> Result<JoinHandle<Atom>, Error> {
        let mut atom = Atom {
            hash: Multihash::default(),
            parent: self.main_head,
            checkpoint: self.checkpoint,
            height: self.entries[&self.main_head].atom.height + 1,
            nonce: Vec::new(),
            random: rand::random(),
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
            atom.hash = Hasher::default().digest(&atom.hash_input());
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
