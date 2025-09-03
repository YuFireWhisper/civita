use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::SystemTime,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use libp2p::PeerId;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::validator::Validator,
    crypto::{hasher::Hasher, Multihash},
    ty::{
        atom::{self, Atom, Command, Height},
        token::Token,
    },
    utils::Trie,
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
    InvalidBodyHash,
    InvalidTokenId,
    InvalidHeight,
    InvalidScriptSig,
    InvalidConversion,
    InvalidNonce,
    MissingInput,
}

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum CreationError {
    #[error("One or more input tokens are already consumed")]
    InputConsumed,

    #[error("Failed to generate trie guide for input tokens")]
    FailedToGenerateGuide,
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
    General { peer_id: PeerId },
    Archive { retain_checkpoints: u32 },
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    pub atom: Atom,
    pub excluded: bool,
    pub children: HashSet<Multihash>,

    // Block only
    pub is_block: bool,
    pub trie: Trie,
    pub weight: u64,
    pub related_token: HashMap<PeerId, HashMap<Multihash, Token>>,
    pub unconfirmed_tokens: HashMap<Multihash, Option<Token>>,

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

    #[derivative(Default(value = "60_000"))]
    pub target_block_time_ms: u64,

    #[derivative(Default(value = "50000"))]
    pub init_vdf_difficulty: u64,

    #[derivative(Default(value = "0.1"))]
    pub max_difficulty_adjustment: f32,

    #[derivative(Default(value = "StorageMode::Archive { retain_checkpoints: 1 }"))]
    pub storage_mode: StorageMode,

    #[derivative(Default(value = "1024"))]
    pub vdf_params: u16,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub atom: Atom,
    pub difficulty: u64,
    pub trie_root: Multihash,
    pub trie_guide: HashMap<Multihash, Vec<u8>>,
    pub related_keys: HashSet<Multihash>,
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

    pub fn genesis() -> Self {
        Self {
            is_block: true,
            is_missing: false,
            ..Default::default()
        }
    }

    pub fn validate_script_sig<V: Validator>(&self, id: &Multihash, pk: &[u8]) -> bool {
        self.atom
            .witness
            .script_sigs
            .get(id)
            .is_none_or(|sig| V::validate_script_sig(pk, sig))
    }

    pub fn validate_conversion<'a, V: Validator>(
        &'a self,
        inputs: impl Iterator<Item = &'a Token>,
    ) -> bool {
        let cmd = self.atom.body.cmd.as_ref().unwrap();
        V::validate_conversion(cmd.code, inputs, cmd.consumed.iter(), &cmd.created)
    }
}

impl<V: Validator> Graph<V> {
    pub fn empty(config: Config) -> Self {
        let entry = Entry::genesis();
        let hash = entry.atom.hash;

        Self {
            entries: HashMap::from_iter([(hash, entry)]),
            dismissed: HashSet::new(),
            main_head: hash,
            checkpoint: hash,
            checkpoint_height: 0,
            history: VecDeque::new(),
            vdf: WesolowskiVDFParams(config.vdf_params).new(),
            difficulty: config.init_vdf_difficulty,
            config,
            _marker: std::marker::PhantomData,
        }
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

        if !Hasher::validate(&atom.header.body_hash, &atom.body.to_vec()) {
            return Err(RejectReason::InvalidBodyHash);
        }

        if atom.header.height < self.checkpoint_height {
            return Err(RejectReason::HeightBelowCheckpoint);
        }

        if &atom.header.parent == hash {
            return Err(RejectReason::SelfReference);
        }

        if atom.body.atoms.contains(hash) {
            return Err(RejectReason::SelfReference);
        }

        if atom.body.atoms.contains(&atom.header.parent) {
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
            let mut atoms = atom.body.atoms.clone();
            atoms.push(atom.header.parent);
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

        if atom.header.checkpoint != self.checkpoint {
            return Err(RejectReason::CheckpointMismatch);
        }

        if atom.header.height != self.entries[&atom.header.parent].atom.header.height + 1 {
            return Err(RejectReason::InvalidHeight);
        }

        if atom.body.atoms.iter().any(|h| self.entries[h].is_block) {
            return Err(RejectReason::BlockInAtoms);
        }

        if self
            .vdf
            .verify(&hash.to_vec(), self.difficulty, &atom.header.nonce)
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

    fn validate_execution(&mut self, cur_hash: &Multihash) -> Result<bool, RejectReason> {
        let mut state = HashMap::new();
        let mut excluded = false;
        let mut weight = 0u64;

        let cur = &self.entries[cur_hash];
        let parent_hash = cur.atom.header.parent;
        let cur_len = cur.atom.body.atoms.len();
        let atoms = &cur.atom.body.atoms;

        for cmd in atoms
            .iter()
            .inspect(|h| excluded |= self.entries[*h].excluded)
            .filter_map(|h| self.entries[h].atom.body.cmd.as_ref())
        {
            weight += 1;

            let inputs = cmd.inputs.iter().try_fold(HashMap::new(), |mut acc, id| {
                let token = state
                    .remove(id)
                    .or_else(|| {
                        let trie = &self.entries[&parent_hash].trie;
                        trie.get(&id.to_vec())
                            .map(|v| Token::from_slice(&v).unwrap())
                            .into()
                    })
                    .flatten()
                    .ok_or(RejectReason::MissingInput)?;
                acc.insert(*id, token);
                Ok(acc)
            })?;

            state.extend(inputs.into_iter().map(|(k, v)| {
                if cmd.consumed.contains(&k) {
                    (k, None)
                } else {
                    (k, Some(v))
                }
            }));
            state.extend(cmd.created.iter().cloned().map(|t| (t.id, Some(t))));
        }

        if cur.atom.body.cmd.is_some() {
            let [Some(cur), Some(parent)] = self.entries.get_disjoint_mut([cur_hash, &parent_hash])
            else {
                unreachable!();
            };

            let cmd = cur.atom.body.cmd.as_ref().unwrap();

            weight += 1;

            let inputs = cmd.inputs.iter().try_fold(HashMap::new(), |mut acc, id| {
                let token = state
                    .remove(id)
                    .or_else(|| {
                        let key = id.to_vec();
                        parent
                            .trie
                            .resolve(std::iter::once(&key), &cur.atom.witness.trie_proofs)
                            .then_some(Some(
                                Token::from_slice(&parent.trie.get(&key).unwrap()).unwrap(),
                            ))
                    })
                    .flatten()
                    .ok_or(RejectReason::MissingInput)?;

                if !cur.validate_script_sig::<V>(id, &token.script_pk) {
                    return Err(RejectReason::InvalidScriptSig);
                }

                excluded |= parent
                    .unconfirmed_tokens
                    .get(id)
                    .is_some_and(|t| t.is_none());

                acc.insert(*id, token);
                Ok(acc)
            })?;

            if !cur.validate_conversion::<V>(inputs.values()) {
                return Err(RejectReason::InvalidConversion);
            }

            for (idx, t) in cmd.created.iter().cloned().enumerate() {
                let data = (*cur_hash, idx as u32).to_vec();
                if !Hasher::validate(&t.id, &data) {
                    return Err(RejectReason::InvalidTokenId);
                }
                state.insert(t.id, Some(t));
            }

            state.extend(inputs.into_iter().map(|(k, v)| {
                if cmd.consumed.contains(&k) {
                    (k, None)
                } else {
                    (k, Some(v))
                }
            }));
        }

        if cur_len < self.config.block_threshold as usize {
            let [Some(cur), Some(parent)] = self.entries.get_disjoint_mut([cur_hash, &parent_hash])
            else {
                unreachable!();
            };

            cur.excluded = excluded;
            if excluded {
                parent.children.remove(&cur.atom.hash);
            }

            return Ok(false);
        }

        let mut related = self.entries[&parent_hash].related_token.clone();
        let mut trie = self.entries[&parent_hash].trie.clone();

        state.into_iter().for_each(|(k, t)| {
            let k_vec = k.to_vec();

            let Some(t) = t else {
                trie.remove(&k_vec);
                related.values_mut().for_each(|m| {
                    m.remove(&k);
                });
                return;
            };

            trie.insert(&k_vec, t.to_vec());

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

        let cur = self.entries.get_mut(cur_hash).unwrap();
        cur.trie = trie;
        cur.related_token = related;
        cur.weight = weight;
        cur.is_block = true;

        Ok(true)
    }

    fn update_weight(&mut self, start: Multihash) {
        let (weight, mut cur) = {
            let e = self.entries.get(&start).unwrap();
            (e.weight, e.atom.header.parent)
        };

        while cur != self.checkpoint {
            let entry = self.entries.get_mut(&cur).unwrap();
            entry.weight += weight;
            cur = entry.atom.header.parent;
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
            .map(|c| (self.entries.get(&c).unwrap().weight, c))
            .max()
            .map(|(.., c)| c)
        {
            cur = next;
        }

        cur
    }

    fn maybe_advance_checkpoint(&mut self) {
        let prev_height = self.entries[&self.checkpoint].atom.header.height;
        let head_height = self.entries[&self.main_head].atom.header.height;

        if head_height != prev_height + self.config.checkpoint_distance * 2 {
            return;
        }

        let next_height = prev_height + self.config.checkpoint_distance;
        let next_hash = self.get_block_at_height(self.main_head, next_height);

        let times = self.collect_times(next_hash, self.checkpoint);
        let difficulty = self.adjust_difficulty(times);

        self.entries
            .retain(|_, e| e.atom.header.checkpoint == next_hash);

        let snapshot = {
            let entry = &self.entries[&next_hash];
            let related_keys = entry
                .related_token
                .values()
                .flat_map(|m| m.keys())
                .cloned()
                .collect::<HashSet<_>>();
            let trie_guide = entry
                .trie
                .generate_guide(related_keys.iter().map(|k| k.to_vec()))
                .expect("Guide must be generated");
            Snapshot {
                atom: entry.atom.clone(),
                difficulty,
                trie_root: entry.trie.root_hash(),
                trie_guide,
                related_keys,
            }
        };

        {
            let len = match self.config.storage_mode {
                StorageMode::General { .. } => 1,
                StorageMode::Archive { retain_checkpoints } => retain_checkpoints,
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
            if e.atom.header.height == height {
                break e.atom.hash;
            }
            cur = e.atom.header.parent;
        }
    }

    fn collect_times(&mut self, start: Multihash, end: Multihash) -> Vec<u64> {
        let mut times = Vec::new();

        let (mut cur, mut next_time) = {
            let entry = &self.entries[&start];
            (entry.atom.header.parent, entry.atom.header.timestamp)
        };

        loop {
            let entry = &self.entries[&cur];

            let dt = next_time.saturating_sub(entry.atom.header.timestamp);
            if dt > 0 {
                times.push(dt);
            }

            next_time = entry.atom.header.timestamp;
            cur = entry.atom.header.parent;

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

        let target = self.config.target_block_time_ms as f32;
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

    pub fn tokens_for(&self, peer: &PeerId) -> HashMap<Multihash, Token> {
        let entry = &self.entries[&self.main_head];

        let mut related = entry.related_token.get(peer).cloned().unwrap_or_default();

        entry.unconfirmed_tokens.iter().for_each(|(k, v)| match v {
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
        let entry = &self.entries[&self.main_head];

        let mut by_peer = entry.related_token.clone();

        entry.unconfirmed_tokens.iter().for_each(|(k, v)| match v {
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

    pub fn export(&self, peer_id: Option<PeerId>) -> Option<Vec<u8>> {
        if let StorageMode::General { peer_id: p } = self.config.storage_mode {
            if peer_id.is_none_or(|id| id != p) {
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

        let hash = info.atom.hash;

        let checkpoint = Entry {
            atom: info.atom,
            is_block: true,
            trie,
            related_token,
            is_missing: false,
            ..Default::default()
        };

        let mut graph = Self {
            checkpoint_height: checkpoint.atom.header.height,
            entries: HashMap::from_iter([(hash, checkpoint)]),
            dismissed: HashSet::new(),
            main_head: hash,
            checkpoint: hash,
            history: VecDeque::new(),
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

    pub fn create_atom(
        &self,
        pair: Option<(Command, HashMap<Multihash, Vec<u8>>)>,
    ) -> Result<JoinHandle<Atom>, CreationError> {
        let mut trie_proofs = HashMap::new();
        let mut cmd = None;
        let mut sigs = HashMap::new();

        let head = &self.entries[&self.main_head];

        if let Some(pair) = pair {
            for id in &pair.0.inputs {
                if head.unconfirmed_tokens.get(id).is_some_and(|t| t.is_none()) {
                    return Err(CreationError::InputConsumed);
                }
            }

            trie_proofs = head
                .trie
                .generate_guide(pair.0.inputs.iter().map(|id| id.to_vec()))
                .ok_or(CreationError::FailedToGenerateGuide)?;

            cmd = Some(pair.0);
            sigs = pair.1;
        }

        let body = atom::Body {
            cmd,
            atoms: self.get_children(self.main_head),
        };

        let witness = atom::Witness {
            trie_proofs,
            script_sigs: sigs,
        };

        let mut header = atom::Header {
            parent: self.main_head,
            checkpoint: self.checkpoint,
            height: head.atom.header.height + 1,
            nonce: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            body_hash: Hasher::digest(&body.to_vec()),
        };

        let vdf = self.vdf.clone();
        let difficulty = self.difficulty;

        Ok(tokio::spawn(async move {
            header.nonce = vdf
                .solve(&header.to_vec(), difficulty)
                .expect("VDF must be solved");
            Atom {
                hash: Hasher::digest(&header.to_vec()),
                header,
                body,
                witness,
            }
        }))
    }

    fn get_children(&self, h: Multihash) -> Vec<Multihash> {
        let entry = &self.entries[&h];

        let mut indeg: HashMap<_, usize> = HashMap::from_iter(
            entry
                .children
                .iter()
                .filter(|c| self.contains(c))
                .map(|c| (*c, self.entries[c].atom.body.atoms.len())),
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
