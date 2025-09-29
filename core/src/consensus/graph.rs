use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use bincode::error::DecodeError;
use derivative::Derivative;
use libp2p::PeerId;
use rocksdb::DB;
use tokio::task::JoinHandle;

use crate::{
    consensus::validator::Validator,
    crypto::Multihash,
    ty::{
        atom::{Atom, AtomBuilder, Command, Height},
        token::Token,
    },
    utils::mmr::{Mmr, MmrProof},
};

pub const HISTORY: &str = "history";
const OWNNER: &str = "owner";

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

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum ImportError {
    #[error("Mismatched atom height")]
    MismatchedHeight,

    #[error("Duplicate atom")]
    DuplicateAtom,

    #[error("Atom rejected: {0:?}")]
    Rejected(RejectReason),

    #[error("Missing parent atoms")]
    MissingParents,

    #[error("Atom should be the main head")]
    NotMainHead,

    #[error("Atom should be the checkpoint")]
    NotCheckpoint,
}

#[derive(Clone, Copy)]
pub struct Status {
    pub main_head: Multihash,
    pub main_height: Height,
    pub checkpoint: Multihash,
    pub checkpoint_height: Height,
    pub difficulty: u64,
}

#[derive(Default)]
#[derive(Debug)]
pub struct UpdateResult {
    pub accepted: HashSet<Multihash>,
    pub rejected: HashMap<Multihash, RejectReason>,
    pub missing: HashSet<Multihash>,
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Entry {
    pub atom: Atom,
    pub children: HashSet<Multihash>,
    pub excluded: bool,

    // Block only
    pub is_block: bool,
    pub mmr: Mmr<Token>,
    pub confirmed: HashMap<PeerId, HashMap<Multihash, u64>>,
    pub unconfirmed_consumed: HashSet<Multihash>,
    pub cmd_hashes: HashSet<Multihash>,
    pub accumulated_diff: HashMap<Multihash, (Vec<u8>, Option<u64>)>,

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

    #[derivative(Default(value = "1024"))]
    pub vdf_params: u16,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Graph<V> {
    entries: HashMap<Multihash, Entry>,
    dismissed: HashSet<Multihash>,

    main_head: Multihash,
    checkpoint: Multihash,
    checkpoint_height: Height,

    difficulty: u64,

    dir: PathBuf,
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
    pub fn new(dir_str: &str, config: Config) -> Result<Self, Error> {
        use bincode::{config, serde::decode_from_slice};

        let dir = Path::new(&dir_str).join(HISTORY);

        let mut file_names = fs::read_dir(&dir)
            .expect("Failed to read history directory")
            .map(|e| {
                e.unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();
        file_names.sort_unstable();

        assert!(
            file_names.is_empty() || file_names.len() % 2 == 1,
            "Should have odd number of history files"
        );

        let distance = config.checkpoint_distance;
        let mut graph = Self::genesis(dir_str, config);
        let mut end = "1";
        let mut epoch = 0;

        for file_name in file_names {
            if !file_name.ends_with(end) {
                let s = if end == "0" { "checkpoint" } else { "history" };
                panic!("File is not a valid {} file: {}", s, file_name);
            }

            let path = dir.join(file_name);
            let data = fs::read(&path).expect("Failed to read history file");

            if end == "0" {
                let atom: Atom = decode_from_slice(&data, config::standard()).unwrap().0;

                assert_eq!(
                    atom.height,
                    epoch * distance,
                    "Mismatched checkpoint height"
                );

                let hash = atom.hash();
                let res = graph.upsert(atom).expect("Duplicate Atom");
                assert!(res.accepted.contains(&hash), "Checkpoint Atom not accepted");
                assert!(res.rejected.is_empty(), "Invalid checkpoint Atom");
                assert!(res.missing.is_empty(), "Missing parents in checkpoint Atom");

                epoch += 1;
                end = "1";
            } else {
                for i in 0..(distance - 1) {
                    let atom: Atom = decode_from_slice(&data, config::standard()).unwrap().0;

                    assert_eq!(
                        atom.height,
                        epoch * distance + i + 1,
                        "Mismatched history height"
                    );
                    assert_eq!(atom.parent, graph.main_head, "Mismatched parent hash");

                    let hash = atom.hash();
                    let res = graph.upsert(atom).expect("Duplicate Atom");
                    assert!(res.accepted.contains(&hash), "History Atom not accepted");
                    assert!(res.rejected.is_empty(), "Invalid history Atom");
                    assert!(res.missing.is_empty(), "Missing parents in history Atom");
                    assert_eq!(graph.main_head, hash, "Atom should be the main head");
                }

                epoch += 1;
                end = "0";
            }
        }

        Ok(graph)
    }

    pub fn genesis(dir: &str, config: Config) -> Self {
        let (hasher, code, tokens) = V::genesis();

        let atom = AtomBuilder::new(Multihash::default(), Multihash::default(), 0)
            .with_hasher(hasher)
            .with_nonce(vec![])
            .with_random(0)
            .with_timestamp(0)
            .with_command((!tokens.is_empty()).then(|| Command {
                code,
                inputs: vec![],
                created: tokens,
            }))
            .build_sync(config.vdf_params, config.init_vdf_difficulty);

        let mut confirmed = HashMap::<PeerId, HashMap<Multihash, u64>>::new();
        let mut mmr = Mmr::default();

        if let Some(cmd) = &atom.cmd {
            for token in &cmd.created {
                let idx = mmr.append(token.id, token.clone());
                V::related_peers(&token.script_pk)
                    .into_iter()
                    .for_each(|p| {
                        confirmed.entry(p).or_default().insert(token.id, idx);
                    });
            }
            mmr.commit();
        }

        let hash = atom.hash();
        let height = atom.height;
        let entry = Entry {
            atom,
            is_block: true,
            mmr,
            confirmed,
            is_missing: false,
            ..Default::default()
        };

        Self {
            entries: HashMap::from_iter([(hash, entry)]),
            dismissed: HashSet::new(),
            main_head: hash,
            checkpoint: hash,
            checkpoint_height: height,
            difficulty: config.init_vdf_difficulty,
            dir: dir.into(),
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn import(&mut self, atoms: Vec<Atom>) -> Result<(), ImportError> {
        assert!(!atoms.is_empty(), "No atoms provided");

        let distance = self.config.checkpoint_distance;
        let epoch = self.checkpoint_height / distance;
        let start = epoch * distance + 1;
        let end = atoms.last().unwrap().height;
        let final_end = start + distance * end / distance - 1;

        let mut exp = start;
        for atom in atoms {
            let height = atom.height;
            let hash = atom.hash();

            if height <= final_end {
                if height != exp {
                    return Err(ImportError::MismatchedHeight);
                }

                let res = self.upsert(atom).ok_or(ImportError::DuplicateAtom)?;
                if !res.rejected.is_empty() {
                    return Err(ImportError::Rejected(
                        *res.rejected.values().next().unwrap(),
                    ));
                }
                if !res.missing.is_empty() {
                    return Err(ImportError::MissingParents);
                }
                if self.main_head != hash {
                    return Err(ImportError::NotMainHead);
                }
                if height % distance == 0 && height != distance && self.checkpoint != hash {
                    return Err(ImportError::NotCheckpoint);
                }

                exp += 1;
                continue;
            }

            if height == exp {
                exp += 1;
            } else if height == exp - 1 {
                // Do nothing
            } else {
                return Err(ImportError::MismatchedHeight);
            }

            let res = self.upsert(atom).ok_or(ImportError::DuplicateAtom)?;
            if !res.rejected.is_empty() {
                return Err(ImportError::Rejected(
                    *res.rejected.values().next().unwrap(),
                ));
            }
            if !res.missing.is_empty() {
                return Err(ImportError::MissingParents);
            }
        }

        Ok(())
    }

    pub fn upsert(&mut self, atom: Atom) -> Option<UpdateResult> {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

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

        let mut stk = VecDeque::new();
        stk.push_back(hash);

        while let Some(u) = stk.pop_front() {
            for child in self.entries[&u].children.clone() {
                let entry = self.entries.get_mut(&child).unwrap();
                entry.pending_parents -= 1;

                if entry.pending_parents == 0 {
                    if let Err(r) = self.final_validation(child) {
                        self.remove_subgraph(child, r, &mut result);
                    } else {
                        result.accepted.insert(child);
                        stk.push_back(child);
                    }
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

        entry
            .atom
            .atoms
            .iter()
            .chain(std::iter::once(&entry.atom.parent))
            .for_each(|p| {
                if let Some(parent) = self.entries.get_mut(p) {
                    parent.children.remove(&hash);
                }
            });

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

            entry
                .atom
                .atoms
                .iter()
                .chain(std::iter::once(&entry.atom.parent))
                .for_each(|p| {
                    if let Some(parent) = self.entries.get_mut(p) {
                        parent.children.remove(&u);
                    }
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

        for parent_hash in parents {
            if self.dismissed.contains(&parent_hash) {
                return Err(RejectReason::DismissedParent);
            }

            let parent = self.entries.entry(parent_hash).or_default();

            if parent.is_missing {
                missing.insert(parent_hash);
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

        if !atom.verify_nonce(self.config.vdf_params, self.difficulty) {
            return Err(RejectReason::InvalidNonce);
        }

        if !self.validate_execution(&hash)? {
            return Ok(());
        }

        self.update_weight(hash);
        self.recompute_main_chain_and_checkpoint();

        Ok(())
    }

    fn validate_execution(&mut self, target_hash: &Multihash) -> Result<bool, RejectReason> {
        let mut consumed = HashMap::<Multihash, (Vec<u8>, MmrProof)>::new();
        let mut created = Vec::<Token>::new();
        let mut cmd_hashes = HashSet::new();
        let mut excluded = false;

        let parent_hash = self.entries[target_hash].atom.parent;
        let parent = &self.entries[&parent_hash];
        let target = &self.entries[target_hash];

        for entry in target
            .atom
            .atoms
            .iter()
            .map(|h| &self.entries[h])
            .chain(std::iter::once(target))
            .filter(|e| e.atom.cmd.is_some())
        {
            let atom = &entry.atom;
            let cmd = atom.cmd.as_ref().unwrap();
            if cmd.created.is_empty() {
                return Err(RejectReason::EmptyInput);
            }
            cmd_hashes.insert(atom.hash());

            let mut inputs = Vec::new();
            for (token, proof, sig) in &cmd.inputs {
                if !parent.mmr.verify(token.id, proof) {
                    return Err(RejectReason::MissingProof);
                }

                if consumed
                    .insert(token.id, (token.script_pk.clone(), proof.clone()))
                    .is_some()
                {
                    return Err(RejectReason::DoubleSpend);
                }

                if !V::validate_script_sig(token.id, &token.script_pk, sig) {
                    return Err(RejectReason::InvalidScriptSig);
                }

                inputs.push(token.clone());
                excluded |= entry.excluded;
            }

            if cmd
                .created
                .iter()
                .enumerate()
                .any(|(i, t)| !t.validate_id(&cmd.inputs[0].0.id, i as u32))
            {
                return Err(RejectReason::InvalidTokenId);
            }

            if !V::validate_conversion(cmd.code, &inputs, &cmd.created) {
                return Err(RejectReason::InvalidConversion);
            }

            created.extend(cmd.created.iter().cloned());
        }

        let threshold = self.config.block_threshold as usize;
        let length = target.atom.atoms.len() + 1;

        if length < threshold {
            excluded |= target.atom.cmd.as_ref().is_some_and(|cmd| {
                cmd.inputs
                    .iter()
                    .any(|(t, _, _)| parent.unconfirmed_consumed.contains(&t.id))
            });

            let parent = self.entries.get_mut(&parent_hash).unwrap();

            if excluded {
                parent.children.remove(target_hash);
            } else {
                parent.unconfirmed_consumed.extend(consumed.keys().copied());
            }

            return Ok(false);
        }

        let mut confirmed = parent.confirmed.clone();
        let mut mmr = parent.mmr.clone();
        let mut diff = parent.accumulated_diff.clone();

        consumed.into_iter().for_each(|(id, (sig, proof))| {
            mmr.delete(id, &proof);
            diff.insert(id, (sig.clone(), None));
            V::related_peers(&sig).into_iter().for_each(|p| {
                let mut empty = false;
                if let Some(set) = confirmed.get_mut(&p) {
                    set.remove(&id);
                    empty = set.is_empty();
                }
                if empty {
                    confirmed.remove(&p);
                }
            });
        });

        created.into_iter().for_each(|token| {
            let id = token.id;
            let script_pk = token.script_pk.clone();
            let idx = mmr.append(token.id, token);
            diff.insert(id, (script_pk.clone(), Some(idx)));
            V::related_peers(&script_pk).into_iter().for_each(|p| {
                confirmed.entry(p).or_default().insert(id, idx);
            });
        });

        mmr.commit();

        let cur = self.entries.get_mut(target_hash).unwrap();
        cur.mmr = mmr;
        cur.confirmed = confirmed;
        cur.cmd_hashes = cmd_hashes;
        cur.accumulated_diff = diff;
        cur.is_block = true;
        cur.excluded = false;

        Ok(true)
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
        use bincode::{
            config,
            serde::{encode_into_std_write, encode_to_vec},
        };

        let prev_height = self.entries[&self.checkpoint].atom.height;
        let head_height = self.entries[&self.main_head].atom.height;

        if head_height != prev_height + self.config.checkpoint_distance * 2 {
            return;
        }

        let next_height = prev_height + self.config.checkpoint_distance;
        let next_hash = self.get_block_at_height(self.main_head, next_height);

        let (times, atoms) = self.collect_times_and_atoms(next_hash, self.checkpoint);
        let difficulty = self.adjust_difficulty(times);

        let dir = Path::new(&self.dir).join(HISTORY);
        let epoch = next_height / self.config.checkpoint_distance;

        {
            // Write checkpoint
            let file_name = format!("{}0", epoch);
            let path = dir.join(file_name);
            let mut file = fs::File::create(&path).expect("Failed to create checkpoint file");
            encode_into_std_write(&atoms[0], &mut file, config::standard())
                .expect("Failed to write checkpoint file");
        }

        {
            // Write Others
            let file_name = format!("{}1", epoch);
            let path = dir.join(file_name);
            let mut file = fs::File::create(&path).expect("Failed to create history file");

            for atom in atoms[1..].iter().rev() {
                encode_into_std_write(atom, &mut file, config::standard())
                    .expect("Failed to write history file");
            }
        }

        let dir = Path::new(&self.dir).join(OWNNER);
        let db = DB::open_default(&dir).expect("Failed to open owner DB");

        for (hash, (sig, idx)) in &self.entries[&next_hash].accumulated_diff {
            V::related_peers(sig).into_iter().for_each(|p| {
                let mut key = Vec::new();
                encode_into_std_write(p, &mut key, config::standard()).unwrap();
                encode_into_std_write(hash, &mut key, config::standard()).unwrap();

                if let Some(idx) = idx {
                    let value = encode_to_vec(idx, config::standard()).unwrap();
                    db.put(key, value).expect("Failed to update owner DB");
                } else {
                    db.delete(key).expect("Failed to update owner DB");
                }
            });
        }

        let nodes_to_keep = self.collect_subtree_from_checkpoint(next_hash);
        self.entries.retain(|hash, _| nodes_to_keep.contains(hash));
        self.checkpoint_height = next_height;
        self.checkpoint = next_hash;
        self.difficulty = difficulty;
    }

    fn get_block_at_height(&self, mut cur: Multihash, height: Height) -> Multihash {
        loop {
            let e = &self.entries[&cur];
            if e.atom.height == height {
                break e.atom.hash();
            }
            cur = e.atom.parent;
        }
    }

    fn collect_times_and_atoms(
        &mut self,
        start: Multihash,
        end: Multihash,
    ) -> (Vec<u64>, Vec<Atom>) {
        let mut times = Vec::new();
        let mut atoms = Vec::new();

        let (mut cur, mut next_time) = {
            let entry = &self.entries[&start];
            atoms.push(entry.atom.clone());
            (entry.atom.parent, entry.atom.timestamp)
        };

        while cur != end {
            let entry = &self.entries[&cur];

            let dt = next_time.saturating_sub(entry.atom.timestamp);
            if dt > 0 {
                times.push(dt);
            }

            next_time = entry.atom.timestamp;
            cur = entry.atom.parent;

            atoms.push(entry.atom.clone());
        }

        (times, atoms)
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

    fn collect_subtree_from_checkpoint(&self, checkpoint: Multihash) -> HashSet<Multihash> {
        let mut nodes_to_keep = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(checkpoint);
        nodes_to_keep.insert(checkpoint);

        while let Some(current) = queue.pop_front() {
            if let Some(entry) = self.entries.get(&current) {
                for child in &entry.children {
                    if nodes_to_keep.insert(*child) {
                        queue.push_back(*child);
                    }
                }
            }
        }

        nodes_to_keep
    }

    pub fn get(&self, h: &Multihash) -> Option<&Atom> {
        self.entries
            .get(h)
            .and_then(|e| (!e.is_missing).then_some(&e.atom))
    }

    pub fn tokens_for(&self, peer: &PeerId) -> Vec<Token> {
        let entry = &self.entries[&self.main_head];
        let mmr = &entry.mmr;
        entry
            .confirmed
            .get(peer)
            .into_iter()
            .flat_map(|hs| {
                hs.iter()
                    .filter(|(h, _)| !entry.unconfirmed_consumed.contains(h))
                    .map(|(_, idx)| mmr.get(*idx).unwrap().1.as_ref().unwrap().clone())
            })
            .collect()
    }

    pub fn create_command(
        &self,
        code: u8,
        input_iter: impl IntoIterator<Item = (Multihash, impl Into<Vec<u8>>)>,
        created_iter: impl IntoIterator<Item = (impl Into<Vec<u8>>, impl Into<Vec<u8>>)>,
        peer: &PeerId,
    ) -> Result<Command, Error> {
        let head = &self.entries[&self.main_head];
        let set = head.confirmed.get(peer).ok_or(Error::NoInput)?;

        let mut inputs = Vec::new();
        for (id, sig) in input_iter {
            let idx = *set.get(&id).ok_or(Error::UnknownTokenId)?;
            let token = head.mmr.get(idx).unwrap().1.as_ref().unwrap().clone();
            let proof = head.mmr.prove(idx).ok_or(Error::FailedToProveInput)?;
            inputs.push((token, proof, sig.into()));
        }

        let first_input_id = inputs.first().ok_or(Error::NoInput)?.0.id;
        let created = created_iter
            .into_iter()
            .enumerate()
            .map(|(idx, (pk, sig))| Token::new(&first_input_id, idx as u32, pk, sig))
            .collect();

        Ok(Command {
            code,
            inputs,
            created,
        })
    }

    pub fn create_atom(&self, cmd: Option<Command>) -> JoinHandle<Atom> {
        AtomBuilder::new(
            self.main_head,
            self.checkpoint,
            self.entries[&self.main_head].atom.height + 1,
        )
        .with_command(cmd)
        .with_atoms(self.get_children(self.main_head))
        .build(self.config.vdf_params, self.difficulty)
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
                    if *d > 0 {
                        *d -= 1;
                        if *d == 0 {
                            stk.push_back(*c);
                        }
                    }
                }
            });
        }

        result
    }

    pub fn current_atoms(&self) -> Vec<Atom> {
        self.entries
            .values()
            .filter(|e| !e.is_missing)
            .map(|e| e.atom.clone())
            .collect()
    }

    pub fn status(&self) -> Status {
        Status {
            main_head: self.main_head,
            main_height: self.entries[&self.main_head].atom.height,
            checkpoint: self.checkpoint,
            checkpoint_height: self.checkpoint_height,
            difficulty: self.difficulty,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Hasher;

    use super::*;

    const INIT_DIFFICULTY: u64 = 5;
    const PEER1: [u8; 39] = [
        0, 37, 8, 2, 18, 33, 3, 37, 231, 146, 221, 228, 232, 82, 157, 2, 152, 38, 140, 247, 207, 5,
        201, 79, 98, 185, 119, 244, 169, 196, 94, 184, 85, 238, 234, 254, 136, 6, 81,
    ];
    const PEER2: [u8; 39] = [
        0, 37, 8, 2, 18, 33, 3, 215, 10, 51, 166, 159, 134, 74, 248, 169, 95, 230, 245, 12, 116,
        122, 68, 95, 157, 233, 179, 114, 84, 200, 57, 227, 138, 230, 88, 254, 185, 162, 42,
    ];

    struct TestValidator;

    impl Validator for TestValidator {
        fn genesis() -> (Hasher, u8, Vec<Token>) {
            let tokens = vec![
                Token::new(&Multihash::default(), 0, [1], PEER1),
                Token::new(&Multihash::default(), 1, [1], PEER1),
                Token::new(&Multihash::default(), 2, [1], PEER1),
            ];
            (Hasher::default(), 0, tokens)
        }

        fn validate_script_sig(_: Multihash, pk: &[u8], sig: &[u8]) -> bool {
            pk == sig
        }

        fn validate_conversion(code: u8, _inputs: &[Token], _created: &[Token]) -> bool {
            code == 0
        }

        fn related_peers(script_pk: &[u8]) -> Vec<PeerId> {
            vec![PeerId::from_bytes(script_pk).unwrap()]
        }

        fn is_related(script_pk: &[u8], peer_id: &PeerId) -> bool {
            script_pk == peer_id.to_bytes()
        }
    }

    fn create_config() -> Config {
        Config {
            block_threshold: 3,
            checkpoint_distance: 10,
            target_block_time: 15,
            max_difficulty_adjustment: 5.0,
            init_vdf_difficulty: INIT_DIFFICULTY,
            vdf_params: 1024,
        }
    }

    fn genesis_hash() -> Multihash {
        let (hasher, code, tokens) = TestValidator::genesis();

        let atom = AtomBuilder::new(Multihash::default(), Multihash::default(), 0)
            .with_hasher(hasher)
            .with_nonce(vec![])
            .with_random(0)
            .with_timestamp(0)
            .with_command((!tokens.is_empty()).then(|| Command {
                code,
                inputs: vec![],
                created: tokens,
            }))
            .build_sync(1024, INIT_DIFFICULTY);

        atom.hash()
    }

    #[test]
    fn initialization() {
        let dir = tempfile::tempdir().unwrap();
        let str = dir.path().to_str().unwrap();
        let config = create_config();
        let exp_hash = genesis_hash();

        let graph = Graph::<TestValidator>::genesis(str, config);

        assert_eq!(graph.entries.len(), 1);
        assert!(graph.dismissed.is_empty());
        assert_eq!(graph.main_head, exp_hash);
        assert_eq!(graph.checkpoint, exp_hash);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);
    }

    #[test]
    fn upsert_normal_atom() {
        let dir = tempfile::tempdir().unwrap();
        let str = dir.path().to_str().unwrap();
        let config = create_config();
        let mut graph = Graph::<TestValidator>::genesis(str, config);

        let atom1 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(1)
            .with_timestamp(1)
            .build_sync(graph.config.vdf_params, graph.difficulty);
        let atom2 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(2)
            .with_timestamp(2)
            .with_atoms(vec![atom1.hash()])
            .build_sync(graph.config.vdf_params, graph.difficulty);
        let atom3 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(3)
            .with_timestamp(3)
            .with_atoms(vec![atom1.hash(), atom2.hash()])
            .build_sync(graph.config.vdf_params, graph.difficulty);

        let res = graph.upsert(atom1.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom1.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 2);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let res = graph.upsert(atom2.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom2.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 3);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        // Atom 3 contains 3 atoms, so it becomes a block
        let res = graph.upsert(atom3.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom3.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 4);
        assert_eq!(graph.main_head, atom3.hash());
        assert_eq!(graph.checkpoint, genesis_hash());
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);
    }

    #[test]
    fn upsert_atom_with_valid_command() {
        let dir = tempfile::tempdir().unwrap();
        let str = dir.path().to_str().unwrap();
        let config = create_config();
        let mut graph = Graph::<TestValidator>::genesis(str, config);

        let atom1 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(1)
            .with_timestamp(1)
            .build_sync(graph.config.vdf_params, graph.difficulty);
        let atom2 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(2)
            .with_timestamp(2)
            .with_atoms(vec![atom1.hash()])
            .build_sync(graph.config.vdf_params, graph.difficulty);
        let cmd = graph
            .create_command(
                0,
                vec![(
                    Token::new(&Multihash::default(), 0, vec![1], PEER1).id,
                    PEER1,
                )],
                vec![(vec![1], PEER2)],
                &PeerId::from_bytes(&PEER1).unwrap(),
            )
            .unwrap();
        let atom3 = AtomBuilder::new(graph.main_head, graph.checkpoint, 1)
            .with_random(3)
            .with_timestamp(3)
            .with_command(Some(cmd))
            .with_atoms(vec![atom1.hash(), atom2.hash()])
            .build_sync(graph.config.vdf_params, graph.difficulty);

        let res = graph.upsert(atom1.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom1.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 2);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let res = graph.upsert(atom2.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom2.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 3);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let res = graph.upsert(atom3.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom3.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 4);
        assert_eq!(graph.main_head, atom3.hash());
        assert_eq!(graph.checkpoint, genesis_hash());
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);
        assert_eq!(
            graph.tokens_for(&PeerId::from_bytes(&PEER2).unwrap()).len(),
            1
        );
    }

    #[tokio::test]
    async fn create_atom() {
        let dir = tempfile::tempdir().unwrap();
        let str = dir.path().to_str().unwrap();
        let config = create_config();
        let mut graph = Graph::<TestValidator>::genesis(str, config);

        let atom1 = graph.create_atom(None).await.unwrap();
        let res = graph.upsert(atom1.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom1.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 2);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let atom2 = graph.create_atom(None).await.unwrap();
        let res = graph.upsert(atom2.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom2.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 3);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let cmd = graph
            .create_command(
                0,
                vec![(
                    Token::new(&Multihash::default(), 0, vec![1], PEER1).id,
                    PEER1,
                )],
                vec![(vec![1], PEER2)],
                &PeerId::from_bytes(&PEER1).unwrap(),
            )
            .unwrap();
        let atom3 = graph.create_atom(Some(cmd)).await.unwrap();
        let res = graph.upsert(atom3.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom3.hash()));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 4);
        assert_eq!(graph.main_head, atom3.hash());
        assert_eq!(graph.checkpoint, genesis_hash());
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);
        assert_eq!(
            graph.tokens_for(&PeerId::from_bytes(&PEER2).unwrap()).len(),
            1
        );
    }
}
