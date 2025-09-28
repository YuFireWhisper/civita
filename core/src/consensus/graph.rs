use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::Path,
    time::SystemTime,
};

use bincode::error::DecodeError;
use derivative::Derivative;
use libp2p::PeerId;
use multihash_derive::MultihashDigest;
use rocksdb::DB;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::validator::Validator,
    crypto::{hasher::Hasher, Multihash},
    ty::{
        atom::{Atom, Command, Height},
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

    #[derivative(Default(value = "\"graph\""))]
    pub storage_dir: &'static str,
}

pub struct Graph<V> {
    entries: HashMap<Multihash, Entry>,
    dismissed: HashSet<Multihash>,

    main_head: Multihash,
    checkpoint: Multihash,
    checkpoint_height: Height,

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
    pub fn new(atoms: Vec<Atom>, config: Config) -> Result<Self, Error> {
        use bincode::{config, serde::decode_from_slice};

        let dir = Path::new(config.storage_dir).join(HISTORY);
        fs::create_dir_all(&dir).unwrap();

        let mut graph = Self::genesis(config);

        let entries = fs::read_dir(&dir).expect("Failed to read history directory");

        let mut file_names = Vec::new();
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            let file_name = path.file_name().unwrap().to_str().unwrap();
            let num = file_name.parse::<u32>().expect("Invalid history file name");
            file_names.push(num);
        }
        file_names.sort_unstable();

        let mut epoch = 0;
        let mut local_atoms = Vec::new();
        for num in file_names {
            epoch += 1;
            assert_eq!(num, epoch);

            let path = dir.join(num.to_string());
            let data = fs::read(&path).expect("Failed to read history file");
            let atoms_in_file: Vec<Atom> = decode_from_slice(&data, config::standard()).unwrap().0;

            let mut cur = epoch * (graph.config.checkpoint_distance - 1);
            for atom in atoms_in_file {
                assert_eq!(atom.height, cur);
                local_atoms.push(atom);
                cur += 1;
            }
            assert_eq!(cur, epoch * graph.config.checkpoint_distance);
        }

        let mut exp = graph.config.checkpoint_distance * epoch + 1;
        if !atoms.iter().all(|a| {
            if a.height == exp {
                exp += 1;
                true
            } else {
                a.height == exp - 1 && a.height % graph.config.checkpoint_distance != 0
            }
        }) {
            panic!("Invalid atoms");
        }

        local_atoms.extend(atoms);

        for atom in local_atoms {
            if graph.upsert(atom).is_none_or(|r| !r.rejected.is_empty()) {
                panic!("Invalid atoms");
            }
        }

        Ok(graph)
    }

    pub fn genesis(config: Config) -> Self {
        let atom = V::genesis();
        assert_eq!(atom.height, 0);

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

        let hash = atom.hash;
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

        if std::panic::catch_unwind(|| {
            self.vdf
                .verify(&atom.vdf_input(), self.difficulty, &atom.nonce)
        })
        .is_err()
        {
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
            cmd_hashes.insert(atom.hash);

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

                if !V::validate_script_sig(sig, &token.script_pk) {
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

        let dir = Path::new(self.config.storage_dir).join(HISTORY);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join((next_height / self.config.checkpoint_distance).to_string());
        let data = encode_to_vec(&atoms, config::standard()).unwrap();
        fs::write(&path, &data).expect("Failed to write history file");

        let dir = Path::new(self.config.storage_dir).join(OWNNER);
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

            atoms.push(entry.atom.clone());
        }

        atoms.reverse();

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
}

#[cfg(test)]
mod tests {
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
        fn genesis() -> Atom {
            let tokens = vec![
                Token::new(&Multihash::default(), 0, [1], PEER1),
                Token::new(&Multihash::default(), 1, [1], PEER2),
                Token::new(&Multihash::default(), 2, [1], PEER2),
            ];

            let cmd = Command {
                code: 0,
                inputs: vec![],
                created: tokens.clone(),
            };

            let mut atom = Atom {
                hash: Multihash::default(),
                parent: Multihash::default(),
                checkpoint: Multihash::default(),
                height: 0,
                nonce: vec![],
                random: 0,
                timestamp: 0,
                cmd: Some(cmd),
                atoms: vec![],
            };

            atom.hash = Hasher::default().digest(&atom.hash_input());
            atom
        }

        fn validate_script_sig(sig: &[u8], script_pk: &[u8]) -> bool {
            sig == script_pk
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

    fn create_config(dir: &'static str) -> Config {
        Config {
            block_threshold: 3,
            checkpoint_distance: 10,
            target_block_time: 15,
            max_difficulty_adjustment: 5.0,
            init_vdf_difficulty: INIT_DIFFICULTY,
            vdf_params: 1024,
            storage_dir: dir,
        }
    }

    fn generate_atom(atom: Atom, difficulty: u64) -> Atom {
        let vdf = WesolowskiVDFParams(1024).new();
        let nonce = vdf.solve(&atom.vdf_input(), difficulty).unwrap();

        let mut atom = Atom {
            nonce,
            hash: Multihash::default(),
            ..atom
        };

        atom.hash = Hasher::default().digest(&atom.hash_input());
        atom
    }

    fn genesis_hash() -> Multihash {
        TestValidator::genesis().hash
    }

    #[test]
    fn initialization() {
        let dir = tempfile::tempdir().unwrap();
        let str = Box::leak(dir.path().to_str().unwrap().to_string().into_boxed_str());
        let config = create_config(str);
        let exp_hash = genesis_hash();

        let graph = Graph::<TestValidator>::genesis(config);

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
        let str = Box::leak(dir.path().to_str().unwrap().to_string().into_boxed_str());
        let config = create_config(str);
        let mut graph = Graph::<TestValidator>::genesis(config);

        let atom1 = {
            let base = Atom {
                parent: graph.main_head,
                checkpoint: graph.checkpoint,
                height: 1,
                timestamp: 1,
                random: 1,
                cmd: None,
                atoms: vec![],
                ..Default::default()
            };
            generate_atom(base, graph.difficulty)
        };

        let atom2 = {
            let base = Atom {
                parent: graph.main_head,
                checkpoint: graph.checkpoint,
                height: 1,
                timestamp: 2,
                random: 2,
                cmd: None,
                atoms: vec![atom1.hash],
                ..Default::default()
            };
            generate_atom(base, graph.difficulty)
        };

        let atom3 = {
            let base = Atom {
                parent: graph.main_head,
                checkpoint: graph.checkpoint,
                height: 1,
                timestamp: 3,
                random: 3,
                cmd: None,
                atoms: vec![atom1.hash, atom2.hash],
                ..Default::default()
            };
            generate_atom(base, graph.difficulty)
        };

        let res = graph.upsert(atom1.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom1.hash));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 2);
        assert_eq!(graph.main_head, genesis_hash());
        assert_eq!(graph.checkpoint, graph.main_head);
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);

        let res = graph.upsert(atom2.clone()).unwrap();
        assert_eq!(res.accepted.len(), 1);
        assert!(res.accepted.contains(&atom2.hash));
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
        assert!(res.accepted.contains(&atom3.hash));
        assert!(res.rejected.is_empty());
        assert!(res.missing.is_empty());
        assert_eq!(graph.entries.len(), 4);
        assert_eq!(graph.main_head, atom3.hash);
        assert_eq!(graph.checkpoint, genesis_hash());
        assert_eq!(graph.checkpoint_height, 0);
        assert_eq!(graph.difficulty, INIT_DIFFICULTY);
    }
}
