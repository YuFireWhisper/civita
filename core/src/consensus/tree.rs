use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    mem::ManuallyDrop,
    path::PathBuf,
};

use bincode::serde::encode_to_vec;
use libp2p::PeerId;
use multihash_derive::MultihashDigest;
use rocksdb::{checkpoint::Checkpoint, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};

use crate::{
    consensus::engine::{ATOM_DIR, MMR_DIR, OWNER_DIR},
    crypto::Multihash,
    traits::{Config, ScriptPubKey},
    ty::{
        atom::{Difficulty, Height, Pruned, Timestamp},
        Atom, Command, Input, Token,
    },
    utils::mmr::{Mmr, MmrProof},
    BINCODE_CONFIG,
};

mod reason;

pub use reason::Reason;

pub type Proofs<T> = HashMap<Multihash, (Token<T>, MmrProof)>;

const TEMP_DIR_PREFIX: &str = "temp";

#[derive(Default)]
pub struct UpdateResult {
    pub accepted: Vec<Multihash>,
    pub dismissed: HashMap<Multihash, Reason>,
    pub missing: Option<Multihash>,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Status {
    pub head: Multihash,
    pub head_height: Height,
    pub finalized: Multihash,
    pub finalized_height: Height,
    pub difficulty: Difficulty,
}

struct Entry<T: Config> {
    pub atom: Atom<T>,
    pub pruned_children: HashMap<Multihash, Pruned<T>>,
    pub block_children: HashSet<Multihash>,

    pub descendants: HashSet<Multihash>,
    pub difficulty: Difficulty,
    pub mmr: Mmr,

    pub mmr_db: Option<DB>,
    pub mmr_db_path: PathBuf,
    pub owner_db: Option<DB>,
    pub owner_db_path: PathBuf,
}

pub struct Tree<T: Config> {
    entries: HashMap<Multihash, Entry<T>>,
    pending: HashMap<Multihash, HashMap<Multihash, Atom<T>>>,
    dismissed: HashMap<Multihash, Reason>,

    head: Multihash,
    finalized: Multihash,
    finalized_height: Height,

    mmr: Mmr,
    atom_height_start: Height,

    mmr_db: DB,
    owner_db: DB,
    atom_db: DB,

    mmr_db_path: PathBuf,
    owner_db_path: PathBuf,
    temp_dir: PathBuf,
    temp_dir_count: u32,

    peer_id: Option<PeerId>,
}

impl<T: Config> Tree<T> {
    pub fn genesis<P>(dir: P, peer_id: Option<PeerId>) -> Self
    where
        P: AsRef<std::path::Path>,
    {
        let dir = dir.as_ref();
        let mmr_db_path = dir.join(MMR_DIR);
        let owner_db_path = dir.join(OWNER_DIR);
        let atom_db_path = dir.join(ATOM_DIR);
        let temp_dir_path = dir.join(TEMP_DIR_PREFIX);

        fs::create_dir_all(&mmr_db_path).unwrap();
        fs::create_dir_all(&owner_db_path).unwrap();
        fs::create_dir_all(&atom_db_path).unwrap();
        let _ = fs::remove_dir_all(&temp_dir_path);
        fs::create_dir_all(&temp_dir_path).unwrap();

        let mut opts = Options::default();
        opts.create_if_missing(true);

        let mmr_db = DB::open(&opts, &mmr_db_path).unwrap();
        let owner_db = DB::open(&opts, &owner_db_path).unwrap();
        let atom_db = DB::open(&opts, &atom_db_path).unwrap();

        let mut mmr = Mmr::default();
        let mut owner_batch = WriteBatch::default();

        if let Some(cmd) = T::genesis_command() {
            debug_assert!(T::validate_command(&cmd));

            let mut keep = Vec::new();

            for (i, token) in cmd.outputs.iter().enumerate() {
                let buf = [[0, 0].as_slice(), &(i as u32).to_be_bytes()].concat();
                let id = T::HASHER.digest(&buf);
                let id_bytes = id.to_bytes();
                let idx = mmr.append(id);
                let value: Vec<u8> = [&idx.to_be_bytes(), token.to_bytes().as_slice()].concat();

                if let Some(peer_id) = peer_id {
                    if token.script_pk.is_related(peer_id) {
                        let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                        owner_batch.put(key, &value);
                        keep.push(idx);
                    }
                } else {
                    for peer_id in token.script_pk.related_peers() {
                        let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                        owner_batch.put(key, &value);
                    }
                }
            }

            mmr.commit();

            if peer_id.is_some() {
                mmr.prune(&keep);
            }
        }

        let genesis = Atom::default()
            .with_difficulty(T::GENESIS_VAF_DIFFICULTY)
            .with_state(mmr.state().clone())
            .with_command(T::genesis_command());

        mmr.write_and_remove_non_peaks(&mmr_db).unwrap();
        owner_db.write(owner_batch).unwrap();

        let temp_mmr_dir = temp_dir_path.join(1.to_string());
        let temp_owner_dir = temp_dir_path.join(2.to_string());

        {
            let cp = Checkpoint::new(&mmr_db).unwrap();
            cp.create_checkpoint(&temp_mmr_dir).unwrap();
            let cp = Checkpoint::new(&owner_db).unwrap();
            cp.create_checkpoint(&temp_owner_dir).unwrap();
        }

        let hash = genesis.hash();
        let height = genesis.height;

        let entry = Entry {
            atom: genesis,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            difficulty: T::GENESIS_VAF_DIFFICULTY,
            mmr: mmr.clone(),
            mmr_db: Some(DB::open_default(&temp_mmr_dir).unwrap()),
            owner_db: Some(DB::open_default(&temp_owner_dir).unwrap()),
            mmr_db_path: temp_mmr_dir,
            owner_db_path: temp_owner_dir,
        };

        Self {
            entries: HashMap::from([(hash, entry)]),
            pending: HashMap::new(),
            dismissed: HashMap::new(),
            head: hash,
            finalized: hash,
            finalized_height: height,
            mmr,
            mmr_db,
            owner_db,
            atom_db,
            mmr_db_path,
            owner_db_path,
            temp_dir: temp_dir_path,
            temp_dir_count: 2,
            atom_height_start: T::GENESIS_HEIGHT,
            peer_id,
        }
    }

    pub fn load_or_genesis<P>(dir: P) -> Option<Self>
    where
        P: AsRef<std::path::Path>,
    {
        let mut tree = Self::genesis(dir.as_ref(), None);
        let atoms = Self::resolve_from_atom_db(&tree.atom_db);
        (atoms.is_empty() || tree.execute_chain(atoms)).then_some(tree)
    }

    fn resolve_from_atom_db(db: &DB) -> Vec<Atom<T>> {
        let iter = db.iterator(IteratorMode::Start);
        let mut atoms = Vec::new();

        let mut prev = None;

        for item in iter {
            let (_key, value) = item.unwrap();
            let atom = Atom::from_bytes(&value).expect("Atom in DB must be valid");
            assert!(prev.is_none_or(|p| p + 1 != atom.height));
            prev = Some(atom.height);
            atoms.push(atom);
        }

        atoms
    }

    pub fn execute_chain<I>(&mut self, chain: I) -> bool
    where
        I: IntoIterator<Item = Atom<T>>,
    {
        for atom in chain {
            let hash = atom.hash();

            if atom.parent != self.head {
                return false;
            }

            if self.basic_validation(&atom).is_some() {
                return false;
            }

            let check_difficulty =
                atom.height.saturating_sub(self.finalized_height) + 1 >= T::MAINTENANCE_WINDOW;

            let mut result = UpdateResult::default();

            self.final_validation(atom, check_difficulty, &mut result);

            if !result.dismissed.is_empty() || result.accepted.is_empty() || self.head != hash {
                return false;
            }

            self.replace_mmr_db(&hash);
            self.replace_owner_db(&hash);

            let entry = &self.entries[&hash];
            self.mmr = entry.mmr.clone();

            let key = self.finalized_height.to_be_bytes();
            let value = entry.atom.to_bytes();
            self.atom_db.put(key, value).unwrap();

            if self.peer_id.is_some()
                && entry.atom.height - self.atom_height_start == T::MAINTENANCE_WINDOW
            {
                let key = self.atom_height_start.to_be_bytes();
                self.atom_db.delete(key).unwrap();
                self.atom_height_start += 1;
            }
        }

        true
    }

    fn next_temp_dir(&mut self) -> PathBuf {
        self.temp_dir_count += 1;
        self.temp_dir.join(self.temp_dir_count.to_string())
    }

    fn replace_mmr_db(&mut self, hash: &Multihash) {
        unsafe {
            ManuallyDrop::drop(&mut ManuallyDrop::new(std::ptr::read(&self.mmr_db)));
        }

        let _ = fs::remove_dir_all(&self.mmr_db_path);
        let cp = Checkpoint::new(self.entries[hash].mmr_db.as_ref().unwrap()).unwrap();
        cp.create_checkpoint(&self.mmr_db_path).unwrap();

        unsafe {
            std::ptr::write(
                &mut self.mmr_db,
                DB::open_default(&self.mmr_db_path).unwrap(),
            );
        }
    }

    fn replace_owner_db(&mut self, hash: &Multihash) {
        unsafe {
            ManuallyDrop::drop(&mut ManuallyDrop::new(std::ptr::read(&self.owner_db)));
        }

        fs::remove_dir_all(&self.owner_db_path).unwrap();
        let cp = Checkpoint::new(self.entries[hash].owner_db.as_ref().unwrap()).unwrap();
        cp.create_checkpoint(&self.owner_db_path).unwrap();

        unsafe {
            std::ptr::write(
                &mut self.owner_db,
                DB::open_default(&self.owner_db_path).unwrap(),
            );
        }
    }

    pub fn with_atom<P>(atom: Atom<T>, dir: P, peer_id: PeerId) -> Self
    where
        P: AsRef<std::path::Path>,
    {
        let dir = dir.as_ref();
        let mmr_db_path = dir.join(MMR_DIR);
        let owner_db_path = dir.join(OWNER_DIR);
        let atom_db_path = dir.join(ATOM_DIR);
        let temp_dir_path = dir.join(TEMP_DIR_PREFIX);

        let _ = fs::remove_dir_all(&temp_dir_path);
        fs::create_dir_all(&mmr_db_path).unwrap();
        let _ = fs::remove_dir_all(&temp_dir_path);
        fs::create_dir_all(&owner_db_path).unwrap();
        let _ = fs::remove_dir_all(&temp_dir_path);
        fs::create_dir_all(&atom_db_path).unwrap();
        let _ = fs::remove_dir_all(&temp_dir_path);
        fs::create_dir_all(&temp_dir_path).unwrap();

        let mmr = Mmr::new(atom.state.clone()).expect("State in Atom must be valid");

        let entry_mmr_db_path = temp_dir_path.join(1.to_string());
        let entry_owner_db_path = temp_dir_path.join(2.to_string());

        let mut opts = Options::default();
        opts.create_if_missing(true);

        let hash = atom.hash();
        let height = atom.height;
        let difficulty = atom.difficulty;

        let entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            difficulty,
            mmr: mmr.clone(),
            mmr_db: Some(DB::open(&opts, &entry_mmr_db_path).unwrap()),
            owner_db: Some(DB::open(&opts, &entry_owner_db_path).unwrap()),
            mmr_db_path: entry_mmr_db_path,
            owner_db_path: entry_owner_db_path,
        };

        let mmr_db = DB::open(&opts, &mmr_db_path).unwrap();
        let owner_db = DB::open(&opts, &owner_db_path).unwrap();
        let atom_db = DB::open(&opts, &atom_db_path).unwrap();

        Self {
            entries: HashMap::from([(hash, entry)]),
            pending: HashMap::new(),
            dismissed: HashMap::new(),
            head: hash,
            finalized: hash,
            finalized_height: height,
            mmr_db_path,
            mmr_db,
            mmr,
            owner_db_path,
            owner_db,
            temp_dir: temp_dir_path,
            temp_dir_count: 2,
            atom_db,
            atom_height_start: height,
            peer_id: Some(peer_id),
        }
    }

    pub fn upsert(&mut self, atom: Atom<T>) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if let Some(reason) = self.dismissed.get(&hash) {
            result.dismissed.insert(hash, reason.inherit());
            return result;
        }

        if self.entries.contains_key(&hash) {
            result.dismissed.insert(hash, Reason::already_existing());
            return result;
        }

        if self
            .pending
            .get(&atom.parent)
            .is_some_and(|m| m.contains_key(&hash))
        {
            result.dismissed.insert(hash, Reason::already_existing());
            return result;
        }

        if let Some(reason) = self.basic_validation(&atom) {
            self.remove_subtree(hash, reason, &mut result);
            return result;
        }

        if let Some(reason) = self.dismissed.get(&atom.parent) {
            self.remove_subtree(hash, reason.inherit_parent(), &mut result);
            return result;
        }

        if !self.entries.contains_key(&atom.parent) {
            result.missing = Some(atom.parent);
            self.pending
                .entry(atom.parent)
                .or_default()
                .insert(hash, atom);
            return result;
        }

        self.final_validation(atom, true, &mut result);

        result
    }

    fn basic_validation(&self, atom: &Atom<T>) -> Option<Reason> {
        if atom.height <= self.finalized_height {
            return Some(Reason::below_finalized(atom.height, self.finalized_height));
        }

        if !atom.validate_atoms_threshold() {
            return Some(Reason::invalid_atom_threshold(
                atom.atoms.len(),
                T::BLOCK_THRESHOLD as usize,
            ));
        }

        if !atom.verify_nonce() {
            return Some(Reason::invalid_nonce());
        }

        None
    }

    fn remove_subtree(&mut self, hash: Multihash, mut reason: Reason, result: &mut UpdateResult) {
        let mut stk = VecDeque::from_iter([hash]);

        while let Some(u) = stk.pop_front() {
            self.dismissed.insert(u, reason);
            result.dismissed.entry(u).or_insert(reason);

            if let Some(children) = self.pending.remove(&u) {
                stk.extend(children.into_keys());
            }

            reason = reason.inherit_parent();
        }
    }

    fn final_validation(
        &mut self,
        atom: Atom<T>,
        check_diffculty: bool,
        result: &mut UpdateResult,
    ) {
        let hash = atom.hash();
        let parent = atom.parent;

        if let Some(reason) = validate(&self.entries[&parent], &atom, check_diffculty) {
            self.remove_subtree(hash, reason, result);
            return;
        }

        if atom.atoms.len() < T::BLOCK_THRESHOLD as usize {
            self.remove_descendants(atom.parent, Reason::non_block_parent(), result);
            let parent = self.entries.get_mut(&parent).unwrap();
            parent.pruned_children.insert(hash, Pruned::from_atom(atom));
            result.accepted.push(hash);
            return;
        }

        let entry = self.transform(atom);
        self.entries.insert(hash, entry);
        result.accepted.push(hash);

        self.update_weight(hash);
        self.recompute_main_chain_and_finalized();

        let Some(children) = self.pending.remove(&hash) else {
            return;
        };

        children.into_values().for_each(|atom| {
            self.final_validation(atom, check_diffculty, result);
        });
    }

    fn remove_descendants(&mut self, hash: Multihash, reason: Reason, result: &mut UpdateResult) {
        let Some(children) = self.pending.remove(&hash) else {
            return;
        };
        let mut stk = VecDeque::from_iter(children.into_keys());

        while let Some(u) = stk.pop_front() {
            self.dismissed.insert(u, reason);
            result.dismissed.entry(u).or_insert(reason);
            if let Some(children) = self.pending.remove(&u) {
                stk.extend(children.into_keys());
            }
        }
    }

    fn transform(&mut self, atom: Atom<T>) -> Entry<T> {
        debug_assert!(atom.atoms.len() >= T::BLOCK_THRESHOLD as usize);

        let hash = atom.hash();

        let entry_mmr_db_path = self.next_temp_dir();
        let entry_owner_db_path = self.next_temp_dir();

        let parent = &self.entries[&atom.parent];

        Checkpoint::new(parent.mmr_db.as_ref().unwrap())
            .unwrap()
            .create_checkpoint(&entry_mmr_db_path)
            .unwrap();
        Checkpoint::new(parent.owner_db.as_ref().unwrap())
            .unwrap()
            .create_checkpoint(&entry_owner_db_path)
            .unwrap();

        let mmr_db = DB::open_default(&entry_mmr_db_path).unwrap();
        let owner_db = DB::open_default(&entry_owner_db_path).unwrap();

        let mut entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            difficulty: parent.difficulty,
            mmr: parent.mmr.clone(),
            mmr_db: Some(mmr_db),
            owner_db: Some(owner_db),
            mmr_db_path: entry_mmr_db_path,
            owner_db_path: entry_owner_db_path,
        };

        if entry
            .atom
            .height
            .saturating_sub(self.atom_height_start.saturating_sub(1))
            >= T::MAINTENANCE_WINDOW
        {
            let timestamps = self
                .collect_timestamps(entry.atom.parent, entry.atom.height, T::MAINTENANCE_WINDOW)
                .expect("Chain continuity is guaranteed here");

            let mut diffs = timestamps
                .windows(2)
                .filter_map(|w| w[1].checked_sub(w[0]))
                .collect::<Vec<_>>();

            diffs.sort_unstable();

            let len = diffs.len();
            let median = if len.is_multiple_of(2) {
                let mid1 = diffs[len / 2 - 1] as f64;
                let mid2 = diffs[len / 2] as f64;
                (mid1 + mid2) / 2.0
            } else {
                diffs[len / 2] as f64
            };

            let target = T::TARGET_BLOCK_TIME_SEC as f64;
            let ratio_raw = target / median;
            let ratio = ratio_raw.clamp(
                1.0 / T::MAX_VDF_DIFFICULTY_ADJUSTMENT,
                T::MAX_VDF_DIFFICULTY_ADJUSTMENT,
            );

            entry.difficulty = ((parent.difficulty as f64 * ratio) as u64).max(1);
        }

        for cmd in entry
            .atom
            .atoms
            .iter()
            .filter_map(|a| a.cmd.as_ref())
            .chain(entry.atom.cmd.as_ref())
        {
            for input in &cmd.inputs {
                let Input::OnChain(token, id, proof, _) = input else {
                    continue;
                };

                entry.mmr.delete(*id, proof);
                let id_bytes = id.to_bytes();

                if let Some(peer_id) = self.peer_id {
                    if token.script_pk.is_related(peer_id) {
                        let key = [peer_id.to_bytes(), id_bytes.clone()].concat();
                        entry.owner_db.as_ref().unwrap().delete(key).unwrap();
                    }
                } else {
                    for peer_id in token.script_pk.related_peers() {
                        let key = [peer_id.to_bytes(), id_bytes.clone()].concat();
                        entry.owner_db.as_ref().unwrap().delete(key).unwrap();
                    }
                }
            }

            let first_input = encode_to_vec(cmd.inputs[0].id(), BINCODE_CONFIG).unwrap();
            let first_input_ref = first_input.as_slice();
            for (i, token) in cmd.outputs.iter().enumerate() {
                let buf = [first_input_ref, &(i as u32).to_be_bytes()].concat();
                let id = T::HASHER.digest(&buf);
                let idx = entry.mmr.append(id);
                let id_bytes = id.to_bytes();
                let value: Vec<u8> = [&idx.to_be_bytes(), token.to_bytes().as_slice()].concat();

                if let Some(peer_id) = self.peer_id {
                    if token.script_pk.is_related(peer_id) {
                        let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                        entry.owner_db.as_ref().unwrap().put(key, &value).unwrap();
                    }
                } else {
                    for peer_id in token.script_pk.related_peers() {
                        let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                        entry.owner_db.as_ref().unwrap().put(key, &value).unwrap();
                    }
                }
            }
        }

        entry.mmr.commit();

        if let Some(peer_id) = self.peer_id {
            let mut keep = Vec::new();
            let bytes = peer_id.to_bytes();
            let iter = entry.owner_db.as_ref().unwrap().prefix_iterator(&bytes);

            for item in iter {
                let (key, value) = item.unwrap();

                if !key.starts_with(&bytes) {
                    break;
                }

                let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
                keep.push(idx);
            }

            entry.mmr.prune(&keep);
        }

        entry
            .mmr
            .write_and_remove_non_peaks(entry.mmr_db.as_ref().unwrap())
            .unwrap();

        self.entries
            .get_mut(&entry.atom.parent)
            .unwrap()
            .block_children
            .insert(hash);

        entry
    }

    fn collect_timestamps(
        &self,
        mut cur_hash: Multihash,
        mut cur_height: Height,
        count: u32,
    ) -> Option<Vec<Timestamp>> {
        let mut timestamps = Vec::with_capacity(count as usize);
        while timestamps.len() < count as usize {
            log::debug!("Collecting timestamp at height {cur_height}");

            let (timestamp, parent) = self
                .entries
                .get(&cur_hash)
                .map(|e| (e.atom.timestamp, e.atom.parent))
                .or_else(|| {
                    self.atom_db
                        .get(cur_height.to_be_bytes())
                        .ok()
                        .flatten()
                        .map(|v| {
                            let atom = Atom::<T>::from_bytes(&v).expect("Atom in DB must be valid");
                            (atom.timestamp, atom.parent)
                        })
                })?;

            timestamps.push(timestamp);
            cur_hash = parent;
            cur_height -= 1;
        }
        Some(timestamps)
    }

    fn update_weight(&mut self, mut cur: Multihash) {
        let hashes = self.entries[&cur].atom.atoms_hashes();

        while cur != self.finalized {
            if let Some(entry) = self.entries.get_mut(&cur) {
                entry.descendants.extend(hashes.iter().copied());
                cur = entry.atom.parent;
            } else {
                log::warn!(
                    "Parent entry not found during weight update. \
                    This should not happen as chain continuity is required for Atom confirmation."
                );
                break;
            }
        }
    }

    fn recompute_main_chain_and_finalized(&mut self) {
        let start = self.finalized;
        let new_head = self.select_heaviest_chain(start);
        if new_head != self.head {
            self.head = new_head;
            self.try_advance_finalized();
        }
    }

    fn select_heaviest_chain(&self, mut cur: Multihash) -> Multihash {
        loop {
            let Some(entry) = self.entries.get(&cur) else {
                log::warn!(
                    "Entry not found when selecting heaviest chain. \
                This should not happen as cur should always originate from \
                either the latest finalized Atom or an existing child node."
                );
                panic!("Invalid state: cur parameter must always be present in entries");
            };

            let Some(next) = entry
                .block_children
                .iter()
                .map(|c| (self.entries[c].descendants.len(), c))
                .max()
                .map(|(_, c)| c)
            else {
                break cur;
            };

            cur = *next;
        }
    }

    fn try_advance_finalized(&mut self) {
        let head_height = self.entries[&self.head].atom.height;
        let target_height = head_height.saturating_sub(T::CONFIRMATION_DEPTH);

        if self.finalized_height >= target_height {
            return;
        }

        let hash = self.get_block_at_height(self.head, target_height);

        self.finalized = hash;
        self.finalized_height = target_height;
        self.prune_non_descendants();

        self.replace_mmr_db(&hash);
        self.replace_owner_db(&hash);

        let entry = &self.entries[&self.finalized];

        self.mmr = entry.mmr.clone();

        let key = self.finalized_height.to_be_bytes();
        let value = entry.atom.to_bytes();
        self.atom_db.put(key, value).unwrap();

        if entry.atom.height - self.atom_height_start == T::MAINTENANCE_WINDOW
            && self.peer_id.is_some()
        {
            let key = self.atom_height_start.to_be_bytes();
            self.atom_db.delete(key).unwrap();
            self.atom_height_start += 1;
        }
    }

    fn get_block_at_height(&self, mut cur: Multihash, height: Height) -> Multihash {
        loop {
            let e = &self.entries[&cur];
            if e.atom.height == height {
                return cur;
            }
            if e.atom.height < height {
                break;
            }
            cur = e.atom.parent;
        }
        cur
    }

    fn prune_non_descendants(&mut self) {
        let mut stk = VecDeque::from_iter([self.finalized]);
        let mut keep = HashSet::from([self.finalized]);

        while let Some(u) = stk.pop_front() {
            let Some(entry) = self.entries.get(&u) else {
                continue;
            };

            entry
                .block_children
                .iter()
                .filter(|c| keep.insert(**c))
                .for_each(|c| stk.push_back(*c));
        }

        self.entries.retain(|h, _| keep.contains(h));
    }

    pub fn create_command(
        &self,
        peer_id: &PeerId,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) -> Option<Command<T>> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer_id));

        let mut inputs = Vec::with_capacity(on_chain_inputs.len() + off_chain_inputs.len());

        if !on_chain_inputs.is_empty() {
            let peer_bytes = peer_id.to_bytes();
            for (id, sig) in on_chain_inputs {
                let key = [peer_bytes.as_slice(), id.to_bytes().as_slice()].concat();
                let value = self.owner_db.get(key).ok().flatten()?;
                let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
                let token = Token::from_bytes(&value[8..]).expect("Token must be valid");
                let proof = self.mmr.prove_with_db(idx, &self.mmr_db).unwrap();
                inputs.push(Input::OnChain(token, id, proof, sig));
            }
        }

        for input in off_chain_inputs {
            inputs.push(Input::OffChain(input));
        }

        Some(Command::new(code, inputs, outputs))
    }

    pub fn create_atom(&self, cmd: Option<Command<T>>) -> Atom<T> {
        Atom::default()
            .with_parent(self.head)
            .with_height(self.entries[&self.head].atom.height + 1)
            .with_random(rand::random())
            .with_timestamp_now()
            .with_difficulty(self.entries[&self.head].difficulty)
            .with_state(self.mmr.state().clone())
            .with_command(cmd)
            .with_atoms(self.get_non_conflicting_children(self.head))
    }

    fn get_non_conflicting_children(&self, hash: Multihash) -> Vec<Pruned<T>> {
        let Some(entry) = self.entries.get(&hash) else {
            return vec![];
        };

        let len = entry.pruned_children.len();
        if len < T::BLOCK_THRESHOLD as usize {
            return vec![];
        }

        let mut consumed = HashSet::new();
        let mut result = Vec::new();

        'outer: for (i, pruned) in entry.pruned_children.values().enumerate() {
            if result.len() + (len - i) < T::BLOCK_THRESHOLD as usize {
                // Not enough remaining children to reach the threshold
                return vec![];
            }

            let Some(cmd) = &pruned.cmd else {
                result.push(pruned.clone());
                continue;
            };

            let mut child_consumed = HashSet::new();

            for input in &cmd.inputs {
                let Input::OnChain(_, id, _, _) = input else {
                    continue;
                };

                if consumed.contains(id) || child_consumed.contains(id) {
                    child_consumed.clear();
                    continue 'outer;
                }

                child_consumed.insert(*id);
            }

            consumed.extend(child_consumed);
            result.push(pruned.clone());
        }

        if result.len() < T::BLOCK_THRESHOLD as usize {
            return vec![];
        }

        result
    }

    pub fn tokens(&self, peer: &PeerId) -> HashMap<Multihash, Token<T>> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer));

        let iter = self.owner_db.prefix_iterator(peer.to_bytes());
        let mut tokens = HashMap::new();

        for item in iter {
            let (key, value) = item.unwrap();
            if !key.starts_with(&peer.to_bytes()) {
                break;
            }
            let id = Multihash::from_bytes(&key[peer.to_bytes().len()..]).unwrap();
            let token = Token::from_bytes(&value[8..]).unwrap();
            tokens.insert(id, token);
        }

        tokens
    }

    pub fn proofs(&self, peer: &PeerId) -> Proofs<T> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer));

        let iter = self.owner_db.prefix_iterator(peer.to_bytes());
        let mut proofs = Proofs::new();

        for item in iter {
            let (key, value) = item.unwrap();
            if !key.starts_with(&peer.to_bytes()) {
                break;
            }

            let id = Multihash::from_bytes(&key[peer.to_bytes().len()..]).unwrap();
            let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
            let token = Token::from_bytes(&value[8..]).unwrap();
            let proof = self.mmr.prove_with_db(idx, &self.mmr_db).unwrap();
            proofs.insert(id, (token, proof));
        }

        proofs
    }

    pub fn get(&self, hash: &Multihash) -> Option<&Atom<T>> {
        self.entries.get(hash).map(|e| &e.atom)
    }

    pub fn get_by_height(&self, height: Height) -> Option<Atom<T>> {
        self.atom_db
            .get(height.to_be_bytes())
            .ok()
            .flatten()
            .map(|v| Atom::<T>::from_bytes(&v).expect("Atom in DB must be valid"))
    }

    pub fn fill(&mut self, proofs: Proofs<T>) -> bool {
        let mut batch = WriteBatch::default();

        for (id, (token, proof)) in proofs {
            if !self.mmr.resolve_and_fill(id, &proof) {
                return false;
            }

            let id_bytes = id.to_bytes();
            let value = [&proof.idx.to_be_bytes(), token.to_bytes().as_slice()].concat();

            if let Some(peer_id) = self.peer_id {
                if !token.script_pk.is_related(peer_id) {
                    return false;
                }
                let key = [peer_id.to_bytes(), id_bytes].concat();
                batch.put(key, &value);
            } else {
                for peer_id in token.script_pk.related_peers() {
                    let key = [peer_id.to_bytes().as_slice(), id_bytes.as_slice()].concat();
                    batch.put(key, &value);
                }
            }
        }

        self.mmr.write_and_remove_non_peaks(&self.mmr_db).unwrap();
        self.owner_db.write(batch).unwrap();

        true
    }

    pub fn finalized(&self) -> Multihash {
        self.finalized
    }

    pub fn finalized_height(&self) -> Height {
        self.finalized_height
    }

    pub fn head(&self) -> Multihash {
        self.head
    }

    pub fn head_height(&self) -> Height {
        self.entries[&self.head].atom.height
    }

    pub fn head_to_finalized(&self) -> Vec<Atom<T>> {
        let mut result = Vec::new();
        let mut cur = self.head;

        while cur != self.finalized {
            let entry = &self.entries[&cur];
            result.push(entry.atom.clone());
            cur = entry.atom.parent;
        }

        result.reverse();
        result
    }

    pub fn status(&self) -> Status {
        Status {
            head: self.head,
            head_height: self.entries[&self.head].atom.height,
            finalized: self.finalized,
            finalized_height: self.finalized_height,
            difficulty: self.entries[&self.head].difficulty,
        }
    }

    pub fn headers(&self, start: Height, count: Height) -> Option<Vec<Multihash>> {
        let mut result = Vec::with_capacity(count as usize);

        if start < T::GENESIS_HEIGHT || start + count - 1 > self.finalized_height {
            return None;
        }

        for h in start..start + count {
            let atom = self.get_by_height(h)?;
            result.push(atom.hash());
        }

        Some(result)
    }
}

fn validate<T: Config>(parent: &Entry<T>, atom: &Atom<T>, check_diffculty: bool) -> Option<Reason> {
    if atom.height != parent.atom.height + 1 {
        return Some(Reason::invalid_height(atom.height, parent.atom.height));
    }

    if check_diffculty && atom.difficulty != parent.difficulty {
        return Some(Reason::mismatch_difficulty(
            parent.difficulty,
            atom.difficulty,
        ));
    }

    let mut consumed = HashSet::new();

    if atom.atoms.len() < T::BLOCK_THRESHOLD as usize {
        let cmd = atom.cmd.as_ref()?;

        if cmd.inputs.is_empty() {
            return Some(Reason::empty_input());
        }

        for input in &cmd.inputs {
            let Input::OnChain(token, id, proof, sig) = input else {
                continue;
            };

            if !consumed.insert(*id) {
                return Some(Reason::double_spend());
            }

            if !parent.mmr.verify(*id, proof) {
                return Some(Reason::invalid_mmr_proof());
            }

            if !token.script_pk.verify(sig) {
                return Some(Reason::invalid_script_sig());
            }
        }

        if !T::validate_command(cmd) {
            return Some(Reason::invalid_command());
        }

        return None;
    }

    for cmd in atom
        .atoms
        .iter()
        .filter_map(|a| a.cmd.as_ref())
        .chain(atom.cmd.as_ref())
    {
        if cmd.inputs.is_empty() {
            return Some(Reason::empty_input());
        }

        for input in &cmd.inputs {
            let Input::OnChain(token, id, proof, sig) = input else {
                continue;
            };

            if !consumed.insert(*id) {
                return Some(Reason::double_spend());
            }

            if !parent.mmr.verify(*id, proof) {
                return Some(Reason::invalid_mmr_proof());
            }

            if !token.script_pk.verify(sig) {
                return Some(Reason::invalid_script_sig());
            }
        }

        if !T::validate_command(cmd) {
            return Some(Reason::invalid_command());
        }
    }

    None
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let head = hex::encode(self.head.to_bytes());
        let finalized = hex::encode(self.finalized.to_bytes());
        writeln!(f, "Status {{")?;
        writeln!(f, "   head: {},", head)?;
        writeln!(f, "   head_height: {},", self.head_height)?;
        writeln!(f, "   finalized: {},", finalized)?;
        writeln!(f, "   finalized_height: {},", self.finalized_height)?;
        writeln!(f, "   difficulty: {}", self.difficulty)?;
        write!(f, "}}")
    }
}

impl<T: Config> Drop for Entry<T> {
    fn drop(&mut self) {
        drop(self.mmr_db.take());
        drop(self.owner_db.take());
        let _ = fs::remove_dir_all(&self.mmr_db_path);
        let _ = fs::remove_dir_all(&self.owner_db_path);
    }
}
