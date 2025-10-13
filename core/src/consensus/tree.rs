use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
};

use libp2p::PeerId;
use multihash_derive::MultihashDigest;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Multihash,
    event::Proposal,
    traits::{Config, ScriptPubKey},
    ty::{
        atom::{Difficulty, Height, Pruned, Timestamp},
        Atom, Command, Input, Token,
    },
    utils::mmr::{Mmr, MmrProof},
};

mod reason;

pub use reason::Reason;

pub type Proofs<T> = HashMap<Multihash, (Token<T>, MmrProof)>;

const MMR_CF: &str = "mmr";
const OWNER_CF: &str = "owner";
const ATOM_CF: &str = "atom";

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
    pub median_block_interval: Option<f64>,
    pub average_tps: Option<f64>,
}

struct Entry<T: Config> {
    pub atom: Atom<T>,
    pub pruned_children: HashMap<Multihash, Pruned<T>>,
    pub block_children: HashSet<Multihash>,
    pub descendants: HashSet<Multihash>,
    pub consumed: HashSet<Multihash>,
    pub difficulty: Difficulty,
}

pub struct Tree<T: Config> {
    entries: HashMap<Multihash, Entry<T>>,
    pending: HashMap<Multihash, HashMap<Multihash, Atom<T>>>,
    dismissed: HashMap<Multihash, Reason>,

    head: Multihash,
    finalized: Multihash,
    finalized_height: Height,

    db: DB,
    mmr: Mmr,
    peer_id: Option<PeerId>,
}

impl<T: Config> Tree<T> {
    pub fn genesis<P>(dir: P, peer_id: Option<PeerId>) -> Self
    where
        P: AsRef<std::path::Path>,
    {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).unwrap();

        let db = {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);

            let descs = [
                ColumnFamilyDescriptor::new(MMR_CF, Options::default()),
                ColumnFamilyDescriptor::new(OWNER_CF, Options::default()),
                ColumnFamilyDescriptor::new(ATOM_CF, Options::default()),
            ];

            DB::open_cf_descriptors(&opts, dir, descs).unwrap()
        };

        let mut mmr = Mmr::default();
        let mut owner_batch = WriteBatch::default();
        let mmr_cf = db.cf_handle(MMR_CF).unwrap();
        let owner_cf = db.cf_handle(OWNER_CF).unwrap();

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
                        owner_batch.put_cf(owner_cf, key, &value);
                        keep.push(idx);
                    }
                } else {
                    for peer_id in token.script_pk.related_peers() {
                        let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                        owner_batch.put_cf(owner_cf, key, &value);
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

        mmr.write_cf_and_remove_non_peaks(&db, mmr_cf).unwrap();
        db.write(owner_batch).unwrap();

        let hash = genesis.hash();
        let height = genesis.height;

        let entry = Entry {
            atom: genesis,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            consumed: HashSet::new(),
            difficulty: T::GENESIS_VAF_DIFFICULTY,
        };

        Self {
            entries: HashMap::from([(hash, entry)]),
            pending: HashMap::new(),
            dismissed: HashMap::new(),
            head: hash,
            finalized: hash,
            finalized_height: height,
            db,
            mmr,
            peer_id,
        }
    }

    pub fn load_or_genesis<P>(dir: P) -> Option<Self>
    where
        P: AsRef<std::path::Path>,
    {
        let mut tree = Self::genesis(dir.as_ref(), None);
        let atoms = tree.resolve_from_db();

        for atom in atoms {
            let _ = tree.upsert(atom, true);
        }

        Some(tree)
    }

    fn resolve_from_db(&self) -> Vec<Atom<T>> {
        let cf = self.db.cf_handle(ATOM_CF).unwrap();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
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

    pub fn with_atom<P>(atom: Atom<T>, dir: P, peer_id: PeerId) -> Self
    where
        P: AsRef<std::path::Path>,
    {
        debug_assert_ne!(atom.height, 0);

        let dir = dir.as_ref();
        fs::create_dir_all(dir).unwrap();

        let hash = atom.hash();
        let height = atom.height;
        let difficulty = atom.difficulty;
        let mmr = Mmr::new(atom.state.clone()).expect("State in Atom must be valid");

        let entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            consumed: HashSet::new(),
            difficulty,
        };

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let descs = [
            ColumnFamilyDescriptor::new(MMR_CF, Options::default()),
            ColumnFamilyDescriptor::new(OWNER_CF, Options::default()),
            ColumnFamilyDescriptor::new(ATOM_CF, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, dir, descs).unwrap();

        let cf = db.cf_handle(ATOM_CF).unwrap();
        let key = height.to_be_bytes();
        let value = entry.atom.to_bytes();
        db.put_cf(cf, key, value).unwrap();

        Self {
            entries: HashMap::from([(hash, entry)]),
            pending: HashMap::new(),
            dismissed: HashMap::new(),
            head: hash,
            finalized: hash,
            finalized_height: height,
            mmr,
            db,
            peer_id: Some(peer_id),
        }
    }

    pub fn upsert(&mut self, atom: Atom<T>, force: bool) -> UpdateResult {
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

        self.final_validation(atom, force, &mut result);

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

    fn final_validation(&mut self, atom: Atom<T>, force: bool, result: &mut UpdateResult) {
        let hash = atom.hash();
        let parent = atom.parent;

        let ori_start = atom.height.saturating_sub(T::MAINTENANCE_WINDOW).max(1);
        let check_difficulty = {
            let cf = self.db.cf_handle(ATOM_CF).unwrap();
            self.db
                .get_pinned_cf(cf, ori_start.to_be_bytes())
                .unwrap()
                .is_some()
        };

        if let Some(reason) = validate(&self.entries[&parent], &self.mmr, &atom, check_difficulty) {
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
        self.recompute_main_chain_and_finalized(force);

        let Some(children) = self.pending.remove(&hash) else {
            return;
        };

        children
            .into_values()
            .for_each(|atom| self.final_validation(atom, force, result));
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
        let parent = &self.entries[&atom.parent];

        let mut entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            consumed: parent.consumed.clone(),
            difficulty: parent.difficulty,
        };

        if let Some(timestamps) = self.collect_timestamps(&entry.atom) {
            let diffs = timestamps
                .windows(2)
                .filter_map(|w| w[0].checked_sub(w[1]))
                .collect::<Vec<_>>();

            if diffs.len() >= 2 {
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
        }

        for cmd in entry
            .atom
            .atoms
            .iter()
            .filter_map(|a| a.cmd.as_ref())
            .chain(entry.atom.cmd.as_ref())
        {
            for input in &cmd.inputs {
                if let Input::OnChain(_, id, _, _) = input {
                    entry.consumed.insert(*id);
                }
            }
        }

        self.entries
            .get_mut(&entry.atom.parent)
            .unwrap()
            .block_children
            .insert(hash);

        entry
    }

    fn collect_timestamps(&self, atom: &Atom<T>) -> Option<Vec<Timestamp>> {
        let start = atom.height.saturating_sub(T::MAINTENANCE_WINDOW).max(1);

        if start == atom.height {
            return Some(vec![atom.timestamp]);
        }

        let cf = self.db.cf_handle(ATOM_CF).unwrap();
        self.db
            .get_pinned_cf(cf, start.to_be_bytes())
            .ok()
            .flatten()?;

        let mut timestamps = Vec::with_capacity((atom.height - start + 1) as usize);
        timestamps.push(atom.timestamp);
        let mut cur_hash = atom.parent;

        for height in (start..atom.height).rev() {
            if height > self.finalized_height {
                let entry = self.entries.get(&cur_hash)?;
                timestamps.push(entry.atom.timestamp);
                cur_hash = entry.atom.parent;
            } else {
                let atom = self.get_by_height(height)?;
                timestamps.push(atom.timestamp);
                cur_hash = atom.parent;
            }
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

    fn recompute_main_chain_and_finalized(&mut self, force: bool) {
        let start = self.finalized;
        let new_head = self.select_heaviest_chain(start);
        debug_assert!(!force || new_head != self.head);
        if new_head != self.head {
            self.head = new_head;
            self.try_advance_finalized(force)
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

    fn try_advance_finalized(&mut self, force: bool) {
        let head_height = self.entries[&self.head].atom.height;

        let (height, hash) = if force {
            (head_height, self.head)
        } else {
            let target_height = head_height.saturating_sub(T::CONFIRMATION_DEPTH);
            if self.finalized_height >= target_height {
                return;
            }
            let hash = self.get_block_at_height(self.head, target_height);
            (target_height, hash)
        };

        {
            let entry = &self.entries[&hash];
            let mut batch = WriteBatch::default();

            let mmr_cf = self.db.cf_handle(MMR_CF).unwrap();
            let owner_cf = self.db.cf_handle(OWNER_CF).unwrap();

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

                    let _ = self.mmr.delete(*id, proof);
                    let id_bytes = id.to_bytes();

                    if let Some(peer_id) = self.peer_id {
                        if token.script_pk.is_related(peer_id) {
                            let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                            batch.delete_cf(owner_cf, key);
                        }
                    } else {
                        for peer_id in token.script_pk.related_peers() {
                            let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                            batch.delete_cf(owner_cf, key);
                        }
                    }
                }

                let first_input = cmd.inputs[0].id().to_bytes();

                for (i, token) in cmd.outputs.iter().enumerate() {
                    let buf = [first_input.as_slice(), &(i as u32).to_be_bytes()].concat();
                    let id = T::HASHER.digest(&buf);
                    let id_bytes = id.to_bytes();
                    let idx = self.mmr.append(id);
                    let value: Vec<u8> = [&idx.to_be_bytes(), token.to_bytes().as_slice()].concat();

                    if let Some(peer_id) = self.peer_id {
                        if token.script_pk.is_related(peer_id) {
                            let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                            batch.put_cf(owner_cf, key, &value);
                        }
                    } else {
                        for peer_id in token.script_pk.related_peers() {
                            let key = [peer_id.to_bytes().as_slice(), id_bytes.as_ref()].concat();
                            batch.put_cf(owner_cf, key, &value);
                        }
                    }
                }
            }

            self.mmr.commit();
            self.mmr
                .write_cf_and_remove_non_peaks(&self.db, mmr_cf)
                .unwrap();
            self.db.write(batch).unwrap();
        }

        self.finalized = hash;
        self.finalized_height = height;

        self.prune_non_descendants();

        let entry = &self.entries[&self.finalized];

        let key = self.finalized_height.to_be_bytes();
        let value = entry.atom.to_bytes();
        let cf = self.db.cf_handle(ATOM_CF).unwrap();
        self.db.put_cf(cf, key, value).unwrap();

        if self.peer_id.is_some() {
            if let Some(height) = height.checked_sub(T::MAINTENANCE_WINDOW) {
                let key = height.to_be_bytes();
                let _ = self.db.delete_cf(cf, key);
            }
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

    pub fn create_command(&self, proposal: Proposal<T>, peer_id: &PeerId) -> Option<Command<T>> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer_id));

        let mut inputs =
            Vec::with_capacity(proposal.on_chain_inputs.len() + proposal.off_chain_inputs.len());

        if !proposal.on_chain_inputs.is_empty() {
            let mmr_cf = self.db.cf_handle(MMR_CF).unwrap();
            let owner_cf = self.db.cf_handle(OWNER_CF).unwrap();

            let peer_bytes = peer_id.to_bytes();
            for (id, sig) in proposal.on_chain_inputs {
                let key = [peer_bytes.as_slice(), id.to_bytes().as_slice()].concat();
                let value = self.db.get_cf(owner_cf, key).ok().flatten()?;
                let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
                let token = Token::from_bytes(&value[8..]).expect("Token must be valid");
                let proof = self.mmr.prove_with_cf(idx, &self.db, mmr_cf).unwrap();
                inputs.push(Input::OnChain(token, id, proof, sig));
            }
        }

        for input in proposal.off_chain_inputs {
            inputs.push(Input::OffChain(input));
        }

        Some(Command::new(proposal.code, inputs, proposal.outputs))
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

        let cf = self.db.cf_handle(OWNER_CF).unwrap();
        let iter = self.db.prefix_iterator_cf(cf, peer.to_bytes());
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

        let cf = self.db.cf_handle(OWNER_CF).unwrap();
        let iter = self.db.prefix_iterator_cf(cf, peer.to_bytes());
        let mut proofs = Proofs::new();

        for item in iter {
            let (key, value) = item.unwrap();
            if !key.starts_with(&peer.to_bytes()) {
                break;
            }

            let id = Multihash::from_bytes(&key[peer.to_bytes().len()..]).unwrap();
            let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
            let token = Token::from_bytes(&value[8..]).unwrap();
            let proof = self.mmr.prove_with_cf(idx, &self.db, cf).unwrap();
            proofs.insert(id, (token, proof));
        }

        proofs
    }

    pub fn get(&self, hash: &Multihash) -> Option<&Atom<T>> {
        self.entries.get(hash).map(|e| &e.atom)
    }

    pub fn get_by_height(&self, height: Height) -> Option<Atom<T>> {
        let cf = self.db.cf_handle(ATOM_CF).unwrap();
        self.db
            .get_cf(cf, height.to_be_bytes())
            .ok()
            .flatten()
            .map(|v| Atom::<T>::from_bytes(&v).expect("Atom in DB must be valid"))
    }

    pub fn fill(&mut self, proofs: Proofs<T>) -> bool {
        let mut batch = WriteBatch::default();

        let mmr_cf = self.db.cf_handle(MMR_CF).unwrap();
        let owner_cf = self.db.cf_handle(OWNER_CF).unwrap();

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
                batch.put_cf(owner_cf, key, &value);
            } else {
                for peer_id in token.script_pk.related_peers() {
                    let key = [peer_id.to_bytes().as_slice(), id_bytes.as_slice()].concat();
                    batch.put_cf(owner_cf, key, &value);
                }
            }
        }

        self.mmr
            .write_cf_and_remove_non_peaks(&self.db, mmr_cf)
            .unwrap();
        self.db.write(batch).unwrap();

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
            median_block_interval: self.median_block_interval(),
            average_tps: self.average_tps(),
        }
    }

    fn median_block_interval(&self) -> Option<f64> {
        let head = &self.entries[&self.head];
        let timestamps = self.collect_timestamps(&head.atom)?;

        if timestamps.len() < 2 {
            return None;
        }

        let mut intervals: Vec<u64> = timestamps
            .windows(2)
            .filter_map(|w| w[0].checked_sub(w[1]))
            .collect();

        if intervals.is_empty() {
            return None;
        }

        intervals.sort_unstable();

        let len = intervals.len();

        let median = if len.is_multiple_of(2) {
            let mid1 = intervals[len / 2 - 1] as f64;
            let mid2 = intervals[len / 2] as f64;
            (mid1 + mid2) / 2.0
        } else {
            intervals[len / 2] as f64
        };

        Some(median)
    }

    fn average_tps(&self) -> Option<f64> {
        let head_height = self.entries[&self.head].atom.height;
        let start = head_height.saturating_sub(T::MAINTENANCE_WINDOW).max(1);

        if start == head_height {
            return None;
        }

        let mut total_commands = 0u64;
        let mut cur_hash = self.head;
        let mut start_timestamp = None;
        let mut end_timestamp = None;

        for height in (start..=head_height).rev() {
            if height == head_height {
                end_timestamp = Some(self.entries[&cur_hash].atom.timestamp);
            }

            if height == start {
                start_timestamp = Some(self.entries[&cur_hash].atom.timestamp);
            }

            if height > self.finalized_height {
                let entry = self.entries.get(&cur_hash)?;
                total_commands +=
                    entry.atom.atoms.iter().filter(|a| a.cmd.is_some()).count() as u64;
                if entry.atom.cmd.is_some() {
                    total_commands += 1;
                }
                cur_hash = entry.atom.parent;
            } else {
                let atom = self.get_by_height(height)?;
                total_commands += atom.atoms.iter().filter(|a| a.cmd.is_some()).count() as u64;
                if atom.cmd.is_some() {
                    total_commands += 1;
                }
                cur_hash = atom.parent;
            }
        }

        let start_timestamp = start_timestamp.expect("start timestamp must be present");
        let end_timestamp = end_timestamp.expect("end timestamp must be present");
        let duration = end_timestamp.checked_sub(start_timestamp)?;

        if duration == 0 {
            return None;
        }

        Some(total_commands as f64 / duration as f64)
    }

    pub fn headers(&self, start: Height, count: Height) -> Option<Vec<Multihash>> {
        let mut result = Vec::with_capacity(count as usize);

        if start == 0 || start + count - 1 > self.finalized_height {
            return None;
        }

        for h in start..start + count {
            let atom = self.get_by_height(h)?;
            result.push(atom.hash());
        }

        Some(result)
    }
}

fn validate<T: Config>(
    parent: &Entry<T>,
    mmr: &Mmr,
    atom: &Atom<T>,
    check_diffculty: bool,
) -> Option<Reason> {
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

            if !mmr.verify(*id, proof) {
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

            if !mmr.verify(*id, proof) {
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
        writeln!(
            f,
            "   median_block_interval: {}",
            if let Some(mbi) = self.median_block_interval {
                format!("{:.2} sec", mbi)
            } else {
                "N/A".to_string()
            }
        )?;
        writeln!(
            f,
            "   average_tps: {}",
            if let Some(tps) = self.average_tps {
                format!("{:.2} tps", tps)
            } else {
                "N/A".to_string()
            }
        )?;
        write!(f, "}}")
    }
}
