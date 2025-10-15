use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    marker::PhantomData,
    time::SystemTime,
};

use libp2p::PeerId;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::{
    chain_config::ChainConfig,
    crypto::{Hasher, Multihash},
    event::Proposal,
    ty::{
        atom::{Difficulty, Height, Pruned, Timestamp},
        Atom, Command, Input, Token,
    },
    utils::mmr::{Mmr, MmrProof},
    validator::ValidatorEngine,
};

mod reason;

pub use reason::Reason;

pub type Proofs = HashMap<Multihash, (Token, MmrProof)>;

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

struct Entry {
    pub atom: Atom,
    pub pruned_children: HashMap<Multihash, Pruned>,
    pub block_children: HashSet<Multihash>,
    pub descendants: HashSet<Multihash>,
    pub consumed: HashSet<Multihash>,
}

pub struct Tree<V: ValidatorEngine> {
    entries: HashMap<Multihash, Entry>,
    pending: HashMap<Multihash, HashMap<Multihash, Atom>>,
    dismissed: HashMap<Multihash, Reason>,

    head: Multihash,
    finalized: Multihash,
    finalized_height: Height,

    db: DB,
    mmr: Mmr,
    chain_config: ChainConfig,
    next_chain_config: Option<(Height, ChainConfig)>,
    window_start: Height,

    peer_id: Option<PeerId>,
    _marker: PhantomData<V>,
}

impl<V: ValidatorEngine> Tree<V> {
    pub fn new<P, T>(atom: Atom, dir: P, peer_id: T) -> Self
    where
        P: AsRef<std::path::Path>,
        T: Into<Option<PeerId>>,
    {
        let peer_id = peer_id.into();
        let db = Self::open_db(&dir);

        let mut batch = WriteBatch::default();

        let mmr = if peer_id.is_some() {
            Mmr::new(atom.state.clone()).expect("State in Atom must be valid")
        } else {
            let mut mmr = Mmr::default();
            apply_atom::<V>(
                &atom,
                atom.chain_config.hasher,
                &mut mmr,
                &db,
                &mut batch,
                peer_id,
            );
            assert_eq!(mmr.state(), atom.state);
            mmr
        };

        {
            let cf = db.cf_handle(ATOM_CF).unwrap();
            let key = atom.height.to_be_bytes();
            let value = atom.to_bytes();
            batch.put_cf(cf, key, value);
        }

        db.write(batch).unwrap();

        let id = atom.id(atom.chain_config.hasher);
        let height = atom.height;
        let chain_config = atom.chain_config;

        let entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            consumed: HashSet::new(),
        };

        Self {
            entries: HashMap::from([(id, entry)]),
            pending: HashMap::new(),
            dismissed: HashMap::new(),
            head: id,
            finalized: id,
            finalized_height: height,
            mmr,
            db,
            chain_config,
            next_chain_config: None,
            window_start: height,
            peer_id,
            _marker: PhantomData,
        }
    }

    fn open_db<P>(dir: P) -> DB
    where
        P: AsRef<std::path::Path>,
    {
        fs::create_dir_all(&dir).unwrap();

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let descs = [
            ColumnFamilyDescriptor::new(MMR_CF, Options::default()),
            ColumnFamilyDescriptor::new(OWNER_CF, Options::default()),
            ColumnFamilyDescriptor::new(ATOM_CF, Options::default()),
        ];

        DB::open_cf_descriptors(&opts, &dir, descs).unwrap()
    }

    pub fn upsert(&mut self, atom: Atom, in_sync: bool) -> UpdateResult {
        let mut result = UpdateResult::default();
        let id = atom.id(self.chain_config.hasher);

        if let Some(reason) = self.dismissed.get(&id) {
            result.dismissed.insert(id, reason.inherit());
            return result;
        }

        if self.entries.contains_key(&id) {
            result.dismissed.insert(id, Reason::already_existing());
            return result;
        }

        if self
            .pending
            .get(&atom.parent)
            .is_some_and(|m| m.contains_key(&id))
        {
            result.dismissed.insert(id, Reason::already_existing());
            return result;
        }

        if let Some(reason) = self.basic_validation(&atom) {
            self.remove_subtree(id, reason, &mut result);
            return result;
        }

        if let Some(reason) = self.dismissed.get(&atom.parent) {
            self.remove_subtree(id, reason.inherit_parent(), &mut result);
            return result;
        }

        if !self.entries.contains_key(&atom.parent) {
            result.missing = Some(atom.parent);
            self.pending
                .entry(atom.parent)
                .or_default()
                .insert(id, atom);
            return result;
        }

        self.final_validation(atom, in_sync, &mut result);

        result
    }

    fn basic_validation(&self, atom: &Atom) -> Option<Reason> {
        if atom.height <= self.finalized_height {
            return Some(Reason::below_finalized(atom.height, self.finalized_height));
        }

        if !atom.atoms.is_empty() && atom.atoms.len() < self.chain_config.block_threshold as usize {
            return Some(Reason::invalid_atom_threshold(
                atom.atoms.len(),
                atom.chain_config.block_threshold as usize,
            ));
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

    fn final_validation(&mut self, atom: Atom, in_sync: bool, result: &mut UpdateResult) {
        let id = atom.id(self.chain_config.hasher);

        let consumed = match self.validate(&atom, in_sync) {
            Ok(c) => c,
            Err(reason) => {
                self.remove_subtree(id, reason, result);
                return;
            }
        };

        if atom.atoms.len() < self.chain_config.block_threshold as usize {
            self.remove_descendants(atom.parent, Reason::non_block_parent(), result);
            let parent = self.entries.get_mut(&atom.parent).unwrap();
            parent.pruned_children.insert(id, Pruned::from_atom(atom));
            result.accepted.push(id);
            return;
        }

        let entry = Entry {
            atom,
            pruned_children: HashMap::new(),
            block_children: HashSet::new(),
            descendants: HashSet::new(),
            consumed,
        };

        let parent = entry.atom.parent;
        self.entries.insert(id, entry);
        self.entries
            .get_mut(&parent)
            .unwrap()
            .block_children
            .insert(id);

        result.accepted.push(id);

        self.update_weight(id);
        self.recompute_main_chain_and_finalized(in_sync);

        let Some(children) = self.pending.remove(&id) else {
            return;
        };

        children
            .into_values()
            .for_each(|atom| self.final_validation(atom, in_sync, result));
    }

    fn validate(&self, atom: &Atom, in_sync: bool) -> Result<HashSet<Multihash>, Reason> {
        {
            let exp = self.entries[&atom.parent].atom.height + 1;
            if atom.height != exp {
                return Err(Reason::invalid_height(atom.height, exp));
            }
        }

        if in_sync {
            let parent = self.entries[&atom.parent].atom.difficulty;

            if !atom.verify_nonce(self.chain_config.vdf_param, parent) {
                return Err(Reason::invalid_nonce());
            }

            let exp = self.calculate_difficulty(atom.parent, atom.height, atom.timestamp, parent);
            if exp != atom.difficulty {
                return Err(Reason::mismatch_difficulty(exp, atom.difficulty));
            }
        }

        let mmr = (!in_sync)
            .then(|| {
                let height = atom
                    .height
                    .saturating_sub(self.chain_config.confirmation_depth + 1);
                self.get_by_height(height).unwrap().state.clone()
            })
            .map(|s| Mmr::new(s).expect("State in Atom must be valid"));

        let mut consumed = HashSet::new();

        for cmd in atom
            .atoms
            .iter()
            .filter_map(|p| p.cmd.as_ref())
            .chain(atom.cmd.as_ref())
        {
            if cmd.inputs.is_empty() {
                return Err(Reason::empty_input());
            }

            for input in &cmd.inputs {
                let id = input.token.id(self.chain_config.hasher);

                if !consumed.insert(id) {
                    return Err(Reason::double_spend());
                }

                if mmr.as_ref().is_some_and(|m| !m.verify(id, &input.proof)) {
                    return Err(Reason::invalid_mmr_proof());
                }
            }

            if !V::validate(cmd) {
                return Err(Reason::invalid_command());
            }
        }

        let mut cur = atom.parent;
        while cur != self.finalized {
            let entry = &self.entries[&cur];
            if !entry.consumed.is_disjoint(&consumed) {
                return Err(Reason::double_spend());
            }
            cur = entry.atom.parent;
        }

        Ok(consumed)
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

    fn calculate_difficulty(
        &self,
        parent: Multihash,
        height: Height,
        timestamp: Timestamp,
        origin: Difficulty,
    ) -> Difficulty {
        let mut timestamps = self.collect_timestamps(parent, height, timestamp);
        diff_median(&mut timestamps)
            .map(|m| {
                let ratio_raw = self.chain_config.target_block_time_sec as f64 / m;
                let max_adj = self.chain_config.max_vdf_difficulty_adjustment as f64;
                let ratio = ratio_raw.clamp(1.0 / max_adj, max_adj);
                ((origin as f64 * ratio) as u64).max(1)
            })
            .unwrap_or(origin)
    }

    fn collect_timestamps(
        &self,
        parent: Multihash,
        height: Height,
        timestamp: Timestamp,
    ) -> Vec<Timestamp> {
        let start = height
            .saturating_sub(self.chain_config.maintenance_window)
            .max(self.window_start);

        let mut timestamps = Vec::with_capacity((height - start + 1) as usize);
        timestamps.push(timestamp);
        let mut cur_hash = parent;

        for height in (start..height).rev() {
            if height > self.finalized_height {
                let entry = &self.entries[&cur_hash];
                timestamps.push(entry.atom.timestamp);
                cur_hash = entry.atom.parent;
            } else {
                let atom = self.get_by_height(height).unwrap();
                timestamps.push(atom.timestamp);
                cur_hash = atom.parent;
            }
        }

        timestamps
    }

    fn update_weight(&mut self, mut cur: Multihash) {
        let hashes = self.entries[&cur]
            .atom
            .atoms_ids(self.chain_config.hasher)
            .to_vec();

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

    fn recompute_main_chain_and_finalized(&mut self, in_sync: bool) {
        let start = self.finalized;
        let new_head = self.select_heaviest_chain(start);
        debug_assert!(!in_sync || new_head != self.head);
        if new_head != self.head {
            self.head = new_head;
            self.try_advance_finalized(in_sync)
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

    fn try_advance_finalized(&mut self, in_sync: bool) {
        let head_height = self.entries[&self.head].atom.height;

        let (height, hash) = if in_sync {
            (head_height, self.head)
        } else {
            let height = head_height.saturating_sub(self.chain_config.confirmation_depth);
            if self.finalized_height >= height {
                return;
            }
            let hash = self.get_block_at_height(self.head, height);
            (height, hash)
        };

        let mut batch = WriteBatch::default();

        apply_atom::<V>(
            &self.entries[&hash].atom,
            self.chain_config.hasher,
            &mut self.mmr,
            &self.db,
            &mut batch,
            self.peer_id,
        );

        self.finalized = hash;
        self.finalized_height = height;
        self.chain_config = self.entries[&hash].atom.chain_config;
        self.entries.get_mut(&hash).unwrap().consumed.clear();

        if self
            .next_chain_config
            .as_ref()
            .is_some_and(|(h, _)| h < &height)
        {
            self.next_chain_config = None;
        }

        self.prune_non_descendants();

        {
            let cf = self.db.cf_handle(ATOM_CF).unwrap();
            let key = self.finalized_height.to_be_bytes();
            let value = self.entries[&self.finalized].atom.to_bytes();
            batch.put_cf(cf, key, value);

            let start = height.saturating_sub(self.chain_config.maintenance_window);
            if start > self.window_start {
                self.window_start = start;
                if self.peer_id.is_some() {
                    batch.delete_cf(cf, self.window_start.to_be_bytes());
                }
            }
        }

        self.db.write(batch).unwrap();
    }

    fn get_block_at_height(&self, mut cur: Multihash, height: Height) -> Multihash {
        loop {
            let e = &self.entries[&cur];
            if e.atom.height == height {
                return cur;
            }
            cur = e.atom.parent;
        }
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

    pub fn create_command(&self, proposal: Proposal, peer_id: &PeerId) -> Option<Command> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer_id));

        let mut inputs = Vec::with_capacity(proposal.inputs.len());

        if !proposal.inputs.is_empty() {
            let mmr_cf = self.db.cf_handle(MMR_CF).unwrap();
            let owner_cf = self.db.cf_handle(OWNER_CF).unwrap();
            let peer_bytes = peer_id.to_bytes();

            for (id, sig) in proposal.inputs {
                let mut key = Vec::with_capacity(peer_bytes.len() + id.encoded_len());
                key.extend_from_slice(peer_bytes.as_slice());
                key.extend_from_slice(id.to_bytes().as_slice());
                let value = self.db.get_cf(owner_cf, key).ok().flatten()?;
                let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
                let token = Token::from_bytes(&value[8..]).expect("Token must be valid");
                let proof = self.mmr.prove_with_cf(idx, &self.db, mmr_cf).unwrap();
                inputs.push(Input::new(token, proof, sig));
            }
        }

        Some(Command::new(
            proposal.code,
            inputs,
            proposal.outputs,
            self.chain_config.hasher,
        ))
    }

    pub fn create_atom(&self, cmd: Option<Command>) -> JoinHandle<Atom> {
        let parent = self.select_parent_for_creation();
        let atoms = self.get_non_conflicting_children(parent);
        let parent_atom = &self.entries[&parent].atom;
        let height = parent_atom.height + 1;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as Timestamp;

        let difficulty = if !atoms.is_empty() {
            self.calculate_difficulty(self.head, height, timestamp, parent_atom.difficulty)
        } else {
            parent_atom.difficulty
        };

        let chain_config = self.expected_chain_config(parent_atom.height + 1);
        let vdf_param = self.chain_config.vdf_param;
        let state = parent_atom.state.clone();
        let hasher = self.chain_config.hasher;

        tokio::task::spawn_blocking(move || {
            Atom::new(chain_config)
                .with_parent(parent)
                .with_height(height)
                .with_difficulty(difficulty)
                .with_random(rand::random())
                .with_timestamp(timestamp)
                .with_command(cmd)
                .with_atoms(atoms)
                .solve(vdf_param)
                .calculate_state(state, hasher)
        })
    }

    fn select_parent_for_creation(&self) -> Multihash {
        let exp = self.expected_chain_config(self.entries[&self.head].atom.height + 1);
        let mut cur = self.finalized;

        loop {
            let entry = &self.entries[&cur];

            let next = entry
                .block_children
                .iter()
                .filter(|child| self.entries[*child].atom.chain_config == exp)
                .max_by_key(|&&child| self.entries[&child].descendants.len())
                .copied();

            match next {
                Some(child) => cur = child,
                None => break cur,
            }
        }
    }

    fn expected_chain_config(&self, height: Height) -> ChainConfig {
        self.next_chain_config
            .filter(|(h, _)| height >= *h)
            .map(|(_, c)| c)
            .unwrap_or(self.chain_config)
    }

    fn get_non_conflicting_children(&self, hash: Multihash) -> Vec<Pruned> {
        let Some(entry) = self.entries.get(&hash) else {
            return vec![];
        };

        let len = entry.pruned_children.len();

        if len < self.chain_config.block_threshold as usize {
            return vec![];
        }

        let mut consumed = HashSet::new();
        let mut result = Vec::new();

        'outer: for (i, pruned) in entry.pruned_children.values().enumerate() {
            if result.len() + (len - i) < self.chain_config.block_threshold as usize {
                return vec![];
            }

            let Some(cmd) = &pruned.cmd else {
                result.push(pruned.clone());
                continue;
            };

            let mut child_consumed = HashSet::new();

            for input in &cmd.inputs {
                let id = input.token.id(self.chain_config.hasher);
                if consumed.contains(&id) || !child_consumed.insert(id) {
                    child_consumed.clear();
                    continue 'outer;
                }
            }

            consumed.extend(child_consumed);
            result.push(pruned.clone());
        }

        if result.len() < self.chain_config.block_threshold as usize {
            return vec![];
        }

        result
    }

    pub fn tokens(&self, peer: &PeerId) -> HashMap<Multihash, Token> {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer));

        let cf = self.db.cf_handle(OWNER_CF).unwrap();
        let peer_bytes = peer.to_bytes();
        let iter = self.db.prefix_iterator_cf(cf, &peer_bytes);
        let mut tokens = HashMap::new();

        for item in iter {
            let (key, value) = item.unwrap();
            if !key.starts_with(&peer_bytes) {
                break;
            }
            let token = Token::from_bytes(&value[8..]).unwrap();
            tokens.insert(token.id(self.chain_config.hasher), token);
        }

        tokens
    }

    pub fn proofs(&self, peer: &PeerId) -> Proofs {
        debug_assert!(self.peer_id.is_none_or(|p| &p == peer));

        let cf = self.db.cf_handle(OWNER_CF).unwrap();
        let iter = self.db.prefix_iterator_cf(cf, peer.to_bytes());
        let mut proofs = Proofs::new();

        for item in iter {
            let (key, value) = item.unwrap();
            if !key.starts_with(&peer.to_bytes()) {
                break;
            }
            let idx = u64::from_be_bytes(value[0..8].try_into().unwrap());
            let token = Token::from_bytes(&value[8..]).unwrap();
            let proof = self.mmr.prove_with_cf(idx, &self.db, cf).unwrap();
            proofs.insert(token.id(self.chain_config.hasher), (token, proof));
        }

        proofs
    }

    pub fn get(&self, hash: &Multihash) -> Option<&Atom> {
        self.entries.get(hash).map(|e| &e.atom)
    }

    pub fn get_by_height(&self, height: Height) -> Option<Atom> {
        let cf = self.db.cf_handle(ATOM_CF).unwrap();
        self.db
            .get_pinned_cf(cf, height.to_be_bytes())
            .unwrap()
            .map(|v| Atom::from_bytes(&v).expect("Atom in DB must be valid"))
    }

    pub fn fill(&mut self, proofs: Proofs) -> bool {
        let mut batch = WriteBatch::default();

        let mmr_cf = self.db.cf_handle(MMR_CF).unwrap();
        let owner_cf = self.db.cf_handle(OWNER_CF).unwrap();

        for (id, (token, proof)) in proofs {
            if !self.mmr.resolve_and_fill(id, &proof) {
                return false;
            }

            let id_bytes = id.to_bytes();

            let mut value = Vec::with_capacity(8 + token.to_bytes().len());
            value.extend(proof.idx.to_be_bytes());
            value.extend(token.to_bytes());

            if let Some(peer_id) = self.peer_id {
                if !V::is_related(&token.script_pk, &peer_id) {
                    return false;
                }
                let mut key = Vec::with_capacity(peer_id.as_ref().encoded_len() + id_bytes.len());
                key.extend(peer_id.to_bytes());
                key.extend(&id_bytes);
                batch.put_cf(owner_cf, key, &value);
            } else {
                for peer_id in V::related_peers(&token.script_pk) {
                    let mut key =
                        Vec::with_capacity(peer_id.as_ref().encoded_len() + id_bytes.len());
                    key.extend(peer_id.to_bytes());
                    key.extend(&id_bytes);
                    batch.put_cf(owner_cf, key, &value);
                }
            }
        }

        self.mmr.write_cf(mmr_cf, &mut batch);
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

    pub fn head_to_finalized(&self) -> Vec<Atom> {
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
            difficulty: self.entries[&self.head].atom.difficulty,
            median_block_interval: self.median_block_interval(),
            average_tps: self.average_tps(),
        }
    }

    fn median_block_interval(&self) -> Option<f64> {
        let head = &self.entries[&self.head];
        let mut timestamps =
            self.collect_timestamps(head.atom.parent, head.atom.height, head.atom.timestamp);
        diff_median(&mut timestamps)
    }

    fn average_tps(&self) -> Option<f64> {
        let head_height = self.entries[&self.head].atom.height;
        let start = head_height
            .saturating_sub(self.chain_config.maintenance_window)
            .max(self.window_start);

        if start == head_height {
            return None;
        }

        let mut total_commands = 0u64;
        let mut cur_hash = self.head;
        let mut start_timestamp = None;
        let mut end_timestamp = None;

        for height in (start..=head_height).rev() {
            if height > self.finalized_height {
                let entry = self.entries.get(&cur_hash)?;

                if height == head_height {
                    end_timestamp = Some(entry.atom.timestamp);
                }

                if height == start {
                    start_timestamp = Some(entry.atom.timestamp);
                }

                total_commands +=
                    entry.atom.atoms.iter().filter(|a| a.cmd.is_some()).count() as u64;
                if entry.atom.cmd.is_some() {
                    total_commands += 1;
                }
                cur_hash = entry.atom.parent;
            } else {
                let atom = self.get_by_height(height)?;

                if height == head_height {
                    end_timestamp = Some(atom.timestamp);
                }

                if height == start {
                    start_timestamp = Some(atom.timestamp);
                }

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

    pub fn hasher(&self) -> Hasher {
        self.chain_config.hasher
    }

    pub fn vdf_param(&self) -> u16 {
        self.chain_config.vdf_param
    }

    pub fn set_next_chain_config(&mut self, height: Height, config: ChainConfig) -> bool {
        if self.next_chain_config.is_some() {
            return false;
        }

        if height <= self.finalized_height {
            return false;
        }

        self.next_chain_config = Some((height, config));
        true
    }
}

fn apply_atom<V: ValidatorEngine>(
    atom: &Atom,
    hasher: Hasher,
    mmr: &mut Mmr,
    db: &DB,
    batch: &mut WriteBatch,
    peer_id: Option<PeerId>,
) {
    let mut keep = Vec::new();
    let mmr_cf = db.cf_handle(MMR_CF).unwrap();
    let owner_cf = db.cf_handle(OWNER_CF).unwrap();
    let mut changed = false;

    atom.atoms
        .iter()
        .filter_map(|a| a.cmd.as_ref())
        .chain(atom.cmd.as_ref())
        .for_each(|cmd| {
            changed = true;

            cmd.inputs.iter().for_each(|input| {
                let id = input.token.id(hasher);
                let _ = mmr.delete(id, &input.proof);

                if let Some(peer_id) = peer_id {
                    if V::is_related(&input.token.script_pk, &peer_id) {
                        let mut key =
                            Vec::with_capacity(peer_id.as_ref().encoded_len() + id.encoded_len());
                        key.extend(peer_id.to_bytes());
                        key.extend(id.to_bytes());
                        batch.delete_cf(owner_cf, key);
                    }
                } else {
                    let id_bytes = id.to_bytes();
                    for peer_id in V::related_peers(&input.token.script_pk) {
                        let mut key =
                            Vec::with_capacity(peer_id.as_ref().encoded_len() + id_bytes.len());
                        key.extend(peer_id.to_bytes());
                        key.extend_from_slice(&id_bytes);
                        batch.delete_cf(owner_cf, key);
                    }
                }
            });

            cmd.outputs.iter().for_each(|token| {
                let id = token.id(hasher);
                let idx = mmr.append(id);

                if let Some(peer_id) = peer_id {
                    if V::is_related(&token.script_pk, &peer_id) {
                        keep.push(idx);
                        let mut key =
                            Vec::with_capacity(peer_id.as_ref().encoded_len() + id.encoded_len());
                        key.extend(peer_id.to_bytes());
                        key.extend(id.to_bytes());
                        let mut value = Vec::new();
                        value.extend(&idx.to_be_bytes());
                        value.extend(token.to_bytes());
                        batch.put_cf(owner_cf, key, value);
                    }
                } else {
                    let id_bytes = id.to_bytes();
                    for peer_id in V::related_peers(&token.script_pk) {
                        let mut key =
                            Vec::with_capacity(peer_id.as_ref().encoded_len() + id_bytes.len());
                        key.extend(peer_id.to_bytes());
                        key.extend_from_slice(&id_bytes);
                        let mut value = Vec::new();
                        value.extend(&idx.to_be_bytes());
                        value.extend(token.to_bytes());
                        batch.put_cf(owner_cf, key, value);
                    }
                }
            });
        });

    if !changed {
        return;
    }

    mmr.commit();

    if peer_id.is_some() {
        mmr.prune(&keep);
    }

    mmr.write_cf(mmr_cf, batch);
}

fn diff_median(values: &mut [u64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }

    let diffs = values
        .windows(2)
        .filter_map(|w| w[1].checked_sub(w[0]))
        .collect::<Vec<_>>();

    match diffs.len() {
        0 => None,
        1 => Some(diffs[0] as f64),
        n if n.is_multiple_of(2) => Some((diffs[n / 2 - 1] as f64 + diffs[n / 2] as f64) / 2.0),
        n => Some(diffs[n / 2] as f64),
    }
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
