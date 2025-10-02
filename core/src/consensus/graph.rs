use std::collections::{HashMap, HashSet, VecDeque};

use derivative::Derivative;
use libp2p::PeerId;
use multihash_derive::MultihashDigest;

use crate::{
    crypto::Multihash,
    traits::{Config, ScriptPubKey},
    ty::{
        atom::{Atom, AtomBuilder, Height},
        Command, Input, Token,
    },
    utils::mmr::{Mmr, MmrProof},
};

pub type Proofs<T> = HashMap<Multihash, (Token<T>, MmrProof)>;

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum RejectReason {
    AlreadyDismissed,
    DismissedParent,
    HeightBelowFinalized,
    SelfReference,
    ParentInAtoms,
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

    #[error("Unknown token id")]
    UnknownTokenId,

    #[error("Failed to prove input token in MMR")]
    FailedToProveInput,

    #[error("Missing script signature for input token")]
    MissingScriptSig,

    #[error("Storage is empty")]
    EmptyStorage,

    #[error("Invalid atoms")]
    InvalidAtoms,

    #[error("Invalid tokens")]
    InvalidTokens,

    #[error("Peer not tracked")]
    PeerNotTracked,
}

#[derive(Clone, Copy)]
pub struct Status {
    pub main_head: Multihash,
    pub main_height: Height,
    pub finalized: Multihash,
    pub finalized_height: Height,
    pub difficulty: u64,
}

#[derive(Debug)]
#[derive(Default)]
pub struct UpdateResult {
    pub accepted: Vec<Multihash>,
    pub rejected: HashMap<Multihash, RejectReason>,
    pub missing: HashSet<Multihash>,
    pub finalized: Vec<Multihash>,
    pub existing: bool,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derivative(Default(bound = "T: Config"))]
struct Entry<T: Config> {
    pub atom: Atom<T>,
    pub children: HashSet<Multihash>,
    pub excluded: bool,
    pub is_block: bool,
    pub cmd_children: HashSet<Multihash>,
    pub pending_parents: usize,
    pub is_missing: bool,
}

pub struct Graph<T: Config> {
    entries: HashMap<Multihash, Entry<T>>,
    dismissed: HashSet<Multihash>,
    main_head: Multihash,
    finalized: Multihash,
    finalized_height: Height,
    finalized_blocks: VecDeque<Multihash>,
    difficulty: u64,
    mmr: Mmr,
    consumed_tokens: HashSet<Multihash>,
    peer_id: Option<PeerId>,
    peer_tokens: HashMap<PeerId, HashMap<Multihash, (u64, Token<T>)>>,
}

impl<T: Config> Entry<T> {
    pub fn new(atom: Atom<T>) -> Self {
        Self {
            atom,
            ..Default::default()
        }
    }

    pub fn new_missing() -> Self {
        Self {
            is_missing: true,
            ..Default::default()
        }
    }
}

impl<T: Config> Graph<T> {
    pub fn new(atom: Atom<T>, peer_id: Option<PeerId>) -> Self {
        let hash = atom.hash();
        let height = atom.height;
        let difficulty = atom.difficulty;
        let mmr = Mmr::with_peaks(atom.peaks.clone());

        Self {
            entries: HashMap::from_iter([(hash, Entry::new(atom))]),
            dismissed: HashSet::new(),
            main_head: hash,
            finalized: hash,
            finalized_height: height,
            finalized_blocks: VecDeque::from([hash]),
            difficulty,
            mmr,
            consumed_tokens: HashSet::new(),
            peer_id,
            peer_tokens: HashMap::new(),
        }
    }

    pub fn upsert(&mut self, atom: Atom<T>) -> UpdateResult {
        let mut result = UpdateResult::default();
        let hash = atom.hash();

        if self.contains(&hash) {
            result.existing = true;
            return result;
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
            return result;
        }

        match self.validate_parents(hash) {
            Ok(missing) => {
                if !missing.is_empty() {
                    self.entries.get_mut(&hash).unwrap().pending_parents = missing.len();
                    result.missing = missing;
                    return result;
                }
            }
            Err(r) => {
                self.remove_subgraph(hash, r, &mut result);
                return result;
            }
        }

        if let Err(r) = self.final_validation(hash) {
            self.remove_subgraph(hash, r, &mut result);
            return result;
        }

        result.accepted.push(hash);

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
                        result.accepted.push(child);
                        stk.push_back(child);
                    }
                }
            }
        }

        result
    }

    fn contains(&self, h: &Multihash) -> bool {
        !self.dismissed.contains(h) && self.entries.get(h).is_some_and(|e| !e.is_missing)
    }

    fn basic_validation(&self, hash: &Multihash) -> Result<(), RejectReason> {
        let atom = &self.entries[hash].atom;

        if self.dismissed.contains(hash) {
            return Err(RejectReason::AlreadyDismissed);
        }

        if atom.height <= self.finalized_height {
            return Err(RejectReason::HeightBelowFinalized);
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

            let parent = self
                .entries
                .entry(parent_hash)
                .or_insert_with(Entry::new_missing);

            if parent.is_missing {
                missing.insert(parent_hash);
            }

            parent.children.insert(hash);
        }

        Ok(missing)
    }

    fn final_validation(&mut self, hash: Multihash) -> Result<(), RejectReason> {
        let atom = &self.entries[&hash].atom;

        if atom.height != self.entries[&atom.parent].atom.height + 1 {
            return Err(RejectReason::InvalidHeight);
        }

        if atom.atoms.iter().any(|h| self.entries[h].is_block) {
            return Err(RejectReason::BlockInAtoms);
        }

        if !atom.verify_nonce(self.difficulty) {
            return Err(RejectReason::InvalidNonce);
        }

        if !self.validate_execution(&hash)? {
            return Ok(());
        }

        self.update_weight(hash);
        self.recompute_main_chain_and_finalized();

        Ok(())
    }

    fn validate_execution(&mut self, target_hash: &Multihash) -> Result<bool, RejectReason> {
        let mut consumed = HashMap::<Multihash, (T::ScriptPk, MmrProof)>::new();
        let mut cmd_children = HashSet::new();
        let mut excluded = false;

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
            cmd_children.insert(atom.hash());

            if cmd.inputs.is_empty() {
                return Err(RejectReason::EmptyInput);
            }

            for input in &cmd.inputs {
                let Input::OnChain(token, id, proof, sig) = input else {
                    continue;
                };

                if self.consumed_tokens.contains(id) {
                    excluded = true;
                    continue;
                }

                if consumed
                    .insert(*id, (token.script_pk.clone(), proof.clone()))
                    .is_some()
                {
                    return Err(RejectReason::DoubleSpend);
                }

                if !self.mmr.verify(*id, proof) {
                    return Err(RejectReason::MissingProof);
                }

                if !token.script_pk.verify(sig) {
                    return Err(RejectReason::InvalidScriptSig);
                }
            }

            if !T::validate_command(cmd) {
                return Err(RejectReason::InvalidConversion);
            }
        }

        if target.atom.atoms.len() + 1 < T::BLOCK_THRESHOLD as usize {
            if excluded {
                let parent_hash = self.entries[target_hash].atom.parent;
                let parent = self.entries.get_mut(&parent_hash).unwrap();
                parent.children.remove(target_hash);
            } else {
                self.consumed_tokens.extend(consumed.keys().copied());
            }

            return Ok(false);
        }

        let cur = self.entries.get_mut(target_hash).unwrap();
        cur.cmd_children = cmd_children;
        cur.excluded = false;
        cur.is_block = true;

        Ok(true)
    }

    fn update_weight(&mut self, start: Multihash) {
        let (cmds, mut cur) = {
            let e = self.entries.get(&start).unwrap();
            (e.cmd_children.clone(), e.atom.parent)
        };

        while cur != self.finalized {
            let entry = self.entries.get_mut(&cur).unwrap();
            entry.cmd_children.extend(cmds.iter().copied());
            cur = entry.atom.parent;
        }
    }

    fn recompute_main_chain_and_finalized(&mut self) {
        let start = self.finalized;
        let new_head = self.ghost_select(start);

        if new_head == self.main_head {
            return;
        }

        self.main_head = new_head;
        self.maybe_advance_finalized();
    }

    fn ghost_select(&self, mut cur: Multihash) -> Multihash {
        while let Some(next) = self
            .entries
            .get(&cur)
            .unwrap()
            .children
            .iter()
            .copied()
            .filter(|c| self.entries[c].is_block)
            .map(|c| (self.entries[&c].cmd_children.len(), c))
            .max()
            .map(|(.., c)| c)
        {
            cur = next;
        }

        cur
    }

    fn maybe_advance_finalized(&mut self) {
        let head_height = self.entries[&self.main_head].atom.height;
        let target_finalized_height = head_height.saturating_sub(T::CONFIRMATION_DEPTH);

        if target_finalized_height <= self.finalized_height {
            return;
        }

        assert_eq!(
            target_finalized_height,
            self.finalized_height + 1,
            "Finalization height jumped from {} to {}, which violates consensus assumptions",
            self.finalized_height,
            target_finalized_height
        );

        let new_finalized = self.get_block_at_height(self.main_head, target_finalized_height);

        debug_assert_eq!(
            self.entries[&new_finalized].atom.parent, self.finalized,
            "New finalized block's parent must be the current finalized block"
        );

        self.apply_block_to_mmr(new_finalized);

        self.finalized_blocks.push_back(new_finalized);
        while self.finalized_blocks.len() > T::MAINTENANCE_WINDOW as usize {
            if let Some(old_block) = self.finalized_blocks.pop_front() {
                self.prune_block(old_block);
            }
        }

        self.prune_non_descendants(new_finalized);

        self.difficulty = self.calculate_difficulty();
        self.finalized = new_finalized;
        self.finalized_height = target_finalized_height;
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

    fn apply_block_to_mmr(&mut self, block_hash: Multihash) {
        use bincode::{
            config,
            serde::{encode_into_std_write, encode_to_vec},
        };

        let entry = &self.entries[&block_hash];
        let mut created = Vec::new();
        let mut consumed = HashMap::<Multihash, (T::ScriptPk, MmrProof)>::new();

        for atom_entry in entry
            .atom
            .atoms
            .iter()
            .map(|h| &self.entries[h])
            .chain(std::iter::once(entry))
            .filter(|e| e.atom.cmd.is_some())
        {
            let atom = &atom_entry.atom;
            let cmd = atom.cmd.as_ref().unwrap();

            for input in &cmd.inputs {
                let Input::OnChain(token, id, proof, _sig) = input else {
                    continue;
                };

                if self.consumed_tokens.contains(id) {
                    continue;
                }

                consumed.insert(*id, (token.script_pk.clone(), proof.clone()));
            }

            let first_input = encode_to_vec(cmd.inputs[0].id(), config::standard()).unwrap();
            created.extend(cmd.outputs.iter().enumerate().map(|(i, t)| {
                let mut buf = first_input.clone();
                encode_into_std_write(i as u32, &mut buf, config::standard()).unwrap();
                (T::HASHER.digest(&buf), (i as u64, t.clone()))
            }));
        }

        consumed.into_iter().for_each(|(id, (pk, proof))| {
            self.mmr.delete(id, &proof);
            self.delete_peer_tokens(&id, &pk);
        });

        created.into_iter().for_each(|(id, (_, token))| {
            let idx = self.mmr.append(id);
            self.add_peer_tokens(id, idx, token);
        });

        let indices = self
            .peer_tokens
            .values_mut()
            .flat_map(|tokens| tokens.values().map(|(idx, _)| *idx))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        self.mmr.commit();
        self.mmr.prune(&indices);
    }

    fn add_peer_tokens(&mut self, token_id: Multihash, idx: u64, token: Token<T>) {
        match self.peer_id {
            Some(peer_id) => {
                if token.script_pk.is_related(peer_id) {
                    self.peer_tokens
                        .entry(peer_id)
                        .or_default()
                        .insert(token_id, (idx, token.clone()));
                }
            }
            None => {
                token
                    .script_pk
                    .related_peers()
                    .into_iter()
                    .for_each(|peer_id| {
                        self.peer_tokens
                            .entry(peer_id)
                            .or_default()
                            .insert(token_id, (idx, token.clone()));
                    });
            }
        }
    }

    fn delete_peer_tokens(&mut self, token_id: &Multihash, script_pk: &T::ScriptPk) {
        match self.peer_id {
            Some(peer_id) => {
                if script_pk.is_related(peer_id) {
                    if let Some(tokens) = self.peer_tokens.get_mut(&peer_id) {
                        tokens.remove(token_id);
                    }
                }
            }
            None => {
                script_pk.related_peers().into_iter().for_each(|peer_id| {
                    if let Some(tokens) = self.peer_tokens.get_mut(&peer_id) {
                        tokens.remove(token_id);
                    }
                });
            }
        }
    }

    fn prune_block(&mut self, block_hash: Multihash) {
        if let Some(entry) = self.entries.remove(&block_hash) {
            for atom_hash in &entry.atom.atoms {
                self.entries.remove(atom_hash);
                self.dismissed.insert(*atom_hash);
            }
            self.dismissed.insert(block_hash);
        }
    }

    fn prune_non_descendants(&mut self, new_finalized: Multihash) {
        let descendants = self.collect_descendants(new_finalized);

        let mut to_keep = HashSet::new();
        for block in &self.finalized_blocks {
            to_keep.insert(*block);
            if let Some(entry) = self.entries.get(block) {
                to_keep.extend(entry.atom.atoms.iter());
            }
        }
        to_keep.extend(descendants);

        let to_remove: Vec<_> = self
            .entries
            .keys()
            .filter(|k| !to_keep.contains(k))
            .copied()
            .collect();

        for hash in to_remove {
            self.entries.remove(&hash);
            self.dismissed.insert(hash);
        }
    }

    fn collect_descendants(&self, root: Multihash) -> HashSet<Multihash> {
        let mut descendants = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(root);
        descendants.insert(root);

        while let Some(current) = queue.pop_front() {
            if let Some(entry) = self.entries.get(&current) {
                for child in &entry.children {
                    if descendants.insert(*child) {
                        queue.push_back(*child);
                    }
                }
            }
        }

        descendants
    }

    fn calculate_difficulty(&self) -> u64 {
        if self.finalized_blocks.len() < 2 {
            return self.difficulty;
        }

        let mut time_diffs = Vec::new();
        let blocks: Vec<_> = self.finalized_blocks.iter().collect();

        for i in 1..blocks.len() {
            let prev_entry = &self.entries[blocks[i - 1]];
            let curr_entry = &self.entries[blocks[i]];
            let time_diff = curr_entry
                .atom
                .timestamp
                .saturating_sub(prev_entry.atom.timestamp);
            if time_diff > 0 {
                time_diffs.push(time_diff);
            }
        }

        if time_diffs.is_empty() {
            return self.difficulty;
        }

        let median = {
            let mid = time_diffs.len() / 2;
            if time_diffs.len() == 1 {
                time_diffs[0] as f64
            } else {
                let (_, m, _) = time_diffs.select_nth_unstable(mid);
                *m as f64
            }
        };

        let target = T::TARGET_BLOCK_TIME_SEC as f64;
        let ratio_raw = target / median;
        let ratio = ratio_raw.clamp(
            1.0 / T::MAX_VDF_DIFFICULTY_ADJUSTMENT,
            T::MAX_VDF_DIFFICULTY_ADJUSTMENT,
        );

        ((self.difficulty as f64 * ratio) as u64).max(1)
    }

    pub fn get(&self, h: &Multihash) -> Option<&Atom<T>> {
        self.entries
            .get(h)
            .and_then(|e| (!e.is_missing).then_some(&e.atom))
    }

    pub fn create_atom(&self, cmd: Option<Command<T>>) -> tokio::task::JoinHandle<Atom<T>> {
        let parent_entry = &self.entries[&self.main_head];

        let height = parent_entry.atom.height + 1;
        let peaks = self.mmr.peak_hashes();

        AtomBuilder::new(self.main_head, height, self.difficulty, peaks)
            .with_command(cmd)
            .with_atoms(self.get_children(self.main_head))
            .build()
    }

    fn get_children(&self, h: Multihash) -> Vec<Multihash> {
        let entry = &self.entries[&h];

        let mut indeg: HashMap<_, usize> = HashMap::from_iter(
            entry
                .children
                .iter()
                .filter(|c| self.contains(c) && !self.entries[*c].is_block)
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

    pub fn current_atoms(&self) -> Vec<Atom<T>> {
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
            finalized: self.finalized,
            finalized_height: self.finalized_height,
            difficulty: self.difficulty,
        }
    }

    pub fn finalized(&self) -> Multihash {
        self.finalized
    }

    pub fn finalized_height(&self) -> Height {
        self.finalized_height
    }

    pub fn fill(&mut self, proofs: HashMap<Multihash, (Token<T>, MmrProof)>) -> bool {
        for (id, (token, proof)) in proofs {
            if !self.mmr.resolve_and_fill(id, &proof) {
                return false;
            }
            self.add_peer_tokens(id, proof.idx, token);
        }

        true
    }

    pub fn tokens(&self, peer_id: &PeerId) -> Option<HashMap<Multihash, Token<T>>> {
        if self.peer_id.is_some_and(|p| &p != peer_id) {
            return None;
        }

        self.peer_tokens
            .get(peer_id)
            .map(|tokens| tokens.iter().map(|(id, (_, token))| (*id, token.clone())))
            .map(HashMap::from_iter)
            .unwrap_or_default()
            .into()
    }

    pub fn tokens_and_proof(
        &self,
        peer_id: &PeerId,
    ) -> Option<HashMap<Multihash, (Token<T>, MmrProof)>> {
        if self.peer_id.is_some_and(|p| p != *peer_id) {
            return None;
        }

        self.peer_tokens
            .get(peer_id)
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|(id, (idx, token))| (*id, (token.clone(), self.mmr.prove(*idx).unwrap())))
            })
            .map(HashMap::from_iter)
            .unwrap_or_default()
            .into()
    }

    pub fn create_command(
        &self,
        peer_id: &PeerId,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) -> Result<Command<T>, Error> {
        if self.peer_id.is_some_and(|p| p != *peer_id) {
            return Err(Error::PeerNotTracked);
        }

        let indices = self.peer_tokens.get(peer_id).ok_or(Error::UnknownTokenId)?;
        let mut inputs = Vec::with_capacity(on_chain_inputs.len() + off_chain_inputs.len());

        for (id, sig) in on_chain_inputs {
            let (idx, token) = indices.get(&id).ok_or(Error::UnknownTokenId)?.clone();
            inputs.push(Input::OnChain(token, id, self.mmr.prove(idx).unwrap(), sig));
        }

        for input in off_chain_inputs {
            inputs.push(Input::OffChain(input));
        }

        Ok(Command::new(code, inputs, outputs))
    }
}
