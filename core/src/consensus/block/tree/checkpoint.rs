use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::{
    consensus::{
        block::{
            self,
            tree::{
                dag::{Dag, ValidationResult},
                node::{BlockNode, SerializedBlockNode, UnifiedNode},
                Mode,
            },
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    utils::{trie::Trie, Record, Weight},
};

#[derive(Clone)]
#[derive(Serialize)]
pub struct EstablishedBlock<T: Record> {
    pub block: Block,
    pub witness: block::Witness,
    pub proposals: Vec<(Proposal<T>, proposal::Witness)>,
}

#[derive(Clone)]
#[derive(Serialize)]
pub struct Summary<T: Record> {
    pub block_node: Option<SerializedBlockNode<T>>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct UpdateResult<H, T: Record> {
    pub validated: Vec<Multihash>,
    pub invalidated: Vec<Multihash>,
    pub phantoms: Vec<Multihash>,
    pub new_checkpoint: Option<BlockNode<H, T>>,
}

enum ValidationEvent {
    BlockValidated { parent: Multihash, hash: Multihash },
    BlockInDagValidated { hash: Multihash },
    ProposalValidated { hash: Multihash },
    InvalidatedHash { hash: Multihash },
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct State<H: Hasher, T: Record> {
    block_dag: Dag<BlockNode<H, T>>,
    proposal_dags: HashMap<Multihash, Dag<UnifiedNode<H, T>>>,
    pending_blocks: HashMap<Multihash, Multihash>, // hash -> parent
    invalid_hashes: HashSet<Multihash>,
    tip_hash: Multihash,
    root_hash: Multihash,
}

pub struct Checkpoint<H: Hasher, T: Record> {
    state: State<H, T>,
    mode: Arc<Mode>,
}

impl<H, T: Record> UpdateResult<H, T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_validated(&mut self, hash: Multihash) {
        self.validated.push(hash);
    }

    pub fn add_invalidated(&mut self, hash: Multihash) {
        self.invalidated.push(hash);
    }

    pub fn add_phantom(&mut self, hash: Multihash) {
        self.phantoms.push(hash);
    }
}

impl ValidationEvent {
    pub fn new_block_validated(parent: Multihash, hash: Multihash) -> Self {
        ValidationEvent::BlockValidated { parent, hash }
    }

    pub fn new_block_in_dag_validated(hash: Multihash) -> Self {
        ValidationEvent::BlockInDagValidated { hash }
    }

    pub fn new_proposal_validated(hash: Multihash) -> Self {
        ValidationEvent::ProposalValidated { hash }
    }

    pub fn new_invalidated_hash(hash: Multihash) -> Self {
        ValidationEvent::InvalidatedHash { hash }
    }
}

impl<H: Hasher, T: Record> State<H, T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(root: BlockNode<H, T>) -> Self {
        let tip_hash = root.id();

        let mut block_dag = Dag::new();
        block_dag.upsert(root.clone(), std::iter::empty());

        let mut proposal_dags = HashMap::new();
        let node = UnifiedNode::Block(root);
        proposal_dags.insert(tip_hash, Dag::new());
        proposal_dags
            .get_mut(&tip_hash)
            .unwrap()
            .upsert(node, std::iter::empty());

        Self {
            block_dag,
            proposal_dags,
            tip_hash,
            root_hash: tip_hash,
            pending_blocks: Default::default(),
            invalid_hashes: Default::default(),
        }
    }

    pub fn is_block_invalided(&self, block: &Block) -> bool {
        self.invalid_hashes.contains(&block.hash::<H>())
            || self.invalid_hashes.contains(&block.parent)
    }

    pub fn is_proposal_invalided(&self, proposal: &Proposal<T>) -> bool {
        self.invalid_hashes.contains(&proposal.hash::<H>())
            || self.invalid_hashes.contains(&proposal.parent)
    }

    pub fn is_block_existed(&self, hash: &Multihash) -> bool {
        self.block_dag.contains(hash)
    }
}

impl<H: Hasher, T: Record> Checkpoint<H, T> {
    pub fn new(tip: BlockNode<H, T>, mode: Arc<Mode>) -> Self {
        Self {
            state: State::with_root(tip),
            mode,
        }
    }

    pub fn new_empty(mode: Arc<Mode>) -> Self {
        Self {
            state: State::new(),
            mode,
        }
    }

    pub fn from_summary(summary: Summary<T>, mode: Arc<Mode>) -> Option<Self> {
        if mode.is_archive() {
            return None;
        }

        let block_node = summary.block_node?;
        let tip = BlockNode::from_serialized(block_node, mode.clone())?;

        Some(Self::new(tip, mode))
    }

    pub fn from_blocks(blocks: Vec<EstablishedBlock<T>>) -> Option<Self> {
        let mut checkpoint = Self::new_empty(Arc::new(Mode::Archive));

        let valid = blocks.into_iter().all(|block| {
            let valid = block
                .proposals
                .into_iter()
                .all(|(p, w)| checkpoint.update_proposal(p, w).invalidated.is_empty());

            if !valid {
                return false;
            }

            let hash = block.block.hash::<H>();
            let res = checkpoint.update_block(block.block, block.witness);

            if !res.invalidated.is_empty() || !res.validated.contains(&hash) {
                return false;
            }

            true
        });

        if !valid {
            return None;
        }

        Some(checkpoint)
    }

    pub fn update_block(&mut self, block: Block, witness: block::Witness) -> UpdateResult<H, T> {
        let hash = block.hash::<H>();
        let mut result = UpdateResult::new();

        if self.state.is_block_invalided(&block) {
            self.state.invalid_hashes.insert(hash);
            result.add_invalidated(hash);
            return result;
        }

        if self.state.is_block_existed(&hash) {
            return result;
        }

        self.state.pending_blocks.insert(hash, block.parent);

        let dag_result = self.upsert_block_to_proposal_dag(block, witness, &mut result);

        self.process_validation_result(dag_result, &mut result);

        result
    }

    fn upsert_block_to_proposal_dag(
        &mut self,
        block: Block,
        witness: block::Witness,
        result: &mut UpdateResult<H, T>,
    ) -> ValidationResult<UnifiedNode<H, T>> {
        let parents = self.collect_block_parents(&block, result);
        let entry = self.state.proposal_dags.entry(block.parent).or_default();
        let n = UnifiedNode::new_block(block, witness, self.mode.clone());
        entry.upsert(n, parents)
    }

    fn collect_block_parents(
        &mut self,
        block: &Block,
        result: &mut UpdateResult<H, T>,
    ) -> Vec<Multihash> {
        let mut parents = Vec::with_capacity(block.proposals.len());
        let dag = self.state.proposal_dags.entry(block.parent).or_default();

        block.proposals.iter().for_each(|p| {
            if !dag.contains(p) {
                result.add_phantom(*p);
            }
            parents.push(*p);
        });

        parents
    }

    fn process_validation_result(
        &mut self,
        result: ValidationResult<UnifiedNode<H, T>>,
        update_result: &mut UpdateResult<H, T>,
    ) {
        let events = self.convert_dag_result_to_events(result);
        self.process_events(events, update_result);
    }

    fn convert_dag_result_to_events(
        &self,
        result: ValidationResult<UnifiedNode<H, T>>,
    ) -> VecDeque<ValidationEvent> {
        result
            .validated
            .iter()
            .copied()
            .map(|n| {
                if let Some(parent) = self.state.pending_blocks.get(&n) {
                    ValidationEvent::new_block_validated(*parent, n)
                } else {
                    ValidationEvent::new_proposal_validated(n)
                }
            })
            .chain(
                result
                    .invalidated
                    .into_iter()
                    .map(ValidationEvent::new_invalidated_hash),
            )
            .collect()
    }

    fn process_events(
        &mut self,
        mut events: VecDeque<ValidationEvent>,
        result: &mut UpdateResult<H, T>,
    ) {
        while let Some(event) = events.pop_front() {
            match event {
                ValidationEvent::BlockValidated { parent, hash } => {
                    events.extend(self.handle_block_validated(parent, hash));
                }
                ValidationEvent::BlockInDagValidated { hash } => {
                    self.handle_block_in_dag_validated(hash, result);
                }
                ValidationEvent::ProposalValidated { hash } => {
                    result.add_validated(hash);
                }
                ValidationEvent::InvalidatedHash { hash } => {
                    self.handle_invalidated_hash(hash, result);
                }
            }
        }
    }

    fn handle_block_validated(
        &mut self,
        parent: Multihash,
        hash: Multihash,
    ) -> impl Iterator<Item = ValidationEvent> {
        let unified_node = self
            .state
            .proposal_dags
            .get_mut(&parent)
            .expect("Parent should exist")
            .remove(&hash)
            .expect("Node should exist");

        let block_node = unified_node
            .as_block()
            .expect("Node should be a block")
            .clone();

        let parents = if self.state.tip_hash == Multihash::default() {
            Vec::new()
        } else {
            vec![parent]
        };

        let dag_result = self.state.block_dag.upsert(block_node, parents);

        dag_result
            .validated
            .into_iter()
            .map(ValidationEvent::new_block_in_dag_validated)
            .chain(
                dag_result
                    .invalidated
                    .into_iter()
                    .map(ValidationEvent::new_invalidated_hash),
            )
    }

    fn handle_block_in_dag_validated(&mut self, hash: Multihash, result: &mut UpdateResult<H, T>) {
        use std::sync::atomic::Ordering::Relaxed;

        if self.state.tip_hash == Multihash::default() {
            // First block in the DAG
            self.state.tip_hash = hash;
            return;
        }

        let node = match self.state.block_dag.get(&hash) {
            Some(node) => node,
            None => return,
        };

        let block_metrics = {
            let weight = *node.weight.read();
            let cumulative_weight = *node.cumulative_weight.read();
            let height = node.height.load(Relaxed);
            (weight, cumulative_weight, height)
        };

        let tip_metrics = {
            let n = self.tip_node();
            (*n.cumulative_weight.read(), n.height.load(Relaxed))
        };

        self.update_tip_if_needed(hash, block_metrics, tip_metrics, result);
    }

    fn update_tip_if_needed(
        &mut self,
        hash: Multihash,
        block_metrics: (T::Weight, T::Weight, u64),
        tip_metrics: (T::Weight, u64),
        result: &mut UpdateResult<H, T>,
    ) {
        let (block_weight, block_cumulative_weight, block_height) = block_metrics;
        let (tip_cumulative_weight, tip_height) = tip_metrics;

        let threshold = self.calculate_weight_threshold();

        if block_weight > threshold {
            self.create_new_checkpoint(hash, result);
            return;
        }

        if (block_cumulative_weight, block_height) > (tip_cumulative_weight, tip_height) {
            self.state.tip_hash = hash;
        }
    }

    fn calculate_weight_threshold(&self) -> T::Weight {
        let total_weight = self
            .state
            .block_dag
            .get(&self.state.tip_hash)
            .expect("Tip node should exist")
            .trie
            .read()
            .weight();
        total_weight.mul_f64(0.67)
    }

    fn create_new_checkpoint(&mut self, hash: Multihash, result: &mut UpdateResult<H, T>) {
        let node = self.state.block_dag.get(&hash).expect("Node should exist");
        let parent = node.block.parent;

        self.state.block_dag.retain(&parent).iter().for_each(|n| {
            self.state.proposal_dags.remove(&n.id());
        });

        let block_node = self
            .state
            .block_dag
            .remove(&hash)
            .expect("Node should exist");

        result.new_checkpoint = Some(block_node);
    }

    fn handle_invalidated_hash(&mut self, hash: Multihash, result: &mut UpdateResult<H, T>) {
        self.state.proposal_dags.remove(&hash);
        self.state.pending_blocks.remove(&hash);
        self.state.invalid_hashes.insert(hash);
        result.add_invalidated(hash);
    }

    pub fn update_proposal(
        &mut self,
        proposal: Proposal<T>,
        witness: proposal::Witness,
    ) -> UpdateResult<H, T> {
        let hash = proposal.hash::<H>();
        let mut result = UpdateResult::new();

        if self.state.is_proposal_invalided(&proposal) {
            self.state.invalid_hashes.insert(hash);
            result.add_invalidated(hash);
            return result;
        }

        let dag_result = self.upsert_proposal_to_proposal_dag(proposal, witness, &mut result);
        self.process_validation_result(dag_result, &mut result);

        result
    }

    fn upsert_proposal_to_proposal_dag(
        &mut self,
        proposal: Proposal<T>,
        witness: proposal::Witness,
        result: &mut UpdateResult<H, T>,
    ) -> ValidationResult<UnifiedNode<H, T>> {
        let parents = self.collect_proposal_parents(&proposal, result);
        let entry = self.state.proposal_dags.entry(proposal.parent).or_default();
        let node = UnifiedNode::new_proposal(proposal, witness);
        entry.upsert(node, parents)
    }

    fn collect_proposal_parents(
        &mut self,
        proposal: &Proposal<T>,
        result: &mut UpdateResult<H, T>,
    ) -> impl IntoIterator<Item = Multihash> {
        let dag = self.state.proposal_dags.entry(proposal.parent).or_default();

        proposal
            .dependencies
            .iter()
            .inspect(|&dep| {
                if !dag.contains(dep) {
                    result.add_phantom(*dep);
                }
            })
            .chain((self.state.tip_hash != Multihash::default()).then_some(&proposal.parent))
            .copied()
            .collect::<Vec<_>>()
    }

    fn tip_node(&self) -> &BlockNode<H, T> {
        self.state
            .block_dag
            .get(&self.state.tip_hash)
            .expect("Tip node should exist")
    }

    pub fn tip_hash(&self) -> Multihash {
        self.state.tip_hash
    }

    pub fn tip_trie(&self) -> Trie<H, T> {
        if !self.state.block_dag.is_empty() {
            self.tip_node().trie_clone()
        } else {
            Default::default()
        }
    }

    pub fn get_proposal_dag(&self, hash: Multihash) -> Option<&Dag<UnifiedNode<H, T>>> {
        self.state.proposal_dags.get(&hash)
    }

    pub fn parent_trie(&self, parent: &Multihash) -> Option<Trie<H, T>> {
        (!self.state.block_dag.is_empty())
            .then_some(
                self.state
                    .block_dag
                    .get(parent)
                    .map(|node| node.trie_clone()),
            )
            .flatten()
    }

    pub fn into_blocks(mut self) -> Vec<EstablishedBlock<T>> {
        assert!(self.mode.is_archive());

        if self.state.block_dag.is_empty() {
            return Vec::new();
        }

        let mut blocks = Vec::new();
        let mut visited = HashSet::new();

        let mut queue = VecDeque::new();
        queue.push_back(self.state.root_hash);

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            visited.insert(hash);

            let cur_node = self
                .state
                .block_dag
                .soft_remove(&hash)
                .expect("Node should exist in the DAG");

            let mut proposals = Vec::with_capacity(cur_node.block.proposals.len());

            if !cur_node.block.proposals.is_empty() {
                let mut dag = self
                    .state
                    .proposal_dags
                    .remove(&cur_node.block.parent)
                    .expect("Proposal DAG should exist");

                cur_node.block.proposals.iter().for_each(|p| {
                    let pn = dag
                        .soft_remove(p)
                        .expect("Proposal node should exist")
                        .into_proposal();
                    proposals.push((pn.proposal, pn.witness));
                });
            }

            let block = EstablishedBlock {
                block: cur_node.block,
                witness: cur_node.witness,
                proposals,
            };

            blocks.push(block);

            if let Some(children) = self.state.block_dag.get_children(&hash) {
                children.iter().for_each(|&child| {
                    if !visited.contains(&child) {
                        queue.push_back(child);
                    }
                });
            }
        }

        blocks
    }

    pub fn to_blocks(&self) -> Vec<EstablishedBlock<T>> {
        assert!(self.mode.is_archive());

        if self.state.block_dag.is_empty() {
            return Vec::new();
        }

        let mut blocks = Vec::new();
        let mut visited = HashSet::new();

        let mut queue = VecDeque::new();
        queue.push_back(self.state.root_hash);

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            let cur_node = self
                .state
                .block_dag
                .get(&hash)
                .expect("Node should exist in the DAG");

            let mut proposals = Vec::with_capacity(cur_node.block.proposals.len());

            if !cur_node.block.proposals.is_empty() {
                let dag = self
                    .state
                    .proposal_dags
                    .get(&cur_node.block.parent)
                    .expect("Proposal DAG should exist");

                cur_node.block.proposals.iter().for_each(|p| {
                    let pn = dag
                        .get(p)
                        .expect("Proposal node should exist")
                        .as_proposal()
                        .expect("Node should be a proposal")
                        .clone();
                    proposals.push((pn.proposal, pn.witness));
                });
            }

            let block = EstablishedBlock {
                block: cur_node.block.clone(),
                witness: cur_node.witness.clone(),
                proposals,
            };

            blocks.push(block);

            if let Some(children) = self.state.block_dag.get_children(&hash) {
                children.iter().for_each(|&child| {
                    if !visited.contains(&child) {
                        queue.push_back(child);
                        visited.insert(child);
                    }
                });
            }
        }

        blocks
    }

    pub fn summary<'a, I, K>(&self, keys: I) -> Summary<T>
    where
        I: IntoIterator<Item = K>,
        K: AsRef<[u8]> + 'a,
    {
        assert!(self.mode.is_archive());

        let block_node = self
            .tip_node()
            .to_serialized(keys)
            .expect("Serialization should succeed");

        Summary {
            block_node: Some(block_node),
        }
    }

    pub fn root_hash(&self) -> Multihash {
        self.state.root_hash
    }
}
