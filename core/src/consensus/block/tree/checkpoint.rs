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

enum ValidatedType {
    BlockInProposalDag((Multihash, Multihash)),
    BlockInBlockDag(Multihash),
    Proposal(Multihash),
}

enum ValidationType {
    Validated(ValidatedType),
    Invalidated(Multihash),
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct UpdateResult<H, T: Record> {
    pub validated: Vec<Multihash>,
    pub invalidated: Vec<Multihash>,
    pub phantoms: Vec<Multihash>,
    pub new_checkpoint: Option<BlockNode<H, T>>,
}

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
    pub root_hash: Multihash,
    pub root_total_weight: T::Weight,
}

pub struct Checkpoint<H: Hasher, T: Record> {
    block_dag: Dag<BlockNode<H, T>>,
    proposal_dags: HashMap<Multihash, Dag<UnifiedNode<H, T>>>,
    pending_blocks: HashMap<Multihash, Multihash>,
    invalid_hashes: HashSet<Multihash>,
    mode: Arc<Mode>,
    tip_hash: Multihash,
    root_hash: Multihash,
    root_total_weight: T::Weight,
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

impl<H: Hasher, T: Record> Checkpoint<H, T> {
    pub fn new(root: BlockNode<H, T>, mode: Arc<Mode>) -> Self {
        let hash = root.id();
        let total_weight = root.trie.read().weight();

        let mut block_dag = Dag::new();
        block_dag.upsert(root.clone(), std::iter::empty());

        let mut proposal_dag = Dag::new();
        let node = UnifiedNode::Block(root);
        proposal_dag.upsert(node, std::iter::empty());

        let proposal_dags = HashMap::from([(hash, proposal_dag)]);

        let tip_hash = hash;
        let root_hash = hash;
        let root_total_weight = total_weight;

        Self {
            block_dag,
            proposal_dags,
            mode,
            tip_hash,
            root_hash,
            root_total_weight,
            pending_blocks: Default::default(),
            invalid_hashes: Default::default(),
        }
    }

    pub fn new_empty(mode: Arc<Mode>) -> Self {
        Self {
            mode,
            block_dag: Default::default(),
            proposal_dags: Default::default(),
            pending_blocks: Default::default(),
            invalid_hashes: Default::default(),
            tip_hash: Default::default(),
            root_hash: Default::default(),
            root_total_weight: Default::default(),
        }
    }

    pub fn from_summary(summary: Summary<T>, mode: Arc<Mode>) -> Option<Self> {
        let Some(block_node) = summary.block_node else {
            return Some(Self::new_empty(mode));
        };

        let block_node = BlockNode::from_serialized(block_node, mode.clone())?;

        let tip_hash = block_node.id();

        let mut block_dag = Dag::new();
        block_dag.upsert(block_node, std::iter::empty());

        Some(Self {
            block_dag,
            tip_hash,
            root_hash: summary.root_hash,
            root_total_weight: summary.root_total_weight,
            mode,
            proposal_dags: Default::default(),
            pending_blocks: Default::default(),
            invalid_hashes: Default::default(),
        })
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

        if self.invalid_hashes.contains(&hash) || self.invalid_hashes.contains(&block.parent) {
            self.invalid_hashes.insert(hash);
            result.add_invalidated(hash);
            return result;
        }

        if self.block_dag.contains(&hash) {
            return result;
        }

        self.pending_blocks.insert(hash, block.parent);

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
        let parents = self.generate_block_parents(&block, result);
        let entry = self.proposal_dags.entry(block.parent).or_default();
        let n = UnifiedNode::new_block(block, witness, self.mode.clone());
        entry.upsert(n, parents)
    }

    fn generate_block_parents(
        &mut self,
        block: &Block,
        result: &mut UpdateResult<H, T>,
    ) -> Vec<Multihash> {
        let mut parents = Vec::with_capacity(block.proposals.len());
        let dag = self.proposal_dags.entry(block.parent).or_default();

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
        let mut stk = vec![];
        stk.extend(result.validated.into_iter().map(|n| {
            let t = if let Some(parent) = self.pending_blocks.remove(&n) {
                ValidatedType::BlockInProposalDag((parent, n))
            } else {
                ValidatedType::Proposal(n)
            };

            ValidationType::Validated(t)
        }));

        stk.extend(
            result
                .invalidated
                .into_iter()
                .map(ValidationType::Invalidated),
        );

        while let Some(v) = stk.pop() {
            match v {
                ValidationType::Validated(validated) => {
                    self.process_validated(validated, update_result, &mut stk);
                }
                ValidationType::Invalidated(hash) => {
                    self.proposal_dags.remove(&hash);
                    self.pending_blocks.remove(&hash);
                    self.invalid_hashes.insert(hash);
                    update_result.add_invalidated(hash);
                }
            }
        }
    }

    fn process_validated(
        &mut self,
        validated: ValidatedType,
        result: &mut UpdateResult<H, T>,
        stk: &mut Vec<ValidationType>,
    ) {
        match validated {
            ValidatedType::BlockInProposalDag((parent, hash)) => {
                self.process_validated_block_in_proposal_dag(parent, hash, stk);
            }
            ValidatedType::BlockInBlockDag(hash) => {
                result.add_validated(hash);
                self.process_validated_block_in_block_dag(hash, result);
            }
            ValidatedType::Proposal(hash) => {
                result.add_validated(hash);
            }
        }
    }

    fn process_validated_block_in_proposal_dag(
        &mut self,
        parent: Multihash,
        hash: Multihash,
        stk: &mut Vec<ValidationType>,
    ) {
        let unified_node = self
            .proposal_dags
            .get_mut(&parent)
            .expect("Parent should exist")
            .remove(&hash)
            .expect("Node should exist");

        let block_node = unified_node
            .as_block()
            .expect("Node should be a block")
            .clone();

        let r = if self.tip_hash == Multihash::default() {
            self.block_dag.upsert(block_node, std::iter::empty())
        } else {
            self.block_dag.upsert(block_node, std::iter::once(parent))
        };

        stk.extend(
            r.validated
                .into_iter()
                .map(|n| ValidationType::Validated(ValidatedType::BlockInBlockDag(n))),
        );
        stk.extend(r.invalidated.into_iter().map(ValidationType::Invalidated));
    }

    fn process_validated_block_in_block_dag(
        &mut self,
        hash: Multihash,
        result: &mut UpdateResult<H, T>,
    ) {
        use std::sync::atomic::Ordering::Relaxed;

        let node = self
            .block_dag
            .get(&hash)
            .expect("Node should exist in the DAG");

        if self.tip_hash == Multihash::default() {
            self.tip_hash = hash;
            self.root_hash = hash;
            self.root_total_weight = node.trie.read().weight();
            return;
        }

        if !self.block_dag.contains(&hash) {
            return;
        }

        let (block_weight, block_cumulative_weight, block_height) = {
            let weight = *node.weight.read();
            let cumulative_weight = *node.cumulative_weight.read();
            (weight, cumulative_weight, node.height.load(Relaxed))
        };

        let (tip_cumulative_weight, tip_height) = {
            let node = self
                .block_dag
                .get(&self.tip_hash)
                .expect("Tip node should exist");
            (*node.cumulative_weight.read(), node.height.load(Relaxed))
        };

        let threshold = self.total_weight().mul_f64(0.67);

        let parent = node.block.parent;

        if block_weight > threshold {
            self.block_dag.retain(&parent).iter().for_each(|n| {
                self.proposal_dags.remove(&n.id());
            });
            let block_node = self.block_dag.remove(&hash).expect("Node should exist");
            result.new_checkpoint = Some(block_node);
        } else {
            let b = (block_cumulative_weight, block_height);
            let t = (tip_cumulative_weight, tip_height);
            if b > t {
                self.tip_hash = hash;
            }
        }
    }

    fn total_weight(&self) -> T::Weight {
        self.block_dag
            .get(&self.root_hash)
            .expect("Tip node should exist")
            .trie
            .read()
            .weight()
    }

    pub fn update_proposal(
        &mut self,
        proposal: Proposal<T>,
        witness: proposal::Witness,
    ) -> UpdateResult<H, T> {
        let hash = proposal.hash::<H>();

        let mut result = UpdateResult::new();

        if self.invalid_hashes.contains(&hash) || self.invalid_hashes.contains(&proposal.parent) {
            self.invalid_hashes.insert(hash);
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
        let parents = self.generate_proposal_parents(&proposal, result);
        let entry = self.proposal_dags.entry(proposal.parent).or_default();
        let node = UnifiedNode::new_proposal(proposal, witness);
        entry.upsert(node, parents)
    }

    fn generate_proposal_parents(
        &mut self,
        proposal: &Proposal<T>,
        result: &mut UpdateResult<H, T>,
    ) -> Vec<Multihash> {
        let mut parents = Vec::with_capacity(1 + proposal.dependencies.len());
        let dag = self.proposal_dags.entry(proposal.parent).or_default();

        if self.tip_hash != Multihash::default() {
            parents.push(proposal.parent);
        }

        proposal.dependencies.iter().for_each(|dep| {
            if !dag.contains(dep) {
                result.add_phantom(*dep);
            }
            parents.push(*dep);
        });

        parents
    }

    pub fn tip_node(&self) -> &BlockNode<H, T> {
        self.block_dag
            .get(&self.tip_hash)
            .expect("Tip node should exist")
    }

    pub fn tip_hash(&self) -> Multihash {
        self.tip_hash
    }

    pub fn tip_trie(&self) -> Trie<H, T> {
        if self.block_dag.is_empty() {
            return Trie::default();
        }
        self.tip_node().trie.read().clone()
    }

    pub fn get_proposal_dag(&self, parent: Multihash) -> Option<&Dag<UnifiedNode<H, T>>> {
        self.proposal_dags.get(&parent)
    }

    pub fn parent_trie(&self, parent: &Multihash) -> Option<Trie<H, T>> {
        if self.block_dag.is_empty() {
            return Some(Trie::default());
        }

        self.block_dag
            .get(parent)
            .map(|node| node.trie.read().clone())
    }

    pub fn root_hash(&self) -> Multihash {
        self.root_hash
    }

    pub fn into_blocks(mut self) -> Vec<EstablishedBlock<T>> {
        assert!(self.mode.is_archive());

        if self.block_dag.is_empty() {
            return Vec::new();
        }

        let mut blocks = Vec::new();
        let mut visited = HashSet::new();

        let mut queue = VecDeque::new();
        queue.push_back(self.root_hash);

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            visited.insert(hash);

            let cur_node = self
                .block_dag
                .soft_remove(&hash)
                .expect("Node should exist in the DAG");

            let mut proposals = Vec::with_capacity(cur_node.block.proposals.len());

            if !cur_node.block.proposals.is_empty() {
                let mut dag = self
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

            if let Some(children) = self.block_dag.get_children(&hash) {
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

        if self.block_dag.is_empty() {
            return Vec::new();
        }

        let mut blocks = Vec::new();
        let mut visited = HashSet::new();

        let mut queue = VecDeque::new();
        queue.push_back(self.root_hash);

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            let cur_node = self
                .block_dag
                .get(&hash)
                .expect("Node should exist in the DAG");

            let mut proposals = Vec::with_capacity(cur_node.block.proposals.len());

            if !cur_node.block.proposals.is_empty() {
                let dag = self
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

            if let Some(children) = self.block_dag.get_children(&hash) {
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

        let root_hash = self.root_hash;
        let root_total_weight = self.root_total_weight;

        Summary {
            block_node: Some(block_node),
            root_hash,
            root_total_weight,
        }
    }
}
