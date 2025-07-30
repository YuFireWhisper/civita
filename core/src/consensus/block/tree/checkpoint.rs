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
    utils::trie::Trie,
};

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct UpdateResult<H> {
    pub validated: Vec<Multihash>,
    pub invalidated: Vec<Multihash>,
    pub phantoms: Vec<Multihash>,
    pub new_checkpoint: Option<BlockNode<H>>,
}

#[derive(Clone)]
#[derive(Serialize)]
pub struct EstablishedBlock {
    pub block: Block,
    pub witness: block::Witness,
    pub proposals: Vec<(Proposal, proposal::Witness)>,
}

#[derive(Clone)]
#[derive(Serialize)]
pub struct Summary {
    pub block_node: SerializedBlockNode,
    pub root_hash: Multihash,
    pub root_total_weight: u64,
}

pub struct Checkpoint<H: Hasher> {
    block_dag: Dag<BlockNode<H>>,
    proposal_dags: HashMap<Multihash, Dag<UnifiedNode<H>>>,
    pending_blocks: HashMap<Multihash, Multihash>,
    invalid_hashes: HashSet<Multihash>,
    mode: Arc<Mode>,
    tip_hash: Multihash,
    root_hash: Multihash,
    root_total_weight: u64,
}

impl<H> UpdateResult<H> {
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

impl<H: Hasher> Checkpoint<H> {
    pub fn new_empty(root: BlockNode<H>, mode: Arc<Mode>) -> Self {
        use std::sync::atomic::Ordering::Relaxed;

        let tip_hash = root.id();
        let root_hash = tip_hash;
        let root_total_weight = root.weight.load(Relaxed);
        let block_dag = Dag::with_root(root);

        Self {
            block_dag,
            proposal_dags: HashMap::new(),
            pending_blocks: HashMap::new(),
            invalid_hashes: HashSet::new(),
            tip_hash,
            root_hash,
            root_total_weight,
            mode,
        }
    }

    pub fn from_summary(summary: Summary, mode: Arc<Mode>) -> Option<Self> {
        let block_node = BlockNode::from_serialized(summary.block_node, mode.clone())?;

        let tip_hash = block_node.id();

        let mut block_dag = Dag::new();
        block_dag.upsert(block_node, std::iter::empty());

        Some(Self {
            block_dag,
            proposal_dags: HashMap::new(),
            pending_blocks: HashMap::new(),
            invalid_hashes: HashSet::new(),
            tip_hash,
            root_hash: summary.root_hash,
            root_total_weight: summary.root_total_weight,
            mode,
        })
    }

    pub fn from_blocks(mut blocks: Vec<EstablishedBlock>) -> Option<Self> {
        let mode = Arc::new(Mode::Archive);

        let root_block = blocks.pop()?;
        let root_node = BlockNode::new(root_block.block, root_block.witness, mode.clone());

        let mut checkpoint = Self::new_empty(root_node, mode);

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

    pub fn update_block(&mut self, block: Block, witness: block::Witness) -> UpdateResult<H> {
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
        result: &mut UpdateResult<H>,
    ) -> ValidationResult<UnifiedNode<H>> {
        let parents = self.generate_block_parents(&block, result);
        let entry = self.proposal_dags.entry(block.parent).or_default();
        let n = UnifiedNode::new_block(block, witness, self.mode.clone());
        entry.upsert(n, parents)
    }

    fn generate_block_parents(
        &mut self,
        block: &Block,
        result: &mut UpdateResult<H>,
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
        result: ValidationResult<UnifiedNode<H>>,
        update_result: &mut UpdateResult<H>,
    ) {
        use std::sync::atomic::Ordering::Relaxed;

        result.validated.into_iter().for_each(|hash| {
            if let Some(parent) = self.pending_blocks.remove(&hash) {
                let node = self
                    .proposal_dags
                    .get_mut(&parent)
                    .expect("Parent should exist")
                    .remove(&hash)
                    .expect("Node should exist")
                    .into_block();

                self.block_dag.upsert(node, std::iter::once(parent));

                let (block_weight, block_cumulative_weight, block_height) = {
                    let node = self.block_dag.get(&hash).expect("Node should exist");
                    (
                        node.weight.load(Relaxed),
                        node.cumulative_weight.load(Relaxed),
                        node.height.load(Relaxed),
                    )
                };

                let (tip_cumulative_weight, tip_height) = {
                    let node = self
                        .block_dag
                        .get(&self.tip_hash)
                        .expect("Tip node should exist");
                    (
                        node.cumulative_weight.load(Relaxed),
                        node.height.load(Relaxed),
                    )
                };

                let threshold = (self.total_weight() as f64) * 0.67;
                if block_weight as f64 > threshold {
                    let removed = self.block_dag.retain(&parent);
                    removed.iter().for_each(|n| {
                        self.proposal_dags.remove(&n.id());
                    });
                    let block_node = self.block_dag.get(&hash).unwrap().clone();
                    update_result.new_checkpoint = Some(block_node);
                } else {
                    let b = (block_cumulative_weight, block_height);
                    let t = (tip_cumulative_weight, tip_height);
                    if b > t {
                        self.tip_hash = hash;
                    }
                }
            }

            update_result.add_validated(hash);
        });

        result.invalidated.into_iter().for_each(|hash| {
            self.proposal_dags.remove(&hash);
            self.pending_blocks.remove(&hash);
            self.invalid_hashes.insert(hash);
            update_result.add_invalidated(hash);
        });
    }

    fn total_weight(&self) -> u64 {
        self.block_dag
            .get(&self.root_hash)
            .expect("Tip node should exist")
            .trie
            .read()
            .weight()
    }

    pub fn update_proposal(
        &mut self,
        proposal: Proposal,
        witness: proposal::Witness,
    ) -> UpdateResult<H> {
        let hash = proposal.hash::<H>();

        let mut result = UpdateResult::new();

        if self.invalid_hashes.contains(&hash) || self.invalid_hashes.contains(&proposal.parent) {
            self.invalid_hashes.insert(hash);
            result.add_invalidated(hash);
            return result;
        }

        let dag_result = self.upsert_proposal_to_proposal_dag(proposal, witness);
        self.process_validation_result(dag_result, &mut result);

        result
    }

    fn upsert_proposal_to_proposal_dag(
        &mut self,
        proposal: Proposal,
        witness: proposal::Witness,
    ) -> ValidationResult<UnifiedNode<H>> {
        let parents = proposal.dependencies.iter().cloned().collect::<Vec<_>>();
        let entry = self.proposal_dags.entry(proposal.parent).or_default();
        let node = UnifiedNode::new_proposal(proposal, witness);
        entry.upsert(node, parents)
    }

    pub fn tip_node(&self) -> &BlockNode<H> {
        self.block_dag
            .get(&self.tip_hash)
            .expect("Tip node should exist")
    }

    pub fn tip_hash(&self) -> Multihash {
        self.tip_hash
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.tip_node().trie.read().clone()
    }

    pub fn get_proposal_dag(&self, parent: Multihash) -> Option<&Dag<UnifiedNode<H>>> {
        self.proposal_dags.get(&parent)
    }

    pub fn parent_trie(&self, parent: &Multihash) -> Option<Trie<H>> {
        self.block_dag
            .get(parent)
            .map(|node| node.trie.read().clone())
    }

    pub fn root_hash(&self) -> Multihash {
        self.root_hash
    }

    pub fn into_blocks(mut self) -> Vec<EstablishedBlock> {
        assert!(self.mode.is_archive());

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

    pub fn to_blocks(&self) -> Vec<EstablishedBlock> {
        assert!(self.mode.is_archive());

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

    pub fn summary<'a, I, T>(&self, keys: I) -> Summary
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]> + 'a,
    {
        assert!(self.mode.is_archive());

        let block_node = self
            .tip_node()
            .to_serialized(keys)
            .expect("Serialization should succeed");

        let root_hash = self.root_hash;
        let root_total_weight = self.root_total_weight;

        Summary {
            block_node,
            root_hash,
            root_total_weight,
        }
    }
}
