use std::{
    collections::{HashMap, HashSet},
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
                node::{BlockNode, UnifiedNode},
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

#[derive(Serialize)]
pub struct EstablishedBlock {
    pub block: Block,
    pub witness: block::Witness,
    pub proposals: HashMap<Multihash, (Proposal, proposal::Witness)>,
}

#[derive(Serialize)]
pub struct EstablishedCheckpoint {
    pub root_hash: Multihash,
    blocks: HashMap<Multihash, EstablishedBlock>,
}

pub struct Checkpoint<H: Hasher> {
    block_dag: Dag<BlockNode<H>>,
    proposal_dags: HashMap<Multihash, Dag<UnifiedNode<H>>>,
    pending_blocks: HashMap<Multihash, Multihash>,
    invalid_hashes: HashSet<Multihash>,
    mode: Arc<Mode>,
    tip: Multihash,
    root_hash: Multihash,
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
    pub fn new(root: BlockNode<H>, mode: Arc<Mode>) -> Self {
        let tip = root.id();
        let block_dag = Dag::with_root(root);

        Self {
            block_dag,
            proposal_dags: HashMap::new(),
            pending_blocks: HashMap::new(),
            invalid_hashes: HashSet::new(),
            mode,
            root_hash: tip,
            tip,
        }
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
                let n = self
                    .proposal_dags
                    .get_mut(&parent)
                    .expect("Parent should exist")
                    .remove(&hash)
                    .expect("Node should exist");

                let block_node = n.as_block().expect("Node should be a block").clone();
                let block_weight = block_node.weight.load(Relaxed);
                let block_cumulative_weight = block_node.cumulative_weight.load(Relaxed);
                let tip_cumulative_weight = self
                    .block_dag
                    .get(&self.tip)
                    .expect("Tip should exist")
                    .cumulative_weight
                    .load(Relaxed);

                let threshold = (self.total_weight() as f64) * 0.67;

                if block_weight as f64 > threshold {
                    let removed = self.block_dag.retain(&parent);
                    removed.iter().for_each(|n| {
                        self.proposal_dags.remove(&n.id());
                    });
                    update_result.new_checkpoint = Some(block_node);
                } else {
                    if block_cumulative_weight > tip_cumulative_weight {
                        self.tip = block_node.id();
                    }

                    self.block_dag.upsert(block_node, std::iter::once(parent));
                    self.proposal_dags
                        .entry(hash)
                        .or_default()
                        .upsert(n, std::iter::empty());
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
            .get(&self.tip)
            .expect("Tip node should exist")
    }

    pub fn tip_block(&self) -> &Block {
        &self.tip_node().block
    }

    pub fn tip_hash(&self) -> Multihash {
        self.tip
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.tip_node().trie.read().clone()
    }

    pub fn tip_cumulative_weight(&self) -> u64 {
        self.tip_node()
            .cumulative_weight
            .load(std::sync::atomic::Ordering::Relaxed)
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

    pub fn root_block(&self) -> &Block {
        &self
            .block_dag
            .get(&self.root_hash)
            .expect("Root node should exist")
            .block
    }

    pub fn into_established(mut self) -> EstablishedCheckpoint {
        let mut blocks = HashMap::new();

        let mut cur = self.root_hash;

        loop {
            let cur_node = self
                .block_dag
                .get(&cur)
                .expect("Node should exist in the DAG");

            let mut proposals = HashMap::new();

            let mut dag = self
                .proposal_dags
                .remove(&cur)
                .expect("Proposal DAG should exist");

            cur_node.block.proposals.iter().for_each(|p| {
                let pn = dag
                    .remove(p)
                    .expect("Proposal node should exist")
                    .into_proposal();
                proposals.insert(*p, (pn.proposal, pn.witness));
            });

            let block = EstablishedBlock {
                block: cur_node.block.clone(),
                witness: cur_node.witness.clone(),
                proposals,
            };

            blocks.insert(cur, block);

            let children = self
                .block_dag
                .get_children(&cur)
                .expect("Children should exist");

            match children.len() {
                0 => break,
                1 => cur = children[0],
                _ => panic!("Checkpoint root should have a single child"),
            }
        }

        EstablishedCheckpoint {
            root_hash: self.root_hash,
            blocks,
        }
    }
}
