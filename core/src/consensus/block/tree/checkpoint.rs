use std::{collections::HashMap, sync::Arc};

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
    utils::{trie::Trie, Record, Weight},
};

pub type Blocks<T> = HashMap<Multihash, EstablishedBlock<T>>;

#[derive(Clone)]
#[derive(Serialize)]
pub struct EstablishedBlock<T: Record> {
    pub block: Block,
    pub witness: block::Witness,
    pub proposals: HashMap<Multihash, (Proposal<T>, proposal::Witness)>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct UpdateResult<H, T: Record> {
    pub validated: Vec<Multihash>,
    pub invalidated: Vec<Multihash>,
    pub phantoms: Vec<Multihash>,
    pub new_checkpoint: Option<BlockNode<H, T>>,
}

enum ShouldUpdate {
    Checkpoint,
    Tip,
}

struct State<H: Hasher, T: Record> {
    dag: Dag<UnifiedNode<H, T>>,
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

impl<H: Hasher, T: Record> State<H, T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(root: BlockNode<H, T>) -> Self {
        let tip_hash = root.id();

        let node = UnifiedNode::Block(root);
        let dag = Dag::with_root(node);

        Self {
            dag,
            tip_hash,
            root_hash: tip_hash,
        }
    }

    pub fn contains(&self, hash: &Multihash) -> bool {
        self.dag.contains(hash)
    }
}

impl<H: Hasher, T: Record> Checkpoint<H, T> {
    pub fn new(tip: BlockNode<H, T>, mode: Arc<Mode>) -> Self {
        Self {
            state: State::with_root(tip),
            mode,
        }
    }

    pub fn with_root(root: BlockNode<H, T>, mode: Arc<Mode>) -> Self {
        Self {
            state: State::with_root(root),
            mode,
        }
    }

    pub fn new_empty(mode: Arc<Mode>) -> Self {
        Self {
            state: State::new(),
            mode,
        }
    }

    pub fn from_blocks<I>(blocks: I) -> Option<(Self, HashMap<Multihash, Blocks<T>>)>
    where
        I: IntoIterator<Item = EstablishedBlock<T>>,
    {
        let mode = Arc::new(Mode::Archive);

        let mut unests = HashMap::new();
        let mut ests = HashMap::new();

        blocks.into_iter().all(|block| {
            let checkpoint_hash = block.block.checkpoint;

            if ests.contains_key(&checkpoint_hash) {
                return false;
            }

            let checkpoint = unests
                .entry(checkpoint_hash)
                .or_insert_with(|| Checkpoint::<H, T>::new_empty(mode.clone()));

            if block
                .proposals
                .into_values()
                .any(|(p, w)| !checkpoint.update_proposal(p, w).invalidated.is_empty())
            {
                return false;
            }

            let res = checkpoint.update_block(block.block, block.witness);

            if !res.invalidated.is_empty() {
                return false;
            }

            if let Some(n) = res.new_checkpoint {
                let tmp = unests
                    .remove(&checkpoint_hash)
                    .expect("Checkpoint should exist");
                ests.insert(checkpoint_hash, tmp.into_blocks());
                unests.insert(n.id(), Checkpoint::with_root(n, mode.clone()));
            }

            true
        });

        if unests.len() != 1 {
            // Checkpoint must have exactly one root
            return None;
        }

        Some((unests.into_values().next().unwrap(), ests))
    }

    pub fn update_block(&mut self, block: Block, witness: block::Witness) -> UpdateResult<H, T> {
        let hash = block.hash::<H>();
        let mut result = UpdateResult::new();

        if self.state.contains(&hash) {
            return result;
        }

        let n = UnifiedNode::new_block(block, witness, self.mode.clone());
        let dag_result = self.state.dag.upsert(n);

        self.process_validation_result(dag_result, &mut result);

        result
    }

    fn process_validation_result(
        &mut self,
        validation_result: ValidationResult<UnifiedNode<H, T>>,
        result: &mut UpdateResult<H, T>,
    ) {
        let mut tip_hash = self.state.tip_hash;

        let should_update = validation_result
            .validated
            .into_iter()
            .inspect(|&hash| result.add_validated(hash))
            .filter_map(|hash| {
                let node = self
                    .state
                    .dag
                    .get(&hash)
                    .expect("Node should exist in the DAG");

                node.as_block().and_then(|node| {
                    match self.should_update_block(node, &tip_hash)? {
                        ShouldUpdate::Checkpoint => Some(hash),
                        ShouldUpdate::Tip => {
                            tip_hash = hash;
                            None
                        }
                    }
                })
            })
            .next();

        validation_result
            .invalidated
            .iter()
            .for_each(|&hash| result.add_invalidated(hash));

        validation_result.phantoms.into_iter().for_each(|hash| {
            result.add_phantom(hash);
        });

        self.state.tip_hash = tip_hash;

        if let Some(hash) = should_update {
            self.create_new_checkpoint(hash, result);
        }
    }

    fn should_update_block(
        &self,
        node: &BlockNode<H, T>,
        tip_hash: &Multihash,
    ) -> Option<ShouldUpdate> {
        use std::sync::atomic::Ordering::Relaxed;

        let block_metrics = {
            let weight = *node.weight.read();
            let cumulative_weight = *node.cumulative_weight.read();
            let height = node.height.load(Relaxed);
            let total_weight = node.trie.read().weight();
            (weight, cumulative_weight, height, total_weight)
        };

        let tip_metrics = {
            let n = self
                .state
                .dag
                .get(tip_hash)
                .expect("Tip node should exist")
                .as_block()
                .unwrap();
            (*n.cumulative_weight.read(), n.height.load(Relaxed))
        };

        let threshold = block_metrics.3.mul_f64(0.67);

        if block_metrics.0 > threshold {
            return Some(ShouldUpdate::Checkpoint);
        }

        if (block_metrics.1, block_metrics.2) > tip_metrics {
            return Some(ShouldUpdate::Tip);
        }

        None
    }

    fn create_new_checkpoint(&mut self, hash: Multihash, result: &mut UpdateResult<H, T>) {
        self.state.dag.retain(&hash);

        let node = self
            .state
            .dag
            .remove(&hash)
            .expect("Node should exist")
            .into_block();

        result.new_checkpoint = Some(node);
    }

    pub fn update_proposal(
        &mut self,
        proposal: Proposal<T>,
        witness: proposal::Witness,
    ) -> UpdateResult<H, T> {
        let mut result = UpdateResult::new();

        let n = UnifiedNode::new_proposal(proposal, witness);
        let dag_result = self.state.dag.upsert(n);

        self.process_validation_result(dag_result, &mut result);

        result
    }

    pub fn tip_node(&self) -> &BlockNode<H, T> {
        self.state
            .dag
            .get(&self.state.tip_hash)
            .expect("Tip node should exist")
            .as_block()
            .expect("Tip node should be a block")
    }

    pub fn tip_hash(&self) -> Multihash {
        self.state.tip_hash
    }

    pub fn tip_trie(&self) -> Trie<H, T> {
        self.tip_node().trie.read().clone()
    }

    pub fn get_trie(&self, parent: &Multihash) -> Option<Trie<H, T>> {
        self.state.dag.get(parent).map(|node| {
            node.as_block()
                .expect("Node should be a block")
                .trie
                .read()
                .clone()
        })
    }

    pub fn into_blocks(mut self) -> Blocks<T> {
        todo!()
    }

    pub fn to_blocks(&self) -> Blocks<T> {
        todo!()
    }

    pub fn root_hash(&self) -> Multihash {
        self.state.root_hash
    }

    #[deprecated]
    pub fn is_empty(&self) -> bool {
        unimplemented!()
    }

    #[deprecated]
    pub fn get_proposal_dag(&self, hash: Multihash) -> Option<&Dag<UnifiedNode<H, T>>> {
        unimplemented!()
    }
}

impl<H: Hasher, T: Record> Default for State<H, T> {
    fn default() -> Self {
        let root = BlockNode::genesis();
        Self::with_root(root)
    }
}
