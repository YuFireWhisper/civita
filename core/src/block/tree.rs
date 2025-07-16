use std::collections::{HashMap, HashSet};

use crate::{
    block::Block,
    crypto::{Hasher, Multihash},
    proposal::Proposal,
};

type Result<T, E = Missing> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Missing {
    Block(Multihash),
    Proposal(Multihash),
}

pub struct Node {
    pub block: Block,
    pub children: HashSet<Multihash>,
    pub weight: u32,
    pub total_weight: u32,
}

pub struct SubTree {
    pub leaf_hash: Multihash,
    pub root_hash: Multihash,
    pub parent_checkpoint: Multihash,
    pub nodes: HashMap<Multihash, Node>,
}

#[derive(Default)]
pub struct Tree {
    pub checkpoint: Multihash,
    pub checkpoints: HashMap<Multihash, SubTree>,
}

impl Node {
    pub fn new(block: Block, props: &HashMap<Multihash, Proposal>, base_weight: u32) -> Self {
        let (weight, total_weight_diff) = Self::calc_weight_and_total_weight_diff(&block, props);

        Node {
            block,
            children: HashSet::new(),
            weight,
            total_weight: base_weight.saturating_add_signed(total_weight_diff),
        }
    }

    fn calc_weight_and_total_weight_diff(
        block: &Block,
        props: &HashMap<Multihash, Proposal>,
    ) -> (u32, i32) {
        let mut weight = block.proposer_weight;
        let mut total_weight_diff = 0;

        for proposal_hash in &block.proposals {
            if let Some(prop) = props.get(proposal_hash) {
                weight += prop.proposer_weight;
                total_weight_diff += prop.total_weight_diff;
            }
        }

        (weight, total_weight_diff)
    }
}

impl SubTree {
    pub fn new<H: Hasher>(leaf: Node) -> Self {
        let leaf_hash = leaf.block.hash::<H>();
        let parent_checkpoint = leaf.block.parent_checkpoint;
        let nodes = HashMap::from([(leaf_hash, leaf)]);

        SubTree {
            leaf_hash,
            root_hash: leaf_hash,
            parent_checkpoint,
            nodes,
        }
    }

    pub fn update<H: Hasher>(&mut self, node: Node) -> Result<()> {
        let hash = node.block.hash::<H>();

        if !self.nodes.contains_key(&node.block.parent) {
            return Err(Missing::Block(node.block.parent));
        }
        self.update_leaf::<H>(&node);
        self.nodes.insert(hash, node);
        Ok(())
    }

    fn update_leaf<H: Hasher>(&mut self, candidate: &Node) {
        let leaf = self.nodes.get(&self.leaf_hash).expect("Leaf should exist");

        if candidate.total_weight > leaf.total_weight {
            self.leaf_hash = candidate.block.hash::<H>();
        }
    }

    pub fn finalize(&mut self, mut cur: Multihash) {
        self.leaf_hash = cur;

        let mut nodes = HashMap::new();

        while cur != self.root_hash {
            let node = self.nodes.remove(&cur).expect("Node should exist");
            let parent = node.block.parent;
            nodes.insert(cur, node);
            cur = parent;
        }

        self.nodes = nodes;
    }

    pub fn leaf(&self) -> &Node {
        self.nodes.get(&self.leaf_hash).expect("Leaf should exist")
    }

    pub fn root(&self) -> &Node {
        self.nodes.get(&self.root_hash).expect("Root should exist")
    }
}

impl Tree {
    pub fn new() -> Self {
        Tree {
            checkpoint: Multihash::default(),
            checkpoints: HashMap::new(),
        }
    }

    pub fn update<H: Hasher>(
        &mut self,
        block: Block,
        props: &HashMap<Multihash, Proposal>,
    ) -> Result<bool, Missing> {
        if block.parent_checkpoint != self.checkpoint {
            return Ok(false);
        }

        if self.checkpoint == Multihash::default() {
            // Block is the genesis block
            let node = Node::new(block, props, 0);
            self.update_checkpoint::<H>(node);
            return Ok(true);
        }

        let checkpoint = self
            .checkpoints
            .get_mut(&self.checkpoint)
            .expect("Checkpoint should exist");

        let node = Node::new(block, props, checkpoint.leaf().total_weight);

        if node.weight as f64 > (2.0 / 3.0) * checkpoint.root().weight as f64 {
            self.update_checkpoint::<H>(node);
            return Ok(true);
        }

        checkpoint.update::<H>(node)?;

        Ok(true)
    }

    fn update_checkpoint<H: Hasher>(&mut self, node: Node) {
        let hash = node.block.hash::<H>();
        let sub_tree = SubTree::new::<H>(node);
        self.checkpoint = hash;
        self.checkpoints.insert(hash, sub_tree);
    }

    pub fn get_leaf(&self) -> &Node {
        self.checkpoints
            .get(&self.checkpoint)
            .and_then(|subtree| subtree.nodes.get(&subtree.leaf_hash))
            .expect("Leaf should exist")
    }
}
