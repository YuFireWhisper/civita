use std::collections::{HashMap, HashSet};

use crate::{
    block::Block,
    crypto::{Hasher, Multihash},
    proposal::Proposal,
    utils::trie::Trie,
};

pub struct Node<H> {
    pub block: Block,
    pub children: HashSet<Multihash>,
    pub trie: Trie<H>,
    pub weight: u32,
    pub total_weight: u32,
}

pub struct SubTree<H> {
    pub leaf_hash: Multihash,
    pub root_hash: Multihash,
    pub parent_checkpoint: Multihash,
    pub nodes: HashMap<Multihash, Node<H>>,
}

#[derive(Default)]
pub struct Tree<H> {
    pub checkpoint: Multihash,
    pub checkpoints: HashMap<Multihash, SubTree<H>>,
}

impl<H: Hasher> Node<H> {
    pub fn new(
        block: Block,
        props: &HashMap<Multihash, Proposal>,
        trie: Trie<H>,
        base_weight: u32,
    ) -> Self {
        let (weight, total_weight_diff) = Self::calc_weight_and_total_weight_diff(&block, props);
        let total_weight = base_weight.saturating_add_signed(total_weight_diff);

        Node {
            block,
            children: HashSet::new(),
            trie,
            weight,
            total_weight,
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

    pub fn hash(&self) -> Multihash {
        self.block.hash::<H>()
    }
}

impl<H: Hasher> SubTree<H> {
    pub fn new(leaf: Node<H>) -> Self {
        let leaf_hash = leaf.hash();
        let parent_checkpoint = leaf.block.parent_checkpoint;
        let nodes = HashMap::from([(leaf_hash, leaf)]);

        SubTree {
            leaf_hash,
            root_hash: leaf_hash,
            parent_checkpoint,
            nodes,
        }
    }

    pub fn update(&mut self, node: Node<H>) {
        assert!(
            self.nodes.contains_key(&node.block.parent),
            "Parent node must exist"
        );

        self.update_leaf(&node);

        let hash = node.hash();
        self.nodes.insert(hash, node);
    }

    fn update_leaf(&mut self, candidate: &Node<H>) {
        let leaf = self.nodes.get(&self.leaf_hash).expect("Leaf should exist");

        if candidate.total_weight > leaf.total_weight {
            self.leaf_hash = candidate.hash();
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

    pub fn leaf(&self) -> &Node<H> {
        self.nodes.get(&self.leaf_hash).expect("Leaf should exist")
    }

    pub fn root(&self) -> &Node<H> {
        self.nodes.get(&self.root_hash).expect("Root should exist")
    }
}

impl<H: Hasher> Tree<H> {
    pub fn new() -> Self {
        Tree {
            checkpoint: Multihash::default(),
            checkpoints: HashMap::new(),
        }
    }

    pub fn update(
        &mut self,
        block: Block,
        props: &HashMap<Multihash, Proposal>,
        trie: Trie<H>,
    ) -> bool {
        if block.parent_checkpoint != self.checkpoint {
            return false;
        }

        if self.checkpoint == Multihash::default() {
            // Block is the genesis block
            let node = Node::new(block, props, trie, 0);
            self.update_checkpoint(node);
            return true;
        }

        let checkpoint = self
            .checkpoints
            .get_mut(&self.checkpoint)
            .expect("Checkpoint should exist");

        let node = Node::new(block, props, trie, checkpoint.leaf().total_weight);

        if node.weight as f64 > (2.0 / 3.0) * checkpoint.root().weight as f64 {
            self.update_checkpoint(node);
            return true;
        }

        checkpoint.update(node);

        true
    }

    fn update_checkpoint(&mut self, node: Node<H>) {
        let hash = node.hash();
        let sub_tree = SubTree::new(node);
        self.checkpoint = hash;
        self.checkpoints.insert(hash, sub_tree);
    }

    pub fn get_leaf_hash(&self) -> Multihash {
        self.checkpoint_tree().leaf_hash
    }

    pub fn get_leaf_height(&self) -> u64 {
        self.checkpoint_tree().leaf().block.height
    }

    pub fn get_leaf(&self) -> &Node<H> {
        self.checkpoint_tree().leaf()
    }

    fn checkpoint_tree(&self) -> &SubTree<H> {
        self.checkpoints
            .get(&self.checkpoint)
            .expect("Checkpoint should exist")
    }

    pub fn get_block(&self, hash: &Multihash) -> Option<&Block> {
        self.checkpoints
            .values()
            .find_map(|subtree| subtree.nodes.get(hash).map(|node| &node.block))
    }

    pub fn checkpoint(&self) -> &Block {
        &self
            .checkpoints
            .get(&self.checkpoint)
            .and_then(|subtree| subtree.nodes.get(&subtree.root_hash))
            .expect("Checkpoint should exist")
            .block
    }

    pub fn checkpoint_hash(&self) -> Multihash {
        self.checkpoint
    }

    pub fn get_trie(&self, hash: &Multihash) -> Option<&Trie<H>> {
        self.checkpoints
            .values()
            .find_map(|subtree| subtree.nodes.get(hash).map(|node| &node.trie))
    }

    pub fn get_node(&self, hash: &Multihash) -> Option<&Node<H>> {
        self.checkpoints
            .values()
            .find_map(|subtree| subtree.nodes.get(hash))
    }
}
