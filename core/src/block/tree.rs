use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    marker::PhantomData,
};

use crate::{
    block::Block,
    crypto::{Hasher, Multihash},
    proposal::Proposal,
};

pub struct Node {
    pub block: Block,
    pub parent: Option<Multihash>,
    pub children: HashSet<Multihash>,
    pub stakes: u32,
    pub is_final: bool,
    pub is_checkpoint: bool,
    pub cumulative_stakes: u32,
}

#[derive(Default)]
pub struct Tree<H: Hasher> {
    pub nodes: HashMap<Multihash, Node>,
    pub proposals: HashMap<Multihash, Proposal>,

    pub height_idx: BTreeMap<u64, HashSet<Multihash>>,
    pub checkpoint_blocks: Vec<Multihash>,
    pub finalized_blocks: HashSet<Multihash>,

    pub best: Option<Multihash>,
    pub total_stakes: u32,

    pub branch_stakes: HashMap<Multihash, u32>,
    pub branch_proposals: HashMap<Multihash, Multihash>,

    pub ancestors_cache: HashMap<(Multihash, Multihash), bool>,

    _marker: PhantomData<H>,
}

impl Node {
    pub fn new(block: Block, stakes: u32) -> Self {
        let parent = if block.height() > 0 {
            Some(block.parent())
        } else {
            None
        };

        Node {
            block,
            parent,
            children: HashSet::new(),
            stakes,
            is_final: false,
            is_checkpoint: false,
            cumulative_stakes: stakes,
        }
    }
}

impl<H: Hasher> Tree<H> {
    pub fn add_block(&mut self, block: Block) -> bool {
        let hash = block.hash::<H>();
        let height = block.height();

        if height > 0 && !self.nodes.contains_key(&block.parent()) {
            return false;
        }

        let Some(stakes) = self.calc_block_stakes(&block) else {
            return false;
        };

        let mut node = Node::new(block, stakes);

        if let Some(parent_hash) = node.parent {
            if let Some(parent_node) = self.nodes.get_mut(&parent_hash) {
                node.cumulative_stakes += parent_node.cumulative_stakes;
                parent_node.children.insert(hash);
            }
        }

        self.nodes.insert(hash, node);
        self.height_idx.entry(height).or_default().insert(hash);

        self.update_best(hash);
        self.check_for_checkpoint(&hash);

        true
    }

    fn calc_block_stakes(&mut self, block: &Block) -> Option<u32> {
        let mut stakes = block.proposer_stakes();

        block
            .proposals()
            .iter()
            .filter_map(|proposal| self.proposals.get(proposal).map(|p| p.proposer_stakes()))
            .for_each(|s| stakes += s);

        Some(stakes)
    }

    fn update_best(&mut self, candidate_hash: Multihash) {
        let Some(candidate) = self.nodes.get(&candidate_hash) else {
            return;
        };

        let Some(cur_hash) = self.best else {
            self.best = Some(candidate_hash);
            return;
        };

        let cur = self.nodes.get(&cur_hash).unwrap();

        if candidate.cumulative_stakes > cur.cumulative_stakes {
            self.best = Some(candidate_hash);
            return;
        }

        if candidate.stakes == cur.stakes && candidate.block.vdf_proof() > cur.block.vdf_proof() {
            self.best = Some(candidate_hash);
        }
    }

    fn check_for_checkpoint(&mut self, block_hash: &Multihash) {
        let Some(node) = self.nodes.get(block_hash) else {
            return;
        };

        if node.stakes * 3 > self.total_stakes * 2 {
            self.generate_checkpoint(*block_hash);
        }
    }

    fn generate_checkpoint(&mut self, block_hash: Multihash) {
        if let Some(node) = self.nodes.get_mut(&block_hash) {
            node.is_checkpoint = true;
        }

        self.checkpoint_blocks.push(block_hash);
        self.finalize_branch(block_hash);
        self.clean_up_non_finalized();
    }

    fn finalize_branch(&mut self, block_hash: Multihash) {
        let mut cur = Some(block_hash);

        while let Some(hash) = cur {
            let Some(node) = self.nodes.get_mut(&hash) else {
                break;
            };

            if node.is_final {
                break;
            }

            node.is_final = true;
            self.finalized_blocks.insert(hash);
            cur = node.parent;
        }
    }

    fn clean_up_non_finalized(&mut self) {
        let (c_hash, c_height) = self
            .checkpoint_blocks
            .last()
            .as_ref()
            .map(|h| {
                let node = self.nodes.get(h).unwrap();
                (**h, node.block.height())
            })
            .unwrap();

        let blocks_to_remove: Vec<Multihash> = self
            .height_idx
            .get(&c_height)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|&hash| hash != &c_hash && !self.finalized_blocks.contains(hash))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        for hash in blocks_to_remove {
            self.remove_branch(hash);
        }
    }

    fn remove_branch(&mut self, block_hash: Multihash) {
        let mut to_remove = VecDeque::new();
        let mut visited = HashSet::new();

        to_remove.push_back(block_hash);

        while let Some(hash) = to_remove.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            if let Some(node) = self.nodes.remove(&hash) {
                for child_hash in node.children {
                    to_remove.push_back(child_hash);
                }

                self.height_idx
                    .entry(node.block.height())
                    .and_modify(|set| {
                        set.remove(&hash);
                    });

                visited.insert(hash);
            }
        }
    }

    pub fn add_proposal(&mut self, proposal: Proposal) -> bool {
        let hash = proposal.parent();

        if !self.nodes.contains_key(&hash) {
            return false;
        }

        self.proposals.insert(hash, proposal);

        true
    }

    pub fn is_ancestor(&mut self, ancestor: Multihash, descendant: Multihash) -> bool {
        let cache_key = (ancestor, descendant);

        if let Some(&result) = self.ancestors_cache.get(&cache_key) {
            return result;
        }

        let result = self.is_ancestor_uncached(ancestor, descendant);
        self.ancestors_cache.insert(cache_key, result);
        result
    }

    fn is_ancestor_uncached(&self, ancestor: Multihash, descendant: Multihash) -> bool {
        let mut current = Some(descendant);

        while let Some(hash) = current {
            if hash == ancestor {
                return true;
            }

            if let Some(node) = self.nodes.get(&hash) {
                current = node.parent;
            } else {
                break;
            }
        }

        false
    }

    pub fn add_blocks_batch(&mut self, blocks: Vec<Block>) -> Vec<bool> {
        blocks
            .into_iter()
            .map(|block| self.add_block(block))
            .collect()
    }

    pub fn get_branch_info(&self, from: Multihash, to: Multihash) -> Option<Vec<Multihash>> {
        let mut path = Vec::new();
        let mut current = Some(to);

        while let Some(hash) = current {
            if hash == from {
                path.reverse();
                return Some(path);
            }

            path.push(hash);

            if let Some(node) = self.nodes.get(&hash) {
                current = node.parent;
            } else {
                break;
            }
        }

        None
    }
}
