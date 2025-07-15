use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::{
    block::Block,
    crypto::{Hasher, Multihash},
    proposal::Proposal,
};

pub struct Node {
    pub block: Block,
    pub parent: Option<Multihash>,
    pub children: HashSet<Multihash>,
    pub weight: u32,
    pub cumulative_weight: u32,
    pub is_finalized: bool,
    pub is_checkpoint: bool,
}

pub struct SubTree {
    pub nodes: HashMap<Multihash, Node>,
    pub proposals: HashMap<Multihash, Proposal>,
    pub height_idx: BTreeMap<u64, HashSet<Multihash>>,
    pub best_chain_tip: Option<Multihash>,
    pub root_checkpoint: Multihash,
    pub is_active: bool,
}

#[derive(Default)]
pub struct Tree {
    pub checkpoints: Vec<Multihash>,
    pub subtrees: HashMap<Multihash, SubTree>,
    pub active_checkpoint: Option<Multihash>,
    pub total_weight: u32,
    pub ancestors_cache: HashMap<(Multihash, Multihash), bool>,
}

impl Node {
    pub fn new(block: Block) -> Self {
        let parent = if block.height > 0 {
            Some(block.parent)
        } else {
            None
        };

        Node {
            weight: block.proposer_weight,
            cumulative_weight: block.proposer_weight,
            block,
            parent,
            children: HashSet::new(),
            is_finalized: false,
            is_checkpoint: false,
        }
    }
}

impl SubTree {
    pub fn new(root_checkpoint: Multihash) -> Self {
        SubTree {
            nodes: HashMap::new(),
            proposals: HashMap::new(),
            height_idx: BTreeMap::new(),
            best_chain_tip: None,
            root_checkpoint,
            is_active: true,
        }
    }

    pub fn add_block<H: Hasher>(&mut self, block: Block) -> Option<i32> {
        let hash = block.hash::<H>();
        let height = block.height;

        if height > 0 && !self.nodes.contains_key(&block.parent) {
            return None;
        }

        let mut node = Node::new(block);
        let mut total_weight_diff = 0;

        if let Some(parent_hash) = node.parent {
            if let Some(parent_node) = self.nodes.get_mut(&parent_hash) {
                node.cumulative_weight += parent_node.cumulative_weight;
                parent_node.children.insert(hash);
            }
        }

        for proposal_hash in &node.block.proposals {
            if let Some(proposal) = self.proposals.get(proposal_hash) {
                node.weight += proposal.proposer_weight;
                node.cumulative_weight += proposal.proposer_weight;
                total_weight_diff += proposal.total_weight_diff;
            }
        }

        self.nodes.insert(hash, node);
        self.height_idx.entry(height).or_default().insert(hash);
        self.update_best_chain(hash);

        Some(total_weight_diff)
    }

    fn update_best_chain(&mut self, candidate_hash: Multihash) {
        let Some(candidate) = self.nodes.get(&candidate_hash) else {
            return;
        };

        let Some(current_best) = self.best_chain_tip else {
            self.best_chain_tip = Some(candidate_hash);
            return;
        };

        let current = self.nodes.get(&current_best).unwrap();

        if candidate.cumulative_weight > current.cumulative_weight {
            self.best_chain_tip = Some(candidate_hash);
        }
    }

    pub fn finalize_to_checkpoint(&mut self, checkpoint_hash: Multihash) {
        let mut current = Some(checkpoint_hash);

        while let Some(hash) = current {
            if let Some(node) = self.nodes.get_mut(&hash) {
                node.is_finalized = true;
                current = node.parent;
            } else {
                break;
            }
        }

        if let Some(node) = self.nodes.get_mut(&checkpoint_hash) {
            node.is_checkpoint = true;
        }

        self.is_active = false;

        self.clean_non_finalized_branches();
    }

    fn clean_non_finalized_branches(&mut self) {
        let blocks_to_remove: Vec<Multihash> = self
            .nodes
            .keys()
            .filter(|&&hash| {
                let node = &self.nodes[&hash];
                !node.is_finalized
            })
            .cloned()
            .collect();

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

                self.height_idx.entry(node.block.height).and_modify(|set| {
                    set.remove(&hash);
                });

                visited.insert(hash);
            }
        }
    }
}

impl Tree {
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            subtrees: HashMap::new(),
            active_checkpoint: None,
            total_weight: 0,
            ancestors_cache: HashMap::new(),
        }
    }

    pub fn add_block<H: Hasher>(&mut self, block: Block) -> bool {
        let checkpoint_hash = block.parent_checkpoint;

        if !self.subtrees.contains_key(&checkpoint_hash) {
            if let Some(active_cp) = self.active_checkpoint {
                if checkpoint_hash != active_cp {
                    return false;
                }
            } else {
                self.subtrees
                    .insert(checkpoint_hash, SubTree::new(checkpoint_hash));
                self.active_checkpoint = Some(checkpoint_hash);
                self.checkpoints.push(checkpoint_hash);
            }
        }

        let subtree = self.subtrees.get_mut(&checkpoint_hash).unwrap();

        if !subtree.is_active {
            return false;
        }

        subtree.add_block::<H>(block).is_some_and(|weight_diff| {
            self.total_weight = self.total_weight.saturating_add_signed(weight_diff);
            self.check_for_checkpoint(checkpoint_hash);
            true
        })
    }

    fn check_for_checkpoint(&mut self, current_checkpoint: Multihash) {
        let Some(subtree) = self.subtrees.get(&current_checkpoint) else {
            return;
        };

        let Some(best_tip) = subtree.best_chain_tip else {
            return;
        };

        let Some(best_node) = subtree.nodes.get(&best_tip) else {
            return;
        };

        if best_node.cumulative_weight * 3 > self.total_weight * 2 {
            self.generate_checkpoint(current_checkpoint, best_tip);
        }
    }

    fn generate_checkpoint(&mut self, current_checkpoint: Multihash, new_checkpoint: Multihash) {
        if let Some(subtree) = self.subtrees.get_mut(&current_checkpoint) {
            subtree.finalize_to_checkpoint(new_checkpoint);
        }

        let new_subtree = SubTree::new(new_checkpoint);
        self.subtrees.insert(new_checkpoint, new_subtree);

        self.active_checkpoint = Some(new_checkpoint);
        self.checkpoints.push(new_checkpoint);
    }

    pub fn get_current_best_tip(&self) -> Option<Multihash> {
        let active_cp = self.active_checkpoint?;
        let subtree = self.subtrees.get(&active_cp)?;
        subtree.best_chain_tip
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
        for subtree in self.subtrees.values() {
            if subtree.nodes.contains_key(&descendant) {
                return self.is_ancestor_in_subtree(subtree, ancestor, descendant);
            }
        }

        self.is_ancestor_across_checkpoints(ancestor, descendant)
    }

    fn is_ancestor_in_subtree(
        &self,
        subtree: &SubTree,
        ancestor: Multihash,
        descendant: Multihash,
    ) -> bool {
        let mut current = Some(descendant);

        while let Some(hash) = current {
            if hash == ancestor {
                return true;
            }

            if let Some(node) = subtree.nodes.get(&hash) {
                current = node.parent;
            } else {
                break;
            }
        }

        false
    }

    fn is_ancestor_across_checkpoints(&self, ancestor: Multihash, descendant: Multihash) -> bool {
        let ancestor_pos = self.checkpoints.iter().position(|&cp| cp == ancestor);
        let descendant_pos = self.checkpoints.iter().position(|&cp| cp == descendant);

        match (ancestor_pos, descendant_pos) {
            (Some(a_pos), Some(d_pos)) => a_pos < d_pos,
            _ => false,
        }
    }

    pub fn get_finalized_chain(&self) -> Vec<Multihash> {
        let mut chain = Vec::new();

        for &checkpoint in &self.checkpoints {
            if let Some(subtree) = self.subtrees.get(&checkpoint) {
                let finalized_blocks: Vec<Multihash> = subtree
                    .nodes
                    .iter()
                    .filter(|(_, node)| node.is_finalized)
                    .map(|(&hash, _)| hash)
                    .collect();

                chain.extend(finalized_blocks);
            }
        }

        chain
    }

    pub fn prune_old_subtrees(&mut self, keep_count: usize) {
        if self.checkpoints.len() <= keep_count {
            return;
        }

        let to_remove = self.checkpoints.len() - keep_count;
        let old_checkpoints: Vec<Multihash> = self.checkpoints.drain(..to_remove).collect();

        for checkpoint in old_checkpoints {
            self.subtrees.remove(&checkpoint);
        }

        self.ancestors_cache.clear();
    }

    pub fn append_proposals<H: Hasher, I>(&mut self, proposals: I)
    where
        I: IntoIterator<Item = Proposal>,
    {
        for proposal in proposals {
            let hash = proposal.hash::<H>();
            let checkpoint_hash = proposal.parent_checkpoint;

            if let Some(subtree) = self.subtrees.get_mut(&checkpoint_hash) {
                subtree.proposals.insert(hash, proposal);
            }
        }
    }
}
