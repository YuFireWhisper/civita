use std::collections::{HashMap, HashSet};

use crate::constants::HashArray;

#[derive(Debug)]
#[derive(Default)]
pub struct VoteManager {
    votes: HashMap<HashArray, u32>,
    total_weight: u32,
}

impl VoteManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_votes<'a>(&mut self, votes: impl Iterator<Item = &'a HashArray>, weight: u32) {
        votes.for_each(|proposal| {
            self.votes
                .entry(*proposal)
                .and_modify(|v| *v += weight)
                .or_insert(weight);
        });
    }

    pub fn add_total_votes(&mut self, weight: u32) {
        self.total_weight += weight;
    }

    pub fn get_winners(&self) -> HashSet<HashArray> {
        let threshold = self.total_weight * 2 / 3;

        self.votes
            .iter()
            .filter(|(_, &count)| count > threshold)
            .map(|(hash, _)| *hash)
            .collect()
    }
}
