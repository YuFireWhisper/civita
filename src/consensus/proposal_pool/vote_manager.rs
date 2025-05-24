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

#[cfg(test)]
mod tests {
    use super::*;

    const WEIGHT_10: u32 = 10;
    const WEIGHT_20: u32 = 20;
    const WEIGHT_30: u32 = 30;
    const WEIGHT_100: u32 = 100;

    fn create_hash(byte: u8) -> HashArray {
        [byte; 32]
    }

    fn create_multiple_hashes(bytes: &[u8]) -> Vec<HashArray> {
        bytes.iter().map(|&b| create_hash(b)).collect()
    }

    #[test]
    fn new_creates_empty_manager() {
        let manager = VoteManager::new();
        assert_eq!(manager.votes.len(), 0);
        assert_eq!(manager.total_weight, 0);
        assert!(manager.get_winners().is_empty());
    }

    #[test]
    fn default_creates_empty_manager() {
        let manager = VoteManager::default();
        assert_eq!(manager.votes.len(), 0);
        assert_eq!(manager.total_weight, 0);
        assert!(manager.get_winners().is_empty());
    }

    #[test]
    fn add_single_vote() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);
        let votes = [hash];

        manager.add_votes(votes.iter(), WEIGHT_10);

        assert_eq!(manager.votes.len(), 1);
        assert_eq!(manager.votes[&hash], WEIGHT_10);
    }

    #[test]
    fn add_multiple_votes_same_weight() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2, 3]);

        manager.add_votes(hashes.iter(), WEIGHT_20);

        assert_eq!(manager.votes.len(), 3);
        for hash in &hashes {
            assert_eq!(manager.votes[hash], WEIGHT_20);
        }
    }

    #[test]
    fn add_duplicate_votes_accumulates() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);
        let votes = [hash];

        manager.add_votes(votes.iter(), WEIGHT_10);
        manager.add_votes(votes.iter(), WEIGHT_20);

        assert_eq!(manager.votes.len(), 1);
        assert_eq!(manager.votes[&hash], WEIGHT_30);
    }

    #[test]
    fn add_total_votes_updates_weight() {
        let mut manager = VoteManager::new();

        manager.add_total_votes(WEIGHT_30);
        assert_eq!(manager.total_weight, WEIGHT_30);

        manager.add_total_votes(WEIGHT_20);
        assert_eq!(manager.total_weight, 50);
    }

    #[test]
    fn empty_votes_iterator() {
        let mut manager = VoteManager::new();
        let empty_votes: Vec<HashArray> = vec![];

        manager.add_votes(empty_votes.iter(), WEIGHT_10);

        assert_eq!(manager.votes.len(), 0);
    }

    #[test]
    fn zero_weight_votes() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);
        let votes = [hash];

        manager.add_votes(votes.iter(), 0);

        assert_eq!(manager.votes.len(), 1);
        assert_eq!(manager.votes[&hash], 0);
    }

    #[test]
    fn get_winners_no_total_weight() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);
        let votes = [hash];

        manager.add_votes(votes.iter(), WEIGHT_100);

        let winners = manager.get_winners();
        assert_eq!(winners.len(), 1);
        assert!(winners.contains(&hash));
    }

    #[test]
    fn get_winners_with_threshold() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2, 3]);

        manager.add_total_votes(90);

        manager.add_votes(std::iter::once(&hashes[0]), 70);
        manager.add_votes(std::iter::once(&hashes[1]), 50);
        manager.add_votes(std::iter::once(&hashes[2]), 60);

        let winners = manager.get_winners();
        assert_eq!(winners.len(), 1);
        assert!(winners.contains(&hashes[0]));
    }

    #[test]
    fn get_winners_multiple_winners() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2, 3]);

        manager.add_total_votes(90);

        manager.add_votes(std::iter::once(&hashes[0]), 70);
        manager.add_votes(std::iter::once(&hashes[1]), 80);
        manager.add_votes(std::iter::once(&hashes[2]), 40);

        let winners = manager.get_winners();
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&hashes[0]));
        assert!(winners.contains(&hashes[1]));
        assert!(!winners.contains(&hashes[2]));
    }

    #[test]
    fn get_winners_no_winners() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2]);

        manager.add_total_votes(WEIGHT_100);

        manager.add_votes(std::iter::once(&hashes[0]), 50);
        manager.add_votes(std::iter::once(&hashes[1]), 60);

        let winners = manager.get_winners();
        assert!(winners.is_empty());
    }

    #[test]
    fn threshold_calculation_edge_cases() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);

        manager.add_total_votes(99);
        manager.add_votes(std::iter::once(&hash), 67);
        assert_eq!(manager.get_winners().len(), 1);

        manager.votes.clear();
        manager.add_votes(std::iter::once(&hash), 66);
        assert!(manager.get_winners().is_empty());
    }

    #[test]
    fn threshold_calculation_even_total() {
        let mut manager = VoteManager::new();
        let hash = create_hash(1);

        manager.add_total_votes(WEIGHT_100);
        manager.add_votes(std::iter::once(&hash), 67);
        assert_eq!(manager.get_winners().len(), 1);

        manager.votes.clear();
        manager.add_votes(std::iter::once(&hash), 66);
        assert!(manager.get_winners().is_empty());
    }

    #[test]
    fn complex_voting_scenario() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2, 3, 4, 5]);

        manager.add_total_votes(300);

        manager.add_votes([&hashes[0], &hashes[1]].iter().copied(), 50);
        manager.add_votes([&hashes[2]].iter().copied(), 100);

        manager.add_votes([&hashes[0]].iter().copied(), 100); // total: 150
        manager.add_votes([&hashes[1]].iter().copied(), 120); // total: 170
        manager.add_votes([&hashes[2]].iter().copied(), 150); // total: 250

        let winners = manager.get_winners();
        assert_eq!(winners.len(), 1);
        assert!(winners.contains(&hashes[2]));
    }

    #[test]
    fn vote_manager_state_consistency() {
        let mut manager = VoteManager::new();
        let hashes = create_multiple_hashes(&[1, 2, 3]);

        manager.add_votes(hashes.iter(), WEIGHT_10);
        manager.add_total_votes(WEIGHT_30);

        let initial_votes = manager.votes.clone();
        let initial_total = manager.total_weight;

        let _winners1 = manager.get_winners();
        let _winners2 = manager.get_winners();

        assert_eq!(manager.votes, initial_votes);
        assert_eq!(manager.total_weight, initial_total);
    }
}
