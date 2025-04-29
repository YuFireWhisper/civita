use std::collections::HashMap;

use crate::{crypto::keypair::PublicKey, utils::IndexedMap};

#[derive(Debug)]
pub struct PendingElection {
    seed: [u8; 32],
    votes: HashMap<libp2p::PeerId, ([u8; 32], PublicKey)>,
    sorted_votes: Option<Vec<libp2p::PeerId>>,
    candidates: Option<IndexedMap<libp2p::PeerId, PublicKey>>,
    message_hash: Option<[u8; 32]>,
    generate_count: u32,
}

impl PendingElection {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            votes: HashMap::new(),
            sorted_votes: None,
            candidates: None,
            message_hash: None,
            generate_count: 0,
        }
    }

    pub fn add_vote(&mut self, peer_id: libp2p::PeerId, output: [u8; 32], public_key: PublicKey) {
        self.votes.insert(peer_id, (output, public_key));
        self.sorted_votes = None;
    }

    pub fn generate_candidates(
        &mut self,
        max: u16,
    ) -> (IndexedMap<libp2p::PeerId, PublicKey>, u32) {
        self.sort_votes();

        let n = self.votes.len().min(max as usize);

        assert!(n > 0, "No votes available to generate candidates");

        let candidates_peers = self.get_first_n(n);

        let mut candidates = IndexedMap::new();
        candidates.extend(candidates_peers.into_iter().filter_map(|peer_id| {
            self.votes
                .get(&peer_id)
                .map(|(_, public_key)| (peer_id, public_key.clone()))
        }));

        self.candidates = Some(candidates.clone());
        self.generate_count += 1;

        (candidates, self.generate_count)
    }

    fn sort_votes(&mut self) {
        if self.sorted_votes.is_none() {
            let mut entries = self.votes.keys().cloned().collect::<Vec<_>>();
            entries.sort_by(|a, b| {
                let a_seed = self.votes.get(a).unwrap().0;
                let b_seed = self.votes.get(b).unwrap().0;
                a_seed.cmp(&b_seed)
            });
            self.sorted_votes = Some(entries);
        }
    }

    fn get_first_n(&mut self, n: usize) -> Vec<libp2p::PeerId> {
        let sorted_votes = self
            .sorted_votes
            .as_mut()
            .expect("Votes should be sorted before removing");

        sorted_votes.iter().take(n).cloned().collect()
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    pub fn is_candidate(&self, peer_id: &libp2p::PeerId) -> bool {
        self.candidates
            .as_ref()
            .is_some_and(|candidates| candidates.contains_key(peer_id))
    }

    pub fn set_message_hash(&mut self, hash: [u8; 32]) {
        self.message_hash = Some(hash);
    }

    pub fn message_hash(&self) -> Option<[u8; 32]> {
        self.message_hash
    }

    pub fn take_candidates(&mut self) -> Option<IndexedMap<libp2p::PeerId, PublicKey>> {
        self.candidates.take()
    }

    pub fn remove_votes<'a>(&mut self, iter: impl Iterator<Item = &'a libp2p::PeerId>) {
        for peer_id in iter {
            self.votes.remove(peer_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        committee::pending_election::PendingElection,
        crypto::keypair::{self, PublicKey},
    };

    fn create_test_peer_id() -> libp2p::PeerId {
        libp2p::PeerId::random()
    }

    fn create_test_public_key() -> PublicKey {
        let (_, pk) = keypair::generate_secp256k1();
        pk
    }

    fn setup_election_with_votes(count: usize) -> (PendingElection, Vec<libp2p::PeerId>) {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);
        let mut peer_ids = Vec::new();

        for i in 0..count {
            let peer_id = create_test_peer_id();
            let output = [i as u8; 32];
            let public_key = create_test_public_key();

            election.add_vote(peer_id, output, public_key);
            peer_ids.push(peer_id);
        }

        (election, peer_ids)
    }

    #[test]
    fn new_creates_empty_election() {
        let seed = [0u8; 32];
        let election = PendingElection::new(seed);

        assert_eq!(election.seed(), &seed);
        assert!(election.message_hash().is_none());
        assert_eq!(election.generate_count, 0);
    }

    #[test]
    fn add_vote_stores_vote_correctly() {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);
        let peer_id = create_test_peer_id();
        let output = [1u8; 32];
        let public_key = create_test_public_key();

        election.add_vote(peer_id, output, public_key);

        assert_eq!(election.votes.len(), 1);
        assert!(election.votes.contains_key(&peer_id));
        assert!(election.sorted_votes.is_none());
    }

    #[test]
    fn add_vote_replaces_existing_vote() {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);
        let peer_id = create_test_peer_id();
        let output1 = [1u8; 32];
        let output2 = [2u8; 32];
        let public_key = create_test_public_key();

        election.add_vote(peer_id, output1, public_key.clone());
        election.add_vote(peer_id, output2, public_key);

        assert_eq!(election.votes.len(), 1);
        assert_eq!(election.votes.get(&peer_id).unwrap().0, output2);
    }

    #[test]
    #[should_panic(expected = "No votes available to generate candidates")]
    fn generate_candidates_panics_when_no_votes() {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);

        election.generate_candidates(10);
    }

    #[test]
    fn generate_candidates_selects_correct_candidates() {
        let (mut election, peer_ids) = setup_election_with_votes(3);

        let (candidates, count) = election.generate_candidates(2);

        assert_eq!(count, 1);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.contains_key(&peer_ids[0]));
        assert!(candidates.contains_key(&peer_ids[1]));
        assert!(!candidates.contains_key(&peer_ids[2]));
    }

    #[test]
    fn generate_candidates_increments_counter() {
        let (mut election, _) = setup_election_with_votes(3);

        let (_, count1) = election.generate_candidates(2);
        let (_, count2) = election.generate_candidates(2);

        assert_eq!(count1, 1);
        assert_eq!(count2, 2);
    }

    #[test]
    fn generate_candidates_limits_by_max_parameter() {
        let (mut election, _) = setup_election_with_votes(5);

        let (candidates, _) = election.generate_candidates(3);

        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn sort_votes_orders_by_output_value() {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);

        let peer_id1 = create_test_peer_id();
        let peer_id2 = create_test_peer_id();
        let peer_id3 = create_test_peer_id();

        let output1 = [3u8; 32];
        let output2 = [1u8; 32];
        let output3 = [2u8; 32];

        let public_key = create_test_public_key();

        election.add_vote(peer_id1, output1, public_key.clone());
        election.add_vote(peer_id2, output2, public_key.clone());
        election.add_vote(peer_id3, output3, public_key);

        election.sort_votes();

        let sorted_votes = election.sorted_votes.as_ref().unwrap();
        assert_eq!(sorted_votes[0], peer_id2);
        assert_eq!(sorted_votes[1], peer_id3);
        assert_eq!(sorted_votes[2], peer_id1);
    }

    #[test]
    fn when_candidates_exist_is_candidate_returns_true() {
        let (mut election, peer_ids) = setup_election_with_votes(2);

        election.generate_candidates(1);

        assert!(election.is_candidate(&peer_ids[0]));
        assert!(!election.is_candidate(&peer_ids[1]));
    }

    #[test]
    fn when_no_candidates_is_candidate_returns_false() {
        let (election, peer_ids) = setup_election_with_votes(1);

        assert!(!election.is_candidate(&peer_ids[0]));
    }

    #[test]
    fn set_message_hash_stores_hash_correctly() {
        let seed = [0u8; 32];
        let mut election = PendingElection::new(seed);
        let hash = [42u8; 32];

        election.set_message_hash(hash);

        assert_eq!(election.message_hash(), Some(hash));
    }

    #[test]
    fn take_candidates_returns_and_clears_candidates() {
        let (mut election, peer_ids) = setup_election_with_votes(1);

        election.generate_candidates(1);
        assert!(election.is_candidate(&peer_ids[0]));

        let candidates = election.take_candidates();

        assert!(candidates.is_some());
        assert_eq!(candidates.unwrap().len(), 1);
        assert!(!election.is_candidate(&peer_ids[0]));
    }

    #[test]
    fn remove_votes_removes_specified_votes() {
        let (mut election, peer_ids) = setup_election_with_votes(3);

        election.remove_votes([&peer_ids[0], &peer_ids[2]].iter().cloned());

        assert_eq!(election.votes.len(), 1);
        assert!(!election.votes.contains_key(&peer_ids[0]));
        assert!(election.votes.contains_key(&peer_ids[1]));
        assert!(!election.votes.contains_key(&peer_ids[2]));
    }

    #[test]
    fn get_first_n_returns_correct_number_of_peers() {
        let (mut election, _) = setup_election_with_votes(5);

        election.sort_votes();
        let result = election.get_first_n(3);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn should_handle_edge_case_when_max_exceeds_votes() {
        let (mut election, peer_ids) = setup_election_with_votes(2);

        let (candidates, _) = election.generate_candidates(5);

        assert_eq!(candidates.len(), 2);
        assert!(candidates.contains_key(&peer_ids[0]));
        assert!(candidates.contains_key(&peer_ids[1]));
    }
}
