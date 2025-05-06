use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};

use crate::{crypto::keypair::PublicKey, utils::IndexedMap};

pub struct Context {
    pub base_input: Vec<u8>,
    pub current_input: Vec<u8>,
    pub epoch: u64,
    pub times: u8,
    pub candidates: HashMap<libp2p::PeerId, (Vec<u8>, PublicKey)>,
    pub start_time: SystemTime,
    pub selection_factor: f64,
    pub invalid_peers: HashSet<libp2p::PeerId>,
}

impl Context {
    pub fn new(base_input: Vec<u8>, epoch: u64, selection_factor: f64) -> Self {
        let current_input = Self::create_input(base_input.clone(), 0);

        Self {
            base_input,
            current_input,
            epoch,
            candidates: HashMap::new(),
            times: 0,
            start_time: SystemTime::now(),
            selection_factor,
            invalid_peers: HashSet::new(),
        }
    }

    pub fn increment(&mut self) {
        self.times += 1;
        self.current_input = Self::create_input(self.base_input.clone(), self.times);
    }

    fn create_input(mut input: Vec<u8>, times: u8) -> Vec<u8> {
        input.extend(&times.to_be_bytes());
        input
    }

    pub fn clear_candidates(&mut self) {
        self.candidates.clear();
    }

    pub fn add_candidate(
        &mut self,
        peer_id: libp2p::PeerId,
        output: Vec<u8>,
        public_key: PublicKey,
    ) {
        self.candidates.insert(peer_id, (output, public_key));
    }

    pub fn get_n_candidates(&mut self, n: u16) -> IndexedMap<libp2p::PeerId, PublicKey> {
        let mut entries: Vec<_> = std::mem::take(&mut self.candidates).into_iter().collect();
        entries.sort_by(|(_, (bytes_a, _)), (_, (bytes_b, _))| bytes_a.cmp(bytes_b));
        entries.truncate(n as usize);
        IndexedMap::from_iter(entries.into_iter().map(|(id, (_, key))| (id, key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::{self, PublicKey};
    use std::time::Duration;

    const TEST_EPOCH: u64 = 100;
    const TEST_SELECTION_FACTOR: f64 = 0.5;
    const DEFAULT_BASE_INPUT: [u8; 4] = [1, 2, 3, 4];

    fn create_test_context() -> Context {
        Context::new(
            DEFAULT_BASE_INPUT.to_vec(),
            TEST_EPOCH,
            TEST_SELECTION_FACTOR,
        )
    }

    fn create_test_candidate(output_value: u8) -> (libp2p::PeerId, Vec<u8>, PublicKey) {
        let peer_id = libp2p::PeerId::random();
        let output = vec![output_value, output_value + 1, output_value + 2];
        let (_, public_key) = keypair::generate_secp256k1();
        (peer_id, output, public_key)
    }

    #[test]
    fn constructor_initializes_context_with_correct_values() {
        let base_input = DEFAULT_BASE_INPUT.to_vec();
        let context = Context::new(base_input.clone(), TEST_EPOCH, TEST_SELECTION_FACTOR);

        assert_eq!(context.base_input, base_input);
        assert_eq!(context.epoch, TEST_EPOCH);
        assert_eq!(context.times, 0);
        assert_eq!(context.selection_factor, TEST_SELECTION_FACTOR);
        assert!(context.candidates.is_empty());
        assert!(context.invalid_peers.is_empty());

        let expected_input = Context::create_input(base_input, 0);
        assert_eq!(context.current_input, expected_input);
    }

    #[test]
    fn create_input_appends_times_to_base_input() {
        let base = vec![10, 20, 30];
        let times = 42;

        let result = Context::create_input(base.clone(), times);

        let mut expected = base;
        expected.extend_from_slice(&times.to_be_bytes());
        assert_eq!(result, expected);
    }

    #[test]
    fn increment_increases_times_counter_and_updates_input() {
        let mut context = create_test_context();
        let initial_times = context.times;
        let initial_input = context.current_input.clone();

        context.increment();

        assert_eq!(context.times, initial_times + 1);

        assert_ne!(context.current_input, initial_input);
        let expected_input = Context::create_input(context.base_input.clone(), context.times);
        assert_eq!(context.current_input, expected_input);
    }

    #[test]
    fn clear_candidates_removes_all_entries() {
        let mut context = create_test_context();

        for i in 0..3 {
            let (peer_id, output, public_key) = create_test_candidate(i);
            context.add_candidate(peer_id, output, public_key);
        }

        assert_eq!(context.candidates.len(), 3);

        context.clear_candidates();

        assert!(context.candidates.is_empty());
    }

    #[test]
    fn add_candidate_stores_entry_correctly() {
        let mut context = create_test_context();
        let (peer_id, output, public_key) = create_test_candidate(5);

        context.add_candidate(peer_id, output.clone(), public_key.clone());

        assert!(context.candidates.contains_key(&peer_id));
        let (stored_output, _) = &context.candidates[&peer_id];
        assert_eq!(stored_output, &output);
    }

    #[test]
    fn add_candidate_overwrites_existing_entry() {
        let mut context = create_test_context();
        let peer_id = libp2p::PeerId::random();

        let output1 = vec![1, 2, 3];
        let (_, public_key1) = keypair::generate_secp256k1();
        context.add_candidate(peer_id, output1, public_key1);

        let output2 = vec![4, 5, 6];
        let (_, public_key2) = keypair::generate_secp256k1();
        context.add_candidate(peer_id, output2.clone(), public_key2.clone());

        assert_eq!(context.candidates.len(), 1);
        let (stored_output, _) = &context.candidates[&peer_id];
        assert_eq!(stored_output, &output2);
    }

    #[test]
    fn get_n_candidates_returns_empty_map_when_no_candidates() {
        let mut context = create_test_context();
        let result = context.get_n_candidates(5);

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn get_n_candidates_limits_to_n_entries() {
        let mut context = create_test_context();

        let mut peer_ids = Vec::new();
        for i in 0..5 {
            let (peer_id, output, key) = create_test_candidate(i);
            peer_ids.push(peer_id);
            context.add_candidate(peer_id, output, key);
        }

        let result = context.get_n_candidates(3);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn get_n_candidates_returns_all_when_fewer_than_n() {
        let mut context = create_test_context();

        for i in 0..3 {
            let (peer_id, output, key) = create_test_candidate(i);
            context.add_candidate(peer_id, output, key);
        }

        let result = context.get_n_candidates(5);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn get_n_candidates_empties_the_candidates_map() {
        let mut context = create_test_context();

        for i in 0..3 {
            let (peer_id, output, key) = create_test_candidate(i);
            context.add_candidate(peer_id, output, key);
        }

        assert_eq!(context.candidates.len(), 3);

        let _ = context.get_n_candidates(5);

        assert!(context.candidates.is_empty());
    }

    #[test]
    fn when_start_time_is_set_it_matches_creation_time() {
        let context = create_test_context();
        let now = SystemTime::now();

        match now.duration_since(context.start_time) {
            Ok(duration) => assert!(duration < Duration::from_secs(1)),
            Err(_) => panic!("start_time is in the future"),
        }
    }
}
