use std::collections::{hash_map::Entry, HashMap, HashSet};

use libp2p::{gossipsub::MessageId, PeerId};

use crate::{
    committee::signature_collector::{SignatureCollector, SignatureResult},
    crypto::dkg::{classic::config::ThresholdCounter, Data},
    network::transport::libp2p_transport::protocols::kad,
};

#[derive(Default)]
pub(super) struct State {
    members: HashSet<PeerId>,
    pub_key: Option<Vec<u8>>,
    processing: HashMap<MessageId, SignatureCollector>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_members(&mut self, members: HashSet<PeerId>) {
        self.members.clear();
        self.members.extend(members);
    }

    pub fn set_pub_key(&mut self, pub_key: Vec<u8>) {
        self.pub_key = Some(pub_key);
    }

    pub fn get_peer_index(&self, peer_id: PeerId) -> Option<u16> {
        self.members
            .iter()
            .position(|peer| *peer == peer_id)
            .map(|index| index as u16 + 1)
    }

    pub fn get_threshold(&self, threshold_counter: &dyn ThresholdCounter) -> u16 {
        threshold_counter.call(self.members.len() as u16)
    }

    pub fn process_signature(
        &mut self,
        msg_id: &MessageId,
        payload: kad::Payload,
        index: u16,
        signature: Data,
        threshold: u16,
    ) -> Option<SignatureResult> {
        let collector = self.track_signature_request(msg_id, payload, threshold);
        let result = collector.add_signature(index, signature);

        if result.is_some() {
            self.processing.remove(msg_id);
        }

        result
    }

    fn track_signature_request(
        &mut self,
        msg_id: &MessageId,
        payload: kad::Payload,
        threshold: u16,
    ) -> &mut SignatureCollector {
        match self.processing.entry(msg_id.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(SignatureCollector::new(payload, threshold)),
        }
    }
}
