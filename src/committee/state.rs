use std::collections::{hash_map::Entry, HashMap, HashSet};

use libp2p::{gossipsub::MessageId, PeerId};

use crate::{
    committee::signature_collector::{SignatureCollector, SignatureResult},
    crypto::dkg::{classic::config::ThresholdCounter, Data},
    network::transport::libp2p_transport::protocols::kad,
};

pub struct State {
    members: HashSet<PeerId>,
    pub_key: Option<Vec<u8>>,
    processing: HashMap<MessageId, SignatureCollector>,
    threshold: u16,
    threshold_counter: Box<dyn ThresholdCounter>,
}

impl State {
    pub fn new(threshold_counter: Box<dyn ThresholdCounter>) -> Self {
        let members = HashSet::new();
        let pub_key = None;
        let processing = HashMap::new();
        let threshold = 0;

        Self {
            members,
            pub_key,
            processing,
            threshold,
            threshold_counter,
        }
    }

    pub fn update_members(&mut self, members: HashSet<PeerId>) {
        self.members.clear();
        self.members.extend(members);
        self.threshold = self.get_threshold(&*self.threshold_counter);
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

    pub fn add_signature(
        &mut self,
        msg_id: MessageId,
        index: u16,
        signature: Data,
    ) -> Option<SignatureResult> {
        let collector = self.track_signature_request(msg_id.clone());
        let result = collector.add_signature(index, signature);

        if result.is_some() {
            self.processing.remove(&msg_id);
        }

        result
    }

    pub fn set_payload(
        &mut self,
        msg_id: MessageId,
        payload: kad::Payload,
    ) -> Option<SignatureResult> {
        let collector = self.track_signature_request(msg_id.clone());
        let result = collector.set_payload(payload);

        if result.is_some() {
            self.processing.remove(&msg_id);
        }

        result
    }

    fn track_signature_request(&mut self, msg_id: MessageId) -> &mut SignatureCollector {
        match self.processing.entry(msg_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(SignatureCollector::new(self.threshold)),
        }
    }
}
