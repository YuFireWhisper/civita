use std::{collections::HashMap, mem};

use crate::{crypto::dkg::Data, network::transport::libp2p_transport::protocols::kad};

#[derive(Debug)]
pub struct SignatureResult {
    pub indices: Vec<u16>,
    pub signatures: Vec<Data>,
    pub payload: kad::Payload,
}

#[derive(Debug)]
pub struct SignatureCollector {
    payload: Option<kad::Payload>,
    partial_signatures: HashMap<u16, Data>,
    threshold: u16,
}

impl SignatureCollector {
    pub fn new(threshold: u16) -> Self {
        let payload = None;
        let partial_signatures = HashMap::new();

        Self {
            payload,
            partial_signatures,
            threshold,
        }
    }

    pub fn set_payload(&mut self, payload: kad::Payload) -> Option<SignatureResult> {
        self.payload = Some(payload);
        self.check_threshold()
    }

    pub fn add_signature(&mut self, index: u16, signature: Data) -> Option<SignatureResult> {
        self.partial_signatures.insert(index, signature);
        self.check_threshold()
    }

    fn check_threshold(&mut self) -> Option<SignatureResult> {
        if self.partial_signatures.len() >= self.threshold as usize && self.payload.is_some() {
            let signatures = mem::take(&mut self.partial_signatures);
            let (indices, signatures): (Vec<u16>, Vec<Data>) = signatures.into_iter().unzip();
            let payload = mem::take(&mut self.payload);

            Some(SignatureResult {
                indices,
                signatures,
                payload: payload.expect("Payload should be present"),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        committee::signature_collector::SignatureCollector,
        crypto::dkg::{classic::signature::SignatureBytes, Data},
        network::transport::libp2p_transport::protocols::kad,
    };

    fn create_payload() -> kad::Payload {
        const PAYLOAD: &[u8] = &[1, 2, 3];
        kad::Payload::Raw(PAYLOAD.to_vec())
    }

    fn create_data() -> Data {
        let signature = SignatureBytes::random();
        Data::Classic(signature)
    }

    #[test]
    fn create() {
        const THRESHOLD: u16 = 3;

        let collector = SignatureCollector::new(THRESHOLD);

        assert!(collector.payload.is_none());
        assert_eq!(collector.partial_signatures.len(), 0);
        assert_eq!(collector.threshold, THRESHOLD);
    }

    #[test]
    fn success_add_signature() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(THRESHOLD);
        collector.set_payload(payload);

        for i in 1..THRESHOLD {
            let signature = create_data();
            let result = collector.add_signature(i, signature.clone());
            assert!(result.is_none());
            assert_eq!(collector.partial_signatures.len(), i as usize);
            assert_eq!(collector.partial_signatures.get(&i), Some(&signature));
        }
    }

    #[test]
    fn none_not_enough_signatures() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(THRESHOLD);
        collector.set_payload(payload);

        for i in 1..THRESHOLD {
            let signature = create_data();
            let result = collector.add_signature(i, signature.clone());
            assert!(result.is_none());
        }
    }

    #[test]
    fn none_no_payload() {
        const THRESHOLD: u16 = 3;

        let mut collector = SignatureCollector::new(THRESHOLD);

        for i in 1..=THRESHOLD {
            let signature = create_data();
            let result = collector.add_signature(i, signature.clone());
            assert!(result.is_none());
        }
    }

    #[test]
    fn some_enough_signatures() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(THRESHOLD);
        collector.set_payload(payload.clone());

        for i in 1..THRESHOLD {
            let signature = create_data();
            let result = collector.add_signature(i, signature.clone());
            assert!(result.is_none());
        }

        let signature = create_data();
        let result = collector.add_signature(THRESHOLD, signature);
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(collector.partial_signatures.is_empty());
        assert_eq!(result.payload, payload);
        assert_eq!(result.indices.len(), THRESHOLD as usize);
        assert_eq!(result.signatures.len(), THRESHOLD as usize);
        assert_eq!(result.indices.len(), result.signatures.len());
    }

    #[test]
    fn set_payload_triggers_result() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(THRESHOLD);

        for i in 1..=THRESHOLD {
            let signature = create_data();
            collector.add_signature(i, signature);
        }

        let result = collector.set_payload(payload.clone());
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(collector.partial_signatures.is_empty());
        assert!(collector.payload.is_none());
        assert_eq!(result.payload, payload);
        assert_eq!(result.indices.len(), THRESHOLD as usize);
        assert_eq!(result.signatures.len(), THRESHOLD as usize);
    }
}
