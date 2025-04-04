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
    payload: kad::Payload,
    partial_signatures: HashMap<u16, Data>,
    threshold: u16,
}

impl SignatureCollector {
    pub fn new(payload: kad::Payload, threshold: u16) -> Self {
        let partial_signatures = HashMap::new();
        Self {
            payload,
            partial_signatures,
            threshold,
        }
    }

    pub fn add_signature(&mut self, index: u16, signature: Data) -> Option<SignatureResult> {
        self.partial_signatures.insert(index, signature);

        if self.partial_signatures.len() >= self.threshold as usize {
            let signatures = mem::take(&mut self.partial_signatures);
            let (indices, signatures): (Vec<u16>, Vec<Data>) = signatures.into_iter().unzip();
            let payload = mem::take(&mut self.payload);

            Some(SignatureResult {
                indices,
                signatures,
                payload,
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

        let payload = create_payload();
        let threshold = 3;
        let collector = SignatureCollector::new(payload.clone(), THRESHOLD);

        assert_eq!(collector.payload, payload);
        assert_eq!(collector.partial_signatures.len(), 0);
        assert_eq!(collector.threshold, threshold);
    }

    #[test]
    fn success_add_signature() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(payload.clone(), THRESHOLD);

        for i in 1..THRESHOLD {
            let signature = create_data();
            collector.add_signature(i, signature.clone());
            assert_eq!(collector.partial_signatures.len(), i as usize);
            assert_eq!(collector.partial_signatures.get(&i), Some(&signature));
        }
    }

    #[test]
    fn none_not_enough_signatures() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(payload, THRESHOLD);

        let mut is_none = true;
        for i in 1..THRESHOLD {
            let signature = create_data();
            let result = collector.add_signature(i, signature.clone());
            if result.is_some() {
                is_none = false;
            }
        }

        assert!(is_none);
    }

    #[test]
    fn some_enough_signatures() {
        const THRESHOLD: u16 = 3;

        let payload = create_payload();
        let mut collector = SignatureCollector::new(payload.clone(), THRESHOLD);

        for i in 1..THRESHOLD {
            let signature = create_data();
            collector.add_signature(i, signature.clone());
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
}
