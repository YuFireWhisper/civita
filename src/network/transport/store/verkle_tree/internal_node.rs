use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_serialize::Compress;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Debug)]
pub struct InternalNode<F: FftField, const N: u16> {
    evals: Evaluations<F>,
}

impl<F: FftField, const N: u16> InternalNode<F, N> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note: The index is 1-based.
    pub fn insert(&mut self, index: u16, value: F) {
        assert!(index <= N, "Index out of bounds");
        assert!(index != 0, "Index must be positive");

        self.evals.evals[index as usize - 1] = value;
    }

    pub fn evaluate_at(&self, index: u16) -> F {
        assert!(index < N, "Index out of bounds");

        self.evals.interpolate_by_ref().evaluate(&F::from(index))
    }

    pub fn evaluate_at_zero(&self) -> F {
        self.evals.interpolate_by_ref().evaluate(&F::zero())
    }
}

impl<F: FftField, const N: u16> Default for InternalNode<F, N> {
    fn default() -> Self {
        let domain = GeneralEvaluationDomain::new(N as usize).expect("Failed to create domain");
        let evals = Evaluations::zero(domain);

        InternalNode { evals }
    }
}

const U16_SIZE: usize = 2;

impl<F: FftField, const N: u16> Serialize for InternalNode<F, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut serializer = serializer.serialize_struct("InternalNode", 2)?;

        // size = (eval_size + u16_size) * evals.len()
        let size = (F::zero().serialized_size(Compress::Yes) + U16_SIZE) * self.evals.evals.len();

        let mut bytes: Vec<u8> = Vec::with_capacity(size);

        for (i, &v) in self.evals.evals.iter().enumerate() {
            if !v.is_zero() {
                bytes.push(i.to_le_bytes()[0]);
                bytes.push(i.to_le_bytes()[1]);

                v.serialize_compressed(&mut bytes)
                    .map_err(serde::ser::Error::custom)?;
            }
        }

        serializer.serialize_field("evals", &bytes)?;
        serializer.end()
    }
}

impl<'de, F: FftField, const N: u16> Deserialize<'de> for InternalNode<F, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "InternalNode")]
        struct InternalNodeData {
            evals: Vec<u8>,
        }

        let mut evals = vec![F::zero(); N as usize];

        let data = InternalNodeData::deserialize(deserializer)?;

        let eval_size = F::zero().serialized_size(Compress::Yes);
        for chunk in data.evals.chunks(eval_size + U16_SIZE) {
            if chunk.len() < eval_size + U16_SIZE {
                return Err(serde::de::Error::custom("Invalid data length"));
            }

            let index = u16::from_le_bytes([chunk[0], chunk[1]]);
            let value =
                F::deserialize_compressed(&chunk[U16_SIZE..]).map_err(serde::de::Error::custom)?;

            evals[index as usize] = value;
        }

        let domain = GeneralEvaluationDomain::new(N as usize).unwrap();
        let evals = Evaluations::from_vec_and_domain(evals, domain);

        Ok(InternalNode { evals })
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_pallas::Fq;
    use num_traits::Zero;

    use super::*;

    const NODE_SIZE: u16 = 16;

    #[test]
    fn new_node_is_initialized_with_zeros() {
        let node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        for i in 0..NODE_SIZE {
            assert!(node.evals.evals[i as usize].is_zero());
        }
    }

    #[test]
    fn insert_stores_value_at_correct_position() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();
        let index = 5u16;
        let value = Fq::ONE;

        node.insert(index, value);

        assert_eq!(node.evals.evals[index as usize - 1], value);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn insert_panics_when_index_exceeds_bounds() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(NODE_SIZE + 1, Fq::ONE);
    }

    #[test]
    #[should_panic(expected = "Index must be positive")]
    fn insert_panics_when_index_is_zero() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(0, Fq::ONE);
    }

    #[test]
    fn evaluate_at_returns_correct_value() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(1, Fq::from(5u32));
        node.insert(2, Fq::from(10u32));
        node.insert(3, Fq::from(15u32));

        let result = node.evaluate_at(2);

        assert!(!result.is_zero());
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn evaluate_at_panics_when_index_out_of_bounds() {
        let node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.evaluate_at(NODE_SIZE);
    }

    #[test]
    fn evaluate_at_zero_returns_interpolated_value() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(1, Fq::from(5u32));
        node.insert(3, Fq::from(10u32));

        let result = node.evaluate_at_zero();

        assert!(!result.is_zero());
    }

    #[test]
    fn serialization_deserialization_preserves_values() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(1, Fq::from(5u32));
        node.insert(3, Fq::from(10u32));
        node.insert(5, Fq::from(15u32));

        let serialized = serde_json::to_string(&node).expect("Serialization failed");

        let deserialized: InternalNode<Fq, NODE_SIZE> =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        for i in 0..NODE_SIZE as usize {
            assert_eq!(node.evals.evals[i], deserialized.evals.evals[i]);
        }
    }

    #[test]
    fn serialization_ignores_zero_values() {
        let mut node: InternalNode<Fq, NODE_SIZE> = InternalNode::new();

        node.insert(1, Fq::from(5u32));
        node.insert(3, Fq::zero());
        node.insert(5, Fq::from(15u32));

        let serialized = serde_json::to_string(&node).expect("Serialization failed");

        let deserialized: InternalNode<Fq, NODE_SIZE> =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert!(deserialized.evals.evals[2].is_zero());
        assert_eq!(node.evals.evals[0], deserialized.evals.evals[0]);
        assert_eq!(node.evals.evals[4], deserialized.evals.evals[4]);
    }

    #[test]
    fn deserialization_handles_empty_data() {
        let empty_json = r#"{"evals":[]}"#;

        let node: InternalNode<Fq, NODE_SIZE> =
            serde_json::from_str(empty_json).expect("Deserialization failed");

        for value in &node.evals.evals {
            assert!(value.is_zero());
        }
    }

    #[test]
    fn deserialization_error_on_invalid_data() {
        let invalid_json = r#"{"evals":[1,2]}"#;

        let result: Result<InternalNode<Fq, NODE_SIZE>, _> = serde_json::from_str(invalid_json);

        assert!(result.is_err());
    }
}
