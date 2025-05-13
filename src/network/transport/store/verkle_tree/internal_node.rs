use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Debug)]
pub struct InternalNode<F: FftField, const N: u32> {
    evals: Evaluations<F>,
}

impl<F: FftField, const N: u32> InternalNode<F, N> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note: The index is 1-based.
    pub fn insert(&mut self, index: u32, value: F) {
        assert!(index <= N, "Index out of bounds");
        assert!(index != 0, "Index must be positive");

        self.evals.evals[index as usize - 1] = value;
    }

    pub fn evaluate_at(&self, index: u32) -> F {
        assert!(index < N, "Index out of bounds");

        self.evals.interpolate_by_ref().evaluate(&F::from(index))
    }

    pub fn evaluate_at_zero(&self) -> F {
        self.evals.interpolate_by_ref().evaluate(&F::zero())
    }
}

impl<F: FftField, const N: u32> Default for InternalNode<F, N> {
    fn default() -> Self {
        let domain = GeneralEvaluationDomain::new(N as usize).expect("Failed to create domain");
        let evals = Evaluations::zero(domain);

        InternalNode { evals }
    }
}

impl<F: FftField, const N: u32> Serialize for InternalNode<F, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut serializer = serializer.serialize_struct("InternalNode", 2)?;

        let mut evals_byte =
            Vec::with_capacity(self.evals.serialized_size(ark_serialize::Compress::Yes));

        self.evals
            .serialize_compressed(&mut evals_byte)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_field("evals", &evals_byte)?;
        serializer.end()
    }
}

impl<'de, F: FftField, const N: u32> Deserialize<'de> for InternalNode<F, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "InternalNode")]
        struct InternalNodeData {
            evals: Vec<u8>,
        }

        let data = InternalNodeData::deserialize(deserializer)?;
        let evals = Evaluations::<F>::deserialize_compressed(data.evals.as_slice())
            .map_err(serde::de::Error::custom)?;

        Ok(InternalNode { evals })
    }
}
