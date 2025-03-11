use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Proof {
    output: Vec<u8>,
    proof: Vec<u8>,
}

impl Proof {
    pub fn new(output: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { output, proof }
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: [u8; 3] = [1, 2, 3];
    const PROOF: [u8; 3] = [4, 5, 6];

    #[test]
    fn test_new() {
        let vrf_proof = Proof::new(OUTPUT.to_vec(), PROOF.to_vec());
        assert_eq!(vrf_proof.output(), OUTPUT);
        assert_eq!(vrf_proof.proof(), PROOF);
    }
}
