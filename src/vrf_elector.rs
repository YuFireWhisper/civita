use serde::{Deserialize, Serialize};
use statrs::distribution::{Binomial, DiscreteCDF};

use crate::crypto::keypair::{self, PublicKey, SecretKey, VrfProof};

type Result<T> = std::result::Result<T, Error>;

const TRUNCATED_HASH_SIZE: usize = 8;
const HASH_BITS: usize = TRUNCATED_HASH_SIZE * 8;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Keypair(#[from] keypair::Error),

    #[error("Invalid proof")]
    InvalidProof,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct Proof {
    pub times: u32,
    pub proof: VrfProof,
}

#[derive(Debug)]
pub struct VrfElector {
    secret_key: SecretKey,
}

impl VrfElector {
    pub fn new(secret_key: SecretKey) -> Self {
        Self { secret_key }
    }

    pub fn generate(
        &self,
        input: impl AsRef<[u8]>,
        stakes: u32,
        total_stakes: u32,
        expected_num: u32,
    ) -> Result<Option<Proof>> {
        let vrf_proof = self.secret_key.prove(input.as_ref())?;
        let vrf_output: [u8; TRUNCATED_HASH_SIZE] = vrf_proof.output()[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        let times_elected =
            Self::calc_elected_times(stakes, total_stakes, vrf_output, expected_num);

        if times_elected > 0 {
            Ok(Some(Proof {
                times: times_elected,
                proof: vrf_proof,
            }))
        } else {
            Ok(None)
        }
    }

    fn calc_elected_times(
        stakes: u32,
        total_stakes: u32,
        hash: [u8; TRUNCATED_HASH_SIZE],
        expected_num: u32,
    ) -> u32 {
        let hash_value = u64::from_be_bytes(hash) as f64;

        for j in 0..=stakes {
            let threshold = Self::calc_threshold(stakes, total_stakes, j, expected_num)
                * 2f64.powi(HASH_BITS as i32);

            if hash_value <= threshold {
                return j;
            }
        }

        0
    }

    fn calc_threshold(stakes: u32, total_stakes: u32, j: u32, expected_num: u32) -> f64 {
        let p = expected_num as f64 / total_stakes as f64;

        let dist = Binomial::new(p, stakes as u64).expect("Invalid binomial distribution");

        dist.cdf(j as u64)
    }

    pub fn verify(
        input: impl AsRef<[u8]>,
        stakes: u32,
        total_stakes: u32,
        expected_num: u32,
        proof: &Proof,
        public_key: &PublicKey,
    ) -> Result<bool> {
        if !public_key.verify_proof(input.as_ref(), &proof.proof) {
            return Ok(false);
        }

        let actual_elected_times = Self::calc_elected_times_with_proof(
            input,
            stakes,
            total_stakes,
            expected_num,
            &proof.proof,
            public_key,
        );

        Ok(actual_elected_times == proof.times)
    }

    pub fn calc_elected_times_with_proof(
        input: impl AsRef<[u8]>,
        stakes: u32,
        total_stakes: u32,
        expected_num: u32,
        proof: &VrfProof,
        public_key: &PublicKey,
    ) -> u32 {
        if !public_key.verify_proof(input.as_ref(), proof) {
            return 0;
        }

        let vrf_output: [u8; TRUNCATED_HASH_SIZE] = proof.output()[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        Self::calc_elected_times(stakes, total_stakes, vrf_output, expected_num)
    }
}
