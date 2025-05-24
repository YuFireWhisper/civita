use statrs::distribution::{Binomial, DiscreteCDF};

use crate::{
    constants::HashArray,
    crypto::keypair::{self, SecretKey, VrfProof},
};

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

#[derive(Debug)]
pub struct VrfElector {
    secret_key: SecretKey,
    expected_num: u32,
}

impl VrfElector {
    pub fn new(secret_key: SecretKey, expected_num: u32) -> Self {
        Self {
            secret_key,
            expected_num,
        }
    }

    pub fn generate(
        &self,
        input: impl AsRef<[u8]>,
        stakes: u32,
        total_stakes: u32,
    ) -> Result<(VrfProof, u32)> {
        let vrf_proof = self.secret_key.prove(input.as_ref())?;

        let times_elected = self.calc_elected_times(stakes, total_stakes, &vrf_proof.output());

        Ok((vrf_proof, times_elected))
    }

    pub fn calc_elected_times(
        &self,
        stakes: u32,
        total_stakes: u32,
        vrf_output: &HashArray,
    ) -> u32 {
        let hash: [u8; TRUNCATED_HASH_SIZE] = vrf_output[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        let hash_value = u64::from_be_bytes(hash) as f64;

        for j in 0..=stakes {
            let threshold =
                self.calc_threshold(stakes, total_stakes, j) * 2f64.powi(HASH_BITS as i32);

            if hash_value <= threshold {
                return j;
            }
        }

        0
    }

    fn calc_threshold(&self, stakes: u32, total_stakes: u32, j: u32) -> f64 {
        let p = self.expected_num as f64 / total_stakes as f64;

        let dist = Binomial::new(p, stakes as u64).expect("Invalid binomial distribution");

        dist.cdf(j as u64)
    }
}
