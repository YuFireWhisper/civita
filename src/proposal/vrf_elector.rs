use serde::{Deserialize, Serialize};
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

    #[error("Invalid VRF proof")]
    InvalidVrfProof,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct Context {
    pub input: HashArray,
    pub total_stakes: u32,
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct ElectionResult {
    pub proof: VrfProof,
    pub times: u32,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct VrfElector {
    secret_key: Option<SecretKey>,
    expected_num: u32,
}

impl Context {
    pub fn new(input: HashArray, total_stakes: u32) -> Self {
        Self {
            input,
            total_stakes,
        }
    }
}

impl VrfElector {
    pub fn new(expected_num: u32) -> Self {
        Self {
            secret_key: None,
            expected_num,
        }
    }

    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    pub fn generate(&self, stakes: u32, ctx: &Context) -> Result<ElectionResult> {
        let proof = self
            .secret_key
            .expect("Secret key must be set")
            .prove(ctx.input)?;
        let times = self.calc_elected_times(stakes, &proof.output(), ctx);

        Ok(ElectionResult { proof, times })
    }

    fn calc_elected_times(&self, stakes: u32, vrf_output: &HashArray, ctx: &Context) -> u32 {
        let hash: [u8; TRUNCATED_HASH_SIZE] = vrf_output[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        let hash_value = u64::from_be_bytes(hash) as f64;

        for j in 0..=stakes {
            let threshold = self.calc_threshold(stakes, j, ctx) * 2f64.powi(HASH_BITS as i32);

            if hash_value <= threshold {
                return j;
            }
        }

        0
    }

    fn calc_threshold(&self, stakes: u32, j: u32, ctx: &Context) -> f64 {
        let p = self.expected_num as f64 / ctx.total_stakes as f64;

        let dist = Binomial::new(p, stakes as u64).expect("Invalid binomial distribution");

        dist.cdf(j as u64)
    }

    pub fn calc_times_with_proof(
        &self,
        stakes: u32,
        vrf_proof: &VrfProof,
        ctx: &Context,
    ) -> Result<u32> {
        Ok(self.calc_elected_times(stakes, &vrf_proof.output(), ctx))
    }
}
