use std::fmt::Display;

use statrs::distribution::{Binomial, DiscreteCDF};

use crate::{
    constants::HashArray,
    crypto::keypair::{self, SecretKey, VrfProof},
};

const TRUNCATED_HASH_SIZE: usize = 8;
const HASH_BITS: usize = TRUNCATED_HASH_SIZE * 8;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    KeyPair(#[from] keypair::Error),

    #[error("{0}")]
    Binomial(#[from] statrs::distribution::BinomialError),
}

#[derive(Clone)]
#[derive(Debug)]
pub enum Role {
    Leader,
    Validator,
}

#[derive(Clone)]
pub struct DrawResult {
    pub proof: VrfProof,
    pub weight: u32,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct Context {
    seed: HashArray,
    role: Role,
    input: HashArray,
    p: f64,
}

impl Context {
    pub fn new(seed: HashArray, role: Role, total_stakes: u32, tau: u16) -> Self {
        let total_stakes = total_stakes as f64;

        let input = Self::generate_input(&seed, &role);
        let p = tau as f64 / total_stakes;

        Self {
            seed,
            role,
            input,
            p,
        }
    }

    fn generate_input(seed: &HashArray, role: &Role) -> HashArray {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(role.to_string().as_bytes());
        hasher.finalize().into()
    }

    pub fn draw(&self, stakes: u32, sk: &SecretKey) -> Result<DrawResult> {
        let proof = sk.prove(self.input)?;

        let hash_as_float = self.hash_to_float(&proof.output());

        if stakes == 0 || self.p <= 0.0 || self.p >= 1.0 {
            return Ok(DrawResult { proof, weight: 0 });
        }

        let mut j = 0u32;

        let dist = Binomial::new(self.p, stakes as u64)?;
        let normalized_hash = hash_as_float / 2f64.powi(HASH_BITS as i32);

        loop {
            let lower_bound = self.binomial_cdf_sum(j, dist);
            let upper_bound = self.binomial_cdf_sum(j + 1, dist);

            if normalized_hash >= lower_bound && normalized_hash < upper_bound {
                break;
            }

            j += 1;

            if j > stakes {
                panic!("Exceeded maximum stakes during draw calculation");
            }
        }

        Ok(DrawResult { proof, weight: j })
    }

    fn hash_to_float(&self, hash: &HashArray) -> f64 {
        let truncated_hash: [u8; TRUNCATED_HASH_SIZE] = hash[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        u64::from_be_bytes(truncated_hash) as f64
    }

    fn binomial_cdf_sum(&self, j: u32, dist: Binomial) -> f64 {
        if j == 0 {
            0.0
        } else {
            dist.cdf((j - 1) as u64)
        }
    }

    pub fn verify(&self, result: DrawResult, stakes: u32) -> Result<bool> {
        if stakes == 0 || self.p <= 0.0 || self.p >= 1.0 {
            return Ok(result.weight == 0);
        }

        let hash_as_float = self.hash_to_float(&result.proof.output());
        let normalized_hash = hash_as_float / 2f64.powi(HASH_BITS as i32);

        let dist = Binomial::new(self.p, stakes as u64)?;

        let lower_bound = self.binomial_cdf_sum(result.weight, dist);
        let upper_bound = self.binomial_cdf_sum(result.weight + 1, dist);

        Ok(normalized_hash >= lower_bound && normalized_hash < upper_bound)
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Leader => write!(f, "Leader"),
            Role::Validator => write!(f, "Validator"),
        }
    }
}
