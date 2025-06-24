use statrs::distribution::{Binomial, DiscreteCDF};

use crate::{
    crypto::{
        self,
        traits::{
            hasher::HashArray,
            vrf::{Proof, Prover, VerifyProof},
        },
        Hasher,
    },
    traits::serializable::{self, Serializable},
};

type Result<T> = std::result::Result<T, Error>;

const TRUNCATED_HASH_SIZE_IN_BYTES: usize = 8;
const TRUNCATED_HASH_SIZE_IN_BITS: usize = TRUNCATED_HASH_SIZE_IN_BYTES * 8;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Binomial(#[from] statrs::distribution::BinomialError),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Crypto(#[from] crypto::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),
}

#[derive(Clone)]
#[derive(Debug)]
pub struct Context<H: Hasher> {
    leader: (HashArray<H>, f64),
    validator: (HashArray<H>, f64),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct DrawProof<P: Proof> {
    pub proof: P,
    pub weight: u32,
}

pub trait Drawer<H: Hasher>: Prover {
    fn draw(
        &self,
        ctx: &Context<H>,
        stakes: u32,
        is_leader: bool,
    ) -> Result<Option<DrawProof<Self::Proof>>>;
}

pub trait VerifyDrawProof<H: Hasher>: VerifyProof {
    fn verify_draw_proof(
        &self,
        ctx: &Context<H>,
        stakes: u32,
        proof: &DrawProof<Self::Proof>,
        is_leader: bool,
    ) -> Result<bool>;
}

impl<H: Hasher> Context<H> {
    pub fn new(
        seed: HashArray<H>,
        total_stakes: u32,
        expected_leaders: u16,
        expected_validators: u16,
    ) -> Self {
        let leader_input = Self::generate_input(seed.clone(), true);
        let leader_p = Self::calc_p(expected_leaders, total_stakes);

        let validator_input = Self::generate_input(seed, false);
        let validator_p = Self::calc_p(expected_validators, total_stakes);

        Self {
            leader: (leader_input, leader_p),
            validator: (validator_input, validator_p),
        }
    }

    fn generate_input(seed: HashArray<H>, is_leader: bool) -> HashArray<H> {
        let mut bytes = Vec::with_capacity(seed.len() + 1);

        bytes.extend(seed);
        bytes.push(is_leader as u8);

        H::hash(&bytes)
    }

    fn calc_p(tau: u16, total_stakes: u32) -> f64 {
        (tau as f64) / (total_stakes as f64)
    }

    fn check_status(&self) -> bool {
        self.leader.1 > 0.0
            && self.leader.1 < 1.0
            && self.validator.1 > 0.0
            && self.validator.1 < 1.0
    }

    fn draw<S: Prover>(
        &self,
        sk: &S,
        stakes: u32,
        is_leader: bool,
    ) -> Result<Option<DrawProof<S::Proof>>> {
        if !self.check_status() {
            return Ok(None);
        }

        let (input, p) = if is_leader {
            (&self.leader.0, self.leader.1)
        } else {
            (&self.validator.0, self.validator.1)
        };

        let proof = sk.prove(input.as_slice())?;
        let output = proof.proof_to_hash();

        let hash_as_float = self.hash_to_float(&output);

        let mut j = 0u32;

        let dist = Binomial::new(p, stakes as u64)?;
        let normalized_hash = hash_as_float / 2f64.powi(TRUNCATED_HASH_SIZE_IN_BITS as i32);

        while j <= stakes {
            let lower_bound = self.binomial_cdf_sum(j, dist);
            let upper_bound = self.binomial_cdf_sum(j + 1, dist);

            if normalized_hash >= lower_bound && normalized_hash < upper_bound {
                return Ok(Some(DrawProof { proof, weight: j }));
            }

            j += 1;
        }

        Ok(None)
    }

    fn hash_to_float(&self, hash: &[u8]) -> f64 {
        u64::from_be_bytes(std::array::from_fn(|i| hash[i])) as f64
    }

    fn binomial_cdf_sum(&self, j: u32, dist: Binomial) -> f64 {
        if j == 0 {
            0.0
        } else {
            dist.cdf((j - 1) as u64)
        }
    }

    fn verify<PK: VerifyProof>(
        &self,
        pk: &PK,
        stakes: u32,
        proof: &DrawProof<PK::Proof>,
        is_leader: bool,
    ) -> Result<bool> {
        if !self.check_status() {
            return Ok(false);
        }

        let (input, p) = if is_leader {
            (&self.leader.0, self.leader.1)
        } else {
            (&self.validator.0, self.validator.1)
        };

        if pk.verify_proof(input.as_slice(), &proof.proof).is_err() {
            return Ok(false);
        }

        let output = proof.proof.proof_to_hash();
        let hash_as_float = self.hash_to_float(&output);
        let normalized_hash = hash_as_float / 2f64.powi(TRUNCATED_HASH_SIZE_IN_BITS as i32);

        let dist = Binomial::new(p, stakes as u64)?;
        let lower_bound = self.binomial_cdf_sum(proof.weight, dist);
        let upper_bound = self.binomial_cdf_sum(proof.weight + 1, dist);

        Ok(normalized_hash >= lower_bound && normalized_hash < upper_bound)
    }
}

impl<P: Proof> Serializable for DrawProof<P> {
    fn serialized_size(&self) -> usize {
        self.proof.serialized_size() + self.weight.serialized_size()
    }

    fn from_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::result::Result<Self, serializable::Error> {
        Ok(Self {
            proof: P::from_reader(reader)?,
            weight: u32::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<(), serializable::Error> {
        self.proof.to_writer(writer)?;
        self.weight.to_writer(writer)?;

        Ok(())
    }
}

impl<H: Hasher, S: Prover> Drawer<H> for S {
    fn draw(
        &self,
        ctx: &Context<H>,
        stakes: u32,
        is_leader: bool,
    ) -> Result<Option<DrawProof<Self::Proof>>> {
        ctx.draw(self, stakes, is_leader)
    }
}

impl<H: Hasher, S: VerifyProof> VerifyDrawProof<H> for S {
    fn verify_draw_proof(
        &self,
        ctx: &Context<H>,
        stakes: u32,
        proof: &DrawProof<Self::Proof>,
        is_leader: bool,
    ) -> Result<bool> {
        ctx.verify(self, stakes, proof, is_leader)
    }
}
