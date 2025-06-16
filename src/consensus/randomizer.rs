use serde::{Deserialize, Serialize};
use statrs::distribution::{Binomial, DiscreteCDF};

use crate::crypto::{
    traits::{
        hasher::HashArray,
        vrf::{Proof, Prover, VerifyProof},
        PublicKey, SecretKey,
    },
    Hasher,
};

type Result<T> = std::result::Result<T, Error>;

const TRUNCATED_HASH_SIZE_IN_BYTES: usize = 8;
const TRUNCATED_HASH_SIZE_IN_BITS: usize = TRUNCATED_HASH_SIZE_IN_BYTES * 8;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Binomial(#[from] statrs::distribution::BinomialError),
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
#[derive(Serialize, Deserialize)]
pub struct WiningProof<P: Proof> {
    pub proof: P,
    pub weight: u32,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct DrawResult<P: Proof> {
    leader: Option<WiningProof<P>>,
    validator: Option<WiningProof<P>>,
}

pub trait Drawer: SecretKey + Prover {
    fn draw(
        &self,
        ctx: Context<<Self::Proof as Proof>::Hasher>,
        stakes: u32,
    ) -> Result<DrawResult<Self::Proof>>;
}

pub trait VerifyDraw: PublicKey + VerifyProof {
    fn verify_draw(
        &self,
        ctx: Context<<Self::Proof as Proof>::Hasher>,
        stakes: u32,
        result: DrawResult<Self::Proof>,
    ) -> Result<bool>;
}

#[derive(Clone)]
#[derive(Debug)]
pub enum Role {
    Leader,
    Validator,
}

impl<H: Hasher> Context<H> {
    pub fn new(
        seed: HashArray<H>,
        total_stakes: u32,
        expected_leaders: u16,
        expected_validators: u16,
    ) -> Self {
        let leader_input = Self::generate_input(seed.clone(), Role::Leader);
        let leader_p = Self::calc_p(expected_leaders, total_stakes);

        let validator_input = Self::generate_input(seed, Role::Validator);
        let validator_p = Self::calc_p(expected_validators, total_stakes);

        Self {
            leader: (leader_input, leader_p),
            validator: (validator_input, validator_p),
        }
    }

    fn generate_input(seed: HashArray<H>, role: Role) -> HashArray<H> {
        let mut bytes = Vec::with_capacity(seed.len() + 1);

        bytes.extend(seed);
        bytes.push(role.as_u8());

        H::hash(&bytes)
    }

    fn calc_p(tau: u16, total_stakes: u32) -> f64 {
        (tau as f64) / (total_stakes as f64)
    }

    fn draw<S>(&self, sk: &S, stakes: u32) -> Result<DrawResult<S::Proof>>
    where
        S: SecretKey + Prover,
        S::Proof: Proof<Hasher = H>,
    {
        let mut result = DrawResult::<S::Proof>::default();

        if self.check_status() {
            self.draw_inner(sk, stakes, Role::Leader, &mut result)?;
            self.draw_inner(sk, stakes, Role::Validator, &mut result)?;
        }

        Ok(result)
    }

    fn check_status(&self) -> bool {
        self.leader.1 > 0.0
            && self.leader.1 < 1.0
            && self.validator.1 > 0.0
            && self.validator.1 < 1.0
    }

    fn draw_inner<S: SecretKey + Prover>(
        &self,
        sk: &S,
        stakes: u32,
        role: Role,
        result: &mut DrawResult<S::Proof>,
    ) -> Result<()> {
        let (input, p) = match role {
            Role::Leader => (&self.leader.0, self.leader.1),
            Role::Validator => (&self.validator.0, self.validator.1),
        };

        let proof = sk.prove(input.as_slice());
        let output = proof.proof_to_hash();

        let hash_as_float = self.hash_to_float(&output);

        let mut j = 0u32;

        let dist = Binomial::new(p, stakes as u64)?;
        let normalized_hash = hash_as_float / 2f64.powi(TRUNCATED_HASH_SIZE_IN_BITS as i32);

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

        let proof = WiningProof { proof, weight: j };

        match role {
            Role::Leader => result.leader = Some(proof),
            Role::Validator => result.validator = Some(proof),
        }

        Ok(())
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

    fn verify_draw<PK: PublicKey + VerifyProof>(
        &self,
        pk: &PK,
        stakes: u32,
        result: DrawResult<PK::Proof>,
    ) -> Result<bool> {
        if !self.check_status() {
            return Ok(result.leader.is_none() && result.validator.is_none());
        }

        Ok(self.verify_inner(pk, stakes, &result, Role::Leader)?
            && self.verify_inner(pk, stakes, &result, Role::Validator)?)
    }

    fn verify_inner<PK: PublicKey + VerifyProof>(
        &self,
        pk: &PK,
        stakes: u32,
        result: &DrawResult<PK::Proof>,
        role: Role,
    ) -> Result<bool> {
        let ((input, p), proof) = match role {
            Role::Leader => match &result.leader {
                Some(proof) => ((&self.leader.0, self.leader.1), proof),
                None => return Ok(true),
            },
            Role::Validator => match &result.validator {
                Some(proof) => ((&self.validator.0, self.validator.1), proof),
                None => return Ok(true),
            },
        };

        if !pk.verify_proof(input.as_slice(), &proof.proof) {
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

impl<S: SecretKey + Prover> Drawer for S {
    fn draw(
        &self,
        ctx: Context<<Self::Proof as Proof>::Hasher>,
        stakes: u32,
    ) -> Result<DrawResult<Self::Proof>> {
        ctx.draw(self, stakes)
    }
}

impl<PK: PublicKey + VerifyProof> VerifyDraw for PK {
    fn verify_draw(
        &self,
        ctx: Context<<Self::Proof as Proof>::Hasher>,
        stakes: u32,
        result: DrawResult<Self::Proof>,
    ) -> Result<bool> {
        ctx.verify_draw(self, stakes, result)
    }
}

impl Role {
    pub fn as_u8(&self) -> u8 {
        match self {
            Role::Leader => 0,
            Role::Validator => 1,
        }
    }
}

impl<P: Proof> Default for DrawResult<P> {
    fn default() -> Self {
        Self {
            leader: None,
            validator: None,
        }
    }
}
