use serde::{Deserialize, Serialize};
use statrs::distribution::{Binomial, DiscreteCDF};

use crate::crypto::{
    traits::{
        hasher::HashArray,
        vrf::{Proof, Prover, VerifyProof},
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

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
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
pub struct DrawResult<P: Proof> {
    leader: Option<(P, u32)>,
    validator: Option<(P, u32)>,
}

pub trait Drawer<H: Hasher>: Prover {
    fn draw(&self, ctx: Context<H>, stakes: u32) -> Result<DrawResult<Self::Proof>>;
}

pub trait VerifyDraw<H: Hasher>: VerifyProof {
    fn verify_draw(
        &self,
        ctx: Context<H>,
        stakes: u32,
        result: DrawResult<Self::Proof>,
    ) -> Result<bool>;
}

#[derive(Clone)]
#[derive(Debug)]
enum Role {
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

    fn check_status(&self) -> bool {
        self.leader.1 > 0.0
            && self.leader.1 < 1.0
            && self.validator.1 > 0.0
            && self.validator.1 < 1.0
    }

    fn draw<S: Prover>(&self, sk: &S, stakes: u32) -> Result<DrawResult<S::Proof>> {
        let mut result = DrawResult::<S::Proof>::default();

        if self.check_status() {
            self.draw_inner(sk, stakes, Role::Leader, &mut result)?;
            self.draw_inner(sk, stakes, Role::Validator, &mut result)?;
        }

        Ok(result)
    }

    fn draw_inner<S: Prover>(
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

        match role {
            Role::Leader => result.leader = Some((proof, j)),
            Role::Validator => result.validator = Some((proof, j)),
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

    fn verify<PK: VerifyProof>(
        &self,
        pk: &PK,
        stakes: u32,
        result: &DrawResult<PK::Proof>,
    ) -> Result<bool> {
        if !self.check_status() {
            return Ok(result.leader.is_none() && result.validator.is_none());
        }

        Ok(self.verify_inner(pk, stakes, result, Role::Leader)?
            && self.verify_inner(pk, stakes, result, Role::Validator)?)
    }

    fn verify_inner<PK: VerifyProof>(
        &self,
        pk: &PK,
        stakes: u32,
        result: &DrawResult<PK::Proof>,
        role: Role,
    ) -> Result<bool> {
        let ((input, p), (proof, weight)) = match role {
            Role::Leader => match &result.leader {
                Some(proof) => ((&self.leader.0, self.leader.1), proof),
                None => return Ok(true),
            },
            Role::Validator => match &result.validator {
                Some(proof) => ((&self.validator.0, self.validator.1), proof),
                None => return Ok(true),
            },
        };

        if !pk.verify_proof(input.as_slice(), proof) {
            return Ok(false);
        }

        let output = proof.proof_to_hash();
        let hash_as_float = self.hash_to_float(&output);
        let normalized_hash = hash_as_float / 2f64.powi(TRUNCATED_HASH_SIZE_IN_BITS as i32);

        let dist = Binomial::new(p, stakes as u64)?;

        let lower_bound = self.binomial_cdf_sum(*weight, dist);
        let upper_bound = self.binomial_cdf_sum(weight + 1, dist);

        Ok(normalized_hash >= lower_bound && normalized_hash < upper_bound)
    }
}

impl<P: Proof> DrawResult<P> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("Failed to serialize DrawResult")
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(slice, bincode::config::standard())
            .map(|(d, _)| d)
            .map_err(Error::from)
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

impl<H: Hasher, S: Prover> Drawer<H> for S {
    fn draw(&self, ctx: Context<H>, stakes: u32) -> Result<DrawResult<Self::Proof>> {
        ctx.draw(self, stakes)
    }
}

impl<H: Hasher, S: VerifyProof> VerifyDraw<H> for S {
    fn verify_draw(
        &self,
        ctx: Context<H>,
        stakes: u32,
        result: DrawResult<Self::Proof>,
    ) -> Result<bool> {
        ctx.verify(self, stakes, &result)
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

impl<P: Proof> Serialize for DrawResult<P> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let leader = self
            .leader
            .as_ref()
            .map(|(proof, weight)| (proof.to_bytes(), *weight));

        let validator = self
            .validator
            .as_ref()
            .map(|(proof, weight)| (proof.to_bytes(), *weight));

        (leader, validator).serialize(serializer)
    }
}

impl<'de, P: Proof> Deserialize<'de> for DrawResult<P> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        type DrawResultTuple = (Option<(Vec<u8>, u32)>, Option<(Vec<u8>, u32)>);

        let (leader, validator): DrawResultTuple = Deserialize::deserialize(deserializer)?;

        let leader = match leader {
            Some((bytes, weight)) => Some((
                P::from_slice(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))?,
                weight,
            )),
            None => None,
        };

        let validator = match validator {
            Some((bytes, weight)) => Some((
                P::from_slice(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))?,
                weight,
            )),
            None => None,
        };

        Ok(DrawResult { leader, validator })
    }
}
