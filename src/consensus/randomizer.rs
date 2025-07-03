use statrs::distribution::{Binomial, DiscreteCDF};

use crate::{
    crypto::{self, Hasher, Multihash},
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
    Serializable(#[from] serializable::Error),
}

pub struct Randomizer {
    expected_leaders: u16,
    expected_validators: u16,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct DrawProof {
    pub proof: crypto::Proof,
    pub weight: u32,
}

impl Randomizer {
    pub fn new(expected_leaders: u16, expected_validators: u16) -> Self {
        Self {
            expected_leaders,
            expected_validators,
        }
    }

    pub fn draw<H: Hasher>(
        &self,
        seed: &[u8],
        total_stakes: u32,
        sk: &crypto::SecretKey,
        stakes: u32,
        is_leader: bool,
    ) -> Result<Option<DrawProof>> {
        if total_stakes == 0 || stakes == 0 {
            return Ok(None);
        }

        let input = Self::generate_input::<H>(seed, is_leader);
        let p = self.calc_p(total_stakes, is_leader);

        if !self.is_status_valid(p) {
            return Ok(None);
        }

        let proof = sk.prove(input.digest());
        let output = proof.to_hash();

        let hash_as_float = self.hash_to_float(output.digest());

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

    fn generate_input<H: Hasher>(seed: &[u8], is_leader: bool) -> Multihash {
        let mut bytes = Vec::with_capacity(seed.len() + 1);
        bytes.extend(seed);
        bytes.push(is_leader as u8);
        H::hash(&bytes)
    }

    fn calc_p(&self, total_stakes: u32, is_leader: bool) -> f64 {
        let tau = if is_leader {
            self.expected_leaders
        } else {
            self.expected_validators
        };
        (tau as f64) / (total_stakes as f64)
    }

    fn is_status_valid(&self, p: f64) -> bool {
        p > 0.0 && p < 1.0
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

    pub fn verify<H: Hasher>(
        &self,
        seed: &[u8],
        total_stakes: u32,
        pk: &crypto::PublicKey,
        stakes: u32,
        proof: &DrawProof,
        is_leader: bool,
    ) -> bool {
        if total_stakes == 0 {
            return false;
        }

        let input = Self::generate_input::<H>(seed, is_leader);
        let p = self.calc_p(total_stakes, is_leader);

        if !self.is_status_valid(p) {
            return false;
        }

        if !pk.verify_proof(input.digest(), &proof.proof) {
            return false;
        }

        let output = proof.proof.to_hash();
        let hash_as_float = self.hash_to_float(output.digest());
        let normalized_hash = hash_as_float / 2f64.powi(TRUNCATED_HASH_SIZE_IN_BITS as i32);

        let dist =
            Binomial::new(p, stakes as u64).expect("Invalid binomial distribution parameters");
        let lower_bound = self.binomial_cdf_sum(proof.weight, dist);
        let upper_bound = self.binomial_cdf_sum(proof.weight + 1, dist);

        normalized_hash >= lower_bound && normalized_hash < upper_bound
    }
}

impl Serializable for DrawProof {
    fn serialized_size(&self) -> usize {
        self.proof.serialized_size() + self.weight.serialized_size()
    }

    fn from_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::result::Result<Self, serializable::Error> {
        Ok(Self {
            proof: crypto::Proof::from_reader(reader)?,
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
