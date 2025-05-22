use statrs::distribution::{Binomial, DiscreteCDF};

use crate::crypto::keypair::{self, SecretKey, VrfProof};

type Result<T> = std::result::Result<T, Error>;

const TRUNCATED_HASH_SIZE: usize = 8;
const HASH_BITS: usize = TRUNCATED_HASH_SIZE * 8;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Keypair(#[from] keypair::Error),
}

pub struct VrfElector {
    secret_key: SecretKey,
    expected_num: u64,
}

impl VrfElector {
    pub fn new(secret_key: SecretKey, expected_num: u64) -> Self {
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
    ) -> Result<Option<(u32, VrfProof)>> {
        let vrf_proof = self.secret_key.prove(input.as_ref())?;
        let vrf_output: [u8; TRUNCATED_HASH_SIZE] = vrf_proof.output()[..TRUNCATED_HASH_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        let times_elected = self.calculate_elected_times(stakes, total_stakes, vrf_output);

        if times_elected > 0 {
            Ok(Some((times_elected, vrf_proof)))
        } else {
            Ok(None)
        }
    }

    fn calculate_elected_times(
        &self,
        stakes: u32,
        total_stakes: u32,
        hash: [u8; TRUNCATED_HASH_SIZE],
    ) -> u32 {
        let hash_value = u64::from_be_bytes(hash) as f64;

        for j in 0..=stakes {
            let threshold =
                self.calculate_threshold(stakes, total_stakes, j) * 2f64.powi(HASH_BITS as i32);

            if hash_value <= threshold {
                return j;
            }
        }

        0
    }

    fn calculate_threshold(&self, stakes: u32, total_stakes: u32, j: u32) -> f64 {
        let p = self.expected_num as f64 / total_stakes as f64;

        let dist = Binomial::new(p, stakes as u64).expect("Invalid binomial distribution");

        dist.cdf(j as u64)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::committee::vrf_elector::VrfElector;
    use crate::crypto::keypair::{self, KeyType};

    const MAX_DEVIATION: f64 = 0.2;
    const KEYTYPE: KeyType = KeyType::Secp256k1;
    const INPUT: &[u8] = b"test input";

    #[rstest]
    #[case([100; 50].to_vec(), 5)]
    #[case([100; 50].to_vec(), 10)]
    #[case([100; 50].to_vec(), 20)]
    #[case([100; 100].to_vec(), 10)]
    fn reasonable_elected_nums(#[case] stakes_array: Vec<u32>, #[case] expected_num: u64) {
        const ITERATIONS: usize = 5;

        let total_stakes: u32 = stakes_array.iter().sum();

        let mut total_elected = 0;

        for _ in 0..ITERATIONS {
            let mut iteration_elected = 0;

            for &stakes in &stakes_array {
                let (sk, _) = keypair::generate_keypair(KEYTYPE);
                let elector = VrfElector::new(sk, expected_num);

                let result = elector.generate(INPUT, stakes, total_stakes).unwrap();
                iteration_elected += result.map_or(0, |(num, _)| num);
            }

            total_elected += iteration_elected;
        }

        let average_elected = total_elected as f64 / ITERATIONS as f64;

        let deviation = (average_elected - expected_num as f64).abs() / expected_num as f64;

        assert!(
            deviation <= MAX_DEVIATION,
            "Deviation is too high, expected: {expected_num}, average actual: {average_elected}, deviation: {deviation}"
        );
    }
}
