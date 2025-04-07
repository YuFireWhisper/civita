use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::dkg::classic::{config::ThresholdCounter, Signature};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Keypair<E: curv::elliptic::curves::Curve> {
    public_key: curv::elliptic::curves::Point<E>,
    private_key: curv::elliptic::curves::Scalar<E>,
}

impl<E: curv::elliptic::curves::Curve> Keypair<E> {
    pub fn new(
        public_key: curv::elliptic::curves::Point<E>,
        private_key: curv::elliptic::curves::Scalar<E>,
    ) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn public_key(&self) -> &curv::elliptic::curves::Point<E> {
        &self.public_key
    }

    pub fn private_key(&self) -> &curv::elliptic::curves::Scalar<E> {
        &self.private_key
    }

    pub fn random() -> Self {
        let private_key = curv::elliptic::curves::Scalar::random();
        let public_key = curv::elliptic::curves::Point::generator() * &private_key;

        Self {
            public_key,
            private_key,
        }
    }

    pub fn related_random<H: Digest + Clone, F: ThresholdCounter>(
        num: u16,
        threshold_counter: F,
    ) -> Vec<Self> {
        use curv::{
            cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
            elliptic::curves::{Point, Scalar},
        };

        let threshold = threshold_counter.call(num);
        let mut pri_key_shares: HashMap<u16, Vec<Scalar<E>>> = HashMap::new();
        let mut pub_key_shares = Vec::with_capacity(num as usize);

        for _ in 0..num {
            let scalar = Scalar::random();
            let (vss, shares) = VerifiableSS::<E, H>::share(threshold, num, &scalar);

            for (j, share) in shares.iter().enumerate() {
                pri_key_shares
                    .entry(j as u16)
                    .or_default()
                    .push(share.to_owned());
            }

            let pub_key_share = vss.commitments[0].to_owned();
            pub_key_shares.push(pub_key_share);
        }

        let pub_key = pub_key_shares.iter().sum::<Point<E>>();
        let mut keypairs: Vec<Keypair<E>> = Vec::with_capacity(num as usize);

        while keypairs.len() < num as usize {
            let pri_key_share = pri_key_shares
                .remove(&(keypairs.len() as u16))
                .expect("Missing private key share");
            let pri_key: Scalar<E> = pri_key_share.iter().sum();
            let keypair = Keypair::new(pub_key.clone(), pri_key);
            keypairs.push(keypair);
        }

        keypairs
    }

    pub fn sign(&self, seed: &[u8], msg: &[u8]) -> Signature<E> {
        Signature::generate::<Sha256>(seed, msg, self)
    }

    pub fn validate(&self, msg: &[u8], sig: &Signature<E>) -> bool {
        sig.validate::<Sha256>(msg, &self.public_key)
    }
}
