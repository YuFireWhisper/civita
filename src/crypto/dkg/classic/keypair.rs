use std::{
    collections::HashMap,
    iter::Sum,
    ops::{Add, Mul, Sub},
};

use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Generator, Point, Scalar},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::dkg::classic::{config::ThresholdCounter, Signature};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct PublicKey<E: Curve>(pub Point<E>);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Secret<E: Curve>(pub Scalar<E>);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Keypair<E: Curve> {
    public_key: PublicKey<E>,
    #[serde(skip)]
    private_key: Secret<E>,
}

impl<E: Curve> PublicKey<E> {
    pub fn aggrege(public_keys: &[PublicKey<E>]) -> Self {
        assert!(!public_keys.is_empty(), "Public keys cannot be empty");

        public_keys.iter().sum()
    }

    pub fn random() -> Self {
        let scalar = Scalar::random();
        let point = Point::generator() * &scalar;
        Self(point)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let point = Point::from_bytes(bytes).expect("Invalid public key bytes");
        Self(point)
    }

    pub fn from_point(point: Point<E>) -> Self {
        Self(point)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }
}

impl<E: Curve> Secret<E> {
    pub fn lagrange_interpolation(indices: &[u16], shares: &[Secret<E>]) -> Self {
        assert_eq!(
            indices.len(),
            shares.len(),
            "Indices and shares must have the same length"
        );

        let points = Self::u16_to_scalars(indices);
        let mut result = Scalar::zero();

        for (i, (xi, yi)) in points.iter().zip(shares.iter()).enumerate() {
            let mut lagrange_coeff = Scalar::from(1);

            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    let numerator = Scalar::zero() - xj;
                    let denominator = xi.clone() - xj;
                    if !denominator.is_zero() {
                        let term = numerator * &denominator.invert().unwrap();
                        lagrange_coeff = lagrange_coeff * &term;
                    }
                }
            }

            result = result + (lagrange_coeff * &yi.0);
        }

        Self(result)
    }

    fn u16_to_scalars(points: &[u16]) -> Vec<Scalar<E>> {
        points.iter().map(|p| (*p).into()).collect()
    }

    pub fn random() -> Self {
        let scalar = Scalar::random();
        Self(scalar)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes)
    }

    pub fn from_scalar(scalar: Scalar<E>) -> Self {
        Self(scalar)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }
}

impl<E: Curve> Keypair<E> {
    pub fn new(public_key: impl Into<PublicKey<E>>, private_key: impl Into<Secret<E>>) -> Self {
        let public_key = public_key.into();
        let private_key = private_key.into();

        Self {
            public_key,
            private_key,
        }
    }

    pub fn public_key(&self) -> &PublicKey<E> {
        &self.public_key
    }

    pub fn private_key(&self) -> &Secret<E> {
        &self.private_key
    }

    pub fn random() -> Self {
        let scalar = Scalar::random();
        let point = Point::generator() * &scalar;

        let public_key = PublicKey(point);
        let private_key = Secret(scalar);

        Self {
            public_key,
            private_key,
        }
    }

    pub fn related_random<H: Digest + Clone, F: ThresholdCounter>(
        num: u16,
        threshold_counter: F,
    ) -> Vec<Self> {
        let threshold = threshold_counter.call(num);
        let mut pri_key_shares: HashMap<u16, Vec<Secret<E>>> = HashMap::new();
        let mut pub_key_shares = Vec::with_capacity(num as usize);

        for _ in 0..num {
            let scalar = Scalar::random();
            let (vss, shares) = VerifiableSS::<E, H>::share(threshold, num, &scalar);

            for (j, share) in shares.iter().enumerate() {
                let pri_key_share = Secret::from_scalar(share.to_owned());
                pri_key_shares
                    .entry(j as u16)
                    .or_default()
                    .push(pri_key_share);
            }

            let pub_key_share = PublicKey::from(vss.commitments[0].to_owned());
            pub_key_shares.push(pub_key_share);
        }

        let pub_key = PublicKey::aggrege(&pub_key_shares);
        let mut keypairs: Vec<Keypair<E>> = Vec::with_capacity(num as usize);

        while keypairs.len() < num as usize {
            let pri_key_share = pri_key_shares
                .remove(&(keypairs.len() as u16))
                .expect("Missing private key share");
            let pri_key: Secret<E> = pri_key_share.iter().sum();
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

impl<E: Curve> Default for PublicKey<E> {
    fn default() -> Self {
        Self(Point::zero())
    }
}

impl<E: Curve> From<&PublicKey<E>> for Vec<u8> {
    fn from(value: &PublicKey<E>) -> Self {
        value.0.to_bytes(true).to_vec()
    }
}

impl<E: Curve> From<Point<E>> for PublicKey<E> {
    fn from(point: Point<E>) -> Self {
        Self(point)
    }
}

impl<E: Curve> Add<&PublicKey<E>> for &PublicKey<E> {
    type Output = PublicKey<E>;

    fn add(self, public_key: &PublicKey<E>) -> Self::Output {
        PublicKey(&self.0 + &public_key.0)
    }
}

impl<'a, E: Curve> Sum<&'a PublicKey<E>> for PublicKey<E> {
    fn sum<I: Iterator<Item = &'a PublicKey<E>>>(iter: I) -> Self {
        iter.fold(PublicKey::default(), |acc, pk| &acc + pk)
    }
}

impl<E: Curve> Sub<&Point<E>> for &PublicKey<E> {
    type Output = Point<E>;

    fn sub(self, point: &Point<E>) -> Self::Output {
        &self.0 - point
    }
}

impl<E: Curve> Mul<&Scalar<E>> for &PublicKey<E> {
    type Output = Point<E>;

    fn mul(self, scalar: &Scalar<E>) -> Self::Output {
        &self.0 * scalar
    }
}

impl<E: Curve> Default for Secret<E> {
    fn default() -> Self {
        Self(Scalar::zero())
    }
}

impl<E: Curve> From<&Secret<E>> for Vec<u8> {
    fn from(value: &Secret<E>) -> Self {
        value.0.to_bytes().to_vec()
    }
}

impl<E: Curve> From<&[u8]> for Secret<E> {
    fn from(bytes: &[u8]) -> Self {
        let scalar = Scalar::from_bytes(bytes).expect("Invalid private key bytes");
        Self(scalar)
    }
}

impl<E: Curve> From<Scalar<E>> for Secret<E> {
    fn from(scalar: Scalar<E>) -> Self {
        Self(scalar)
    }
}

impl<E: Curve> Add<&Secret<E>> for &Secret<E> {
    type Output = Secret<E>;

    fn add(self, private_key: &Secret<E>) -> Self::Output {
        Secret(&self.0 + &private_key.0)
    }
}

impl<'a, E: Curve> Sum<&'a Secret<E>> for Secret<E> {
    fn sum<I: Iterator<Item = &'a Secret<E>>>(iter: I) -> Self {
        iter.fold(Secret::default(), |acc, s| &acc + s)
    }
}

impl<E: Curve> Mul<&Secret<E>> for Scalar<E> {
    type Output = Scalar<E>;

    fn mul(self, private_key: &Secret<E>) -> Self::Output {
        self * &private_key.0
    }
}

impl<E: Curve> Mul<&Secret<E>> for Generator<E> {
    type Output = Point<E>;

    fn mul(self, private_key: &Secret<E>) -> Self::Output {
        self * &private_key.0
    }
}

impl<E: Curve> Default for Keypair<E> {
    fn default() -> Self {
        let public_key = PublicKey::default();
        let private_key = Secret::default();
        Self {
            public_key,
            private_key,
        }
    }
}
