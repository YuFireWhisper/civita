use std::{
    iter::Sum,
    ops::{Add, Mul, Sub},
};

use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Generator, Point, Scalar},
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::crypto::dkg::classic::config::ThresholdCounter;

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
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes(true).to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let point = Point::from_bytes(bytes).expect("Invalid public key bytes");
        Self(point)
    }
}

impl<E: Curve> Secret<E> {
    pub fn aggrege(indices: &[u16], shares: &[Secret<E>]) -> Self {
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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self)
    }

    pub fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Secret::default(), |acc, s| &acc + &s)
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
        let mut pri_key_shares = vec![Vec::with_capacity(num as usize); num as usize];
        let mut pub_key_shares = Vec::with_capacity(num as usize);

        for _ in 0..num {
            let scalar = Scalar::random();
            let (vss, shares) = VerifiableSS::<E, H>::share(threshold, num, &scalar);

            for (j, share) in shares.iter().enumerate() {
                pri_key_shares[j].push(share.clone().into());
            }

            let pub_key_share = PublicKey::from(vss.commitments.into_iter().next().unwrap());
            pub_key_shares.push(pub_key_share);
        }

        let pub_key = PublicKey::from(pub_key_shares);

        let mut keypairs: Vec<Keypair<E>> = Vec::with_capacity(num as usize);

        while keypairs.len() < num as usize {
            let pri_key_share = pri_key_shares.remove(0);
            let pri_key = Secret::sum(pri_key_share.into_iter());
            let keypair = Keypair::new(pub_key.clone(), pri_key);
            keypairs.push(keypair);
        }

        keypairs
    }
}

impl<E: Curve> Default for PublicKey<E> {
    fn default() -> Self {
        Self(Point::zero())
    }
}

impl<E: Curve> From<&[PublicKey<E>]> for PublicKey<E> {
    fn from(pub_keys: &[PublicKey<E>]) -> Self {
        assert!(!pub_keys.is_empty(), "Public key points cannot be empty");
        let point = pub_keys.iter().map(|pk| &pk.0).sum();
        Self(point)
    }
}

impl<E: Curve> From<Vec<PublicKey<E>>> for PublicKey<E> {
    fn from(pub_keys: Vec<PublicKey<E>>) -> Self {
        assert!(!pub_keys.is_empty(), "Public key points cannot be empty");
        let point = pub_keys.into_iter().map(|pk| pk.0).sum();
        Self(point)
    }
}

impl<E: Curve> From<Point<E>> for PublicKey<E> {
    fn from(point: Point<E>) -> Self {
        Self(point)
    }
}

impl<E: Curve> From<&[Point<E>]> for PublicKey<E> {
    fn from(points: &[Point<E>]) -> Self {
        assert!(!points.is_empty(), "Public key points cannot be empty");
        Self(points.iter().sum())
    }
}

impl<E: Curve> From<Vec<Point<E>>> for PublicKey<E> {
    fn from(points: Vec<Point<E>>) -> Self {
        assert!(!points.is_empty(), "Public key points cannot be empty");
        Self(points.into_iter().sum())
    }
}

impl<E: Curve> From<&PublicKey<E>> for Vec<u8> {
    fn from(public_key: &PublicKey<E>) -> Self {
        public_key.0.to_bytes(true).to_vec()
    }
}

impl<E: Curve> Add<&Point<E>> for &PublicKey<E> {
    type Output = Point<E>;

    fn add(self, point: &Point<E>) -> Self::Output {
        &self.0 + point
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

impl<E: Curve> From<Vec<u8>> for Secret<E> {
    fn from(bytes: Vec<u8>) -> Self {
        let scalar = Scalar::from_bytes(&bytes).expect("Invalid private key bytes");
        Self(scalar)
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

impl<E: Curve> Sum for Secret<E> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Secret::default(), |acc, s| &acc + &s)
    }
}

impl<E: Curve> Mul<&Secret<E>> for Scalar<E> {
    type Output = Scalar<E>;

    fn mul(self, private_key: &Secret<E>) -> Self::Output {
        self * &private_key.0
    }
}

impl<E: Curve> Mul<&Scalar<E>> for Secret<E> {
    type Output = Scalar<E>;

    fn mul(self, scalar: &Scalar<E>) -> Self::Output {
        self.0 * scalar
    }
}

impl<E: Curve> Mul<Generator<E>> for &Secret<E> {
    type Output = Point<E>;

    fn mul(self, generator: Generator<E>) -> Self::Output {
        &self.0 * generator
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
