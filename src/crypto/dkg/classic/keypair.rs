use std::ops::{Add, Mul};

use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct PublicKey<E: Curve>(pub Point<E>);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct PrivateKey<E: Curve>(pub Scalar<E>);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Keypair<E: Curve> {
    pub public_key: PublicKey<E>,
    #[serde(skip)]
    pub private_key: PrivateKey<E>,
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

impl<E: Curve> PrivateKey<E> {
    pub fn aggrege<H: Digest + Clone>(indices: &[u16], shares: &[Scalar<E>]) -> Self {
        assert_eq!(
            indices.len(),
            shares.len(),
            "Indices and shares must have the same length"
        );

        let points = to_scalars(indices);
        VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, shares).into()
    }
}

pub fn to_scalars<E, T>(points: &[T]) -> Vec<Scalar<E>>
where
    E: Curve,
    T: Into<Scalar<E>> + Copy,
{
    points.iter().map(|p| (*p).into()).collect()
}

impl<E: Curve> Keypair<E> {
    pub fn new(public_key: impl Into<PublicKey<E>>, private_key: impl Into<PrivateKey<E>>) -> Self {
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

    pub fn private_key(&self) -> &PrivateKey<E> {
        &self.private_key
    }

    pub fn random() -> Self {
        let scalar = Scalar::random();
        let point = Point::generator() * &scalar;

        let public_key = PublicKey(point);
        let private_key = PrivateKey(scalar);

        Self {
            public_key,
            private_key,
        }
    }
}

impl<E: Curve> Default for PublicKey<E> {
    fn default() -> Self {
        Self(Point::zero())
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

impl<E: Curve> Mul<&Scalar<E>> for &PublicKey<E> {
    type Output = Point<E>;

    fn mul(self, scalar: &Scalar<E>) -> Self::Output {
        &self.0 * scalar
    }
}

impl<E: Curve> Default for PrivateKey<E> {
    fn default() -> Self {
        Self(Scalar::zero())
    }
}

impl<E: Curve> From<Scalar<E>> for PrivateKey<E> {
    fn from(scalar: Scalar<E>) -> Self {
        Self(scalar)
    }
}

impl<E: Curve> From<&[Scalar<E>]> for PrivateKey<E> {
    fn from(scalars: &[Scalar<E>]) -> Self {
        assert!(!scalars.is_empty(), "Private key scalars cannot be empty");
        Self(scalars.iter().sum())
    }
}

impl<E: Curve> Mul<&PrivateKey<E>> for Scalar<E> {
    type Output = Scalar<E>;

    fn mul(self, private_key: &PrivateKey<E>) -> Self::Output {
        self * &private_key.0
    }
}

impl<E: Curve> Mul<&Scalar<E>> for PrivateKey<E> {
    type Output = Scalar<E>;

    fn mul(self, scalar: &Scalar<E>) -> Self::Output {
        self.0 * scalar
    }
}

impl<E: Curve> Default for Keypair<E> {
    fn default() -> Self {
        let public_key = PublicKey::default();
        let private_key = PrivateKey::default();
        Self {
            public_key,
            private_key,
        }
    }
}
