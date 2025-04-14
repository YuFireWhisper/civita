use std::iter::Sum;

use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Inconsistent variants")]
    InconsistentVariants,

    #[error("Iterator empty")]
    IteratorEmpty,
}

#[derive(Clone)]
#[derive(Debug)]
pub enum CryptoScheme {
    Secp256k1,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub enum Scalar {
    Secp256k1(curv::elliptic::curves::Scalar<curv::elliptic::curves::secp256_k1::Secp256k1>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub enum Point {
    Secp256k1(curv::elliptic::curves::Point<curv::elliptic::curves::secp256_k1::Secp256k1>),
}

impl Scalar {
    pub fn random(scheme: &CryptoScheme) -> Self {
        match scheme {
            CryptoScheme::Secp256k1 => Scalar::secp256k1_random(),
        }
    }

    pub fn zero(scheme: CryptoScheme) -> Self {
        match scheme {
            CryptoScheme::Secp256k1 => Scalar::secp256k1_zero(),
        }
    }

    pub fn secp256k1_random() -> Self {
        Scalar::Secp256k1(curv::elliptic::curves::Scalar::random())
    }

    pub fn secp256k1_zero() -> Self {
        Scalar::Secp256k1(curv::elliptic::curves::Scalar::zero())
    }

    pub fn is_same_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Scalar::Secp256k1(_), Scalar::Secp256k1(_)) => true,
        }
    }

    pub fn is_same_type_point(&self, other: &Point) -> bool {
        match (self, other) {
            (Scalar::Secp256k1(_), Point::Secp256k1(_)) => true,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map_err(Error::from)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(s, _)| s)
            .map_err(Error::from)
    }
}

impl Point {
    pub fn zero(scheme: CryptoScheme) -> Self {
        match scheme {
            CryptoScheme::Secp256k1 => Point::secp256k1_zero(),
        }
    }

    pub fn secp256k1_zero() -> Self {
        Point::Secp256k1(curv::elliptic::curves::Point::zero())
    }

    pub fn is_same_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Point::Secp256k1(_), Point::Secp256k1(_)) => true,
        }
    }

    pub fn is_same_type_scalar(&self, other: &Scalar) -> bool {
        match (self, other) {
            (Point::Secp256k1(_), Scalar::Secp256k1(_)) => true,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map_err(Error::from)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(s, _)| s)
            .map_err(Error::from)
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let first = iter.next().expect("Iterator is empty");
        match first {
            Scalar::Secp256k1(first_scalar) => {
                let sum = iter.fold(first_scalar, |acc, scalar| match scalar {
                    Scalar::Secp256k1(s) => acc + s,
                });
                Scalar::Secp256k1(sum)
            }
        }
    }
}

impl Sum for Point {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let first = iter.next().expect("Iterator is empty");
        match first {
            Point::Secp256k1(first_point) => {
                let sum = iter.fold(first_point, |acc, point| match point {
                    Point::Secp256k1(p) => acc + p,
                });
                Point::Secp256k1(sum)
            }
        }
    }
}
