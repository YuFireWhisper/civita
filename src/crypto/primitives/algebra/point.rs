use curv::{
    elliptic::curves::secp256_k1::Secp256k1 as CurvSecp256k1, elliptic::curves::Point as CurvPoint,
};
use serde::{Deserialize, Serialize};

use crate::crypto::primitives::algebra::{Error, Scalar, Scheme};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub enum Point {
    Secp256k1(CurvPoint<CurvSecp256k1>),
}

impl Point {
    pub fn zero(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Secp256k1 => Point::secp256k1_zero(),
        }
    }

    pub fn secp256k1_zero() -> Self {
        Point::Secp256k1(curv::elliptic::curves::Point::zero())
    }

    pub fn to_curv_secp256k1_point(&self) -> Result<CurvPoint<CurvSecp256k1>> {
        match self {
            Point::Secp256k1(point) => Ok(point.clone()),
        }
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

    pub fn sum<I: Iterator<Item = Self>>(iter: I) -> Result<Self> {
        let mut iter = iter.peekable();
        let mut sum = iter.next().ok_or(Error::IteratorEmpty)?;

        while let Some(next) = iter.next() {
            if !sum.is_same_type(&next) {
                return Err(Error::InconsistentVariants);
            }
            sum = match (sum, next) {
                (Point::Secp256k1(s), Point::Secp256k1(n)) => Point::Secp256k1(s + n),
            };
        }

        Ok(sum)
    }
}
