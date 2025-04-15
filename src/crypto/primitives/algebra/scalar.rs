use curv::{
    elliptic::curves::secp256_k1::Secp256k1 as CurvSecp256k1, elliptic::curves::Point as CurvPoint,
    elliptic::curves::Scalar as CurvScalar,
};
use serde::{Deserialize, Serialize};

use crate::crypto::primitives::algebra::{point::Point, Error, Scheme};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub enum Scalar {
    Secp256k1(CurvScalar<CurvSecp256k1>),
}

impl Scalar {
    pub fn random(scheme: &Scheme) -> Self {
        match scheme {
            Scheme::Secp256k1 => Scalar::secp256k1_random(),
        }
    }

    pub fn zero(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Secp256k1 => Scalar::secp256k1_zero(),
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

    pub fn verify(&self, index: u16, commitments: &[Point]) -> Result<bool> {
        match self {
            Scalar::Secp256k1(scalar) => self.verify_secp256k1(index, scalar, commitments),
        }
    }

    fn verify_secp256k1(
        &self,
        index: u16,
        scalar: &CurvScalar<CurvSecp256k1>,
        commitments: &[Point],
    ) -> Result<bool> {
        let g = CurvPoint::<CurvSecp256k1>::generator();
        let s_point = g * scalar;
        let commitments = commitments
            .iter()
            .map(|point| {
                if !point.is_same_type_scalar(self) {
                    return Err(Error::InconsistentVariants);
                }
                point.to_curv_secp256k1_point()
            })
            .collect::<Result<Vec<_>>>()?;
        let comm_to_point = Self::get_point_commitment(index, &commitments)?;
        if s_point == comm_to_point {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_point_commitment(
        index: u16,
        commitments: &[CurvPoint<CurvSecp256k1>],
    ) -> Result<CurvPoint<CurvSecp256k1>> {
        let index_fe = CurvScalar::<CurvSecp256k1>::from(index);
        let mut comm_iter = commitments.iter().rev();
        let head = comm_iter.next().ok_or(Error::IteratorEmpty)?;
        let tail = comm_iter;

        Ok(tail.fold(head.clone(), |acc, x| x + acc * &index_fe))
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

        while let Some(scalar) = iter.next() {
            if !sum.is_same_type(&scalar) {
                return Err(Error::InconsistentVariants);
            }
            match (sum, scalar) {
                (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2)) => {
                    sum = Scalar::Secp256k1(s1 + s2);
                }
            }
        }
        Ok(sum)
    }
}
