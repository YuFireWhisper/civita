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

    pub fn from_curv_secp256k1(scalar: CurvScalar<CurvSecp256k1>) -> Self {
        Scalar::Secp256k1(scalar)
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

    pub fn get_secp256k1_raw(&self) -> Result<&CurvScalar<CurvSecp256k1>> {
        match self {
            Scalar::Secp256k1(scalar) => Ok(scalar),
        }
    }

    pub fn is_secp256k1(&self) -> bool {
        matches!(self, Scalar::Secp256k1(_))
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

        for scalar in iter {
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

impl From<CurvScalar<CurvSecp256k1>> for Scalar {
    fn from(scalar: CurvScalar<CurvSecp256k1>) -> Self {
        Scalar::Secp256k1(scalar)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::primitives::{
        algebra::{Error, Point, Scalar, Scheme},
        vss::Vss,
    };

    const DEFAULT_SCHEME: Scheme = Scheme::Secp256k1;
    const DEFAULT_INDEX_ONE_BASE: u16 = 1;

    fn create_valid_scalar_and_commitments() -> (Scalar, Vec<Point>) {
        const NUM_SHARES: u16 = 5;
        const THRESHOLD: u16 = 3;
        let (scalars, commitments) = Vss::share(&DEFAULT_SCHEME, THRESHOLD, NUM_SHARES);
        (scalars.get(&DEFAULT_INDEX_ONE_BASE).unwrap().clone(), commitments)
    }

    #[test]
    fn secp256k1_scalars_are_randomly_generated() {
        let scalar1 = Scalar::random(&Scheme::Secp256k1);
        let scalar2 = Scalar::random(&Scheme::Secp256k1);

        assert_ne!(scalar1, scalar2);
    }

    #[test]
    fn secp256k1_zero_creates_additive_identity() {
        let zero = Scalar::zero(Scheme::Secp256k1);
        let random = Scalar::random(&Scheme::Secp256k1);

        assert!(zero.is_secp256k1());

        match (zero, random.clone()) {
            (Scalar::Secp256k1(z), Scalar::Secp256k1(r)) => {
                let sum = Scalar::Secp256k1(z + r);
                assert_eq!(sum, random);
            }
        }
    }

    #[test]
    fn secp256k1_specific_factory_methods_work() {
        let random = Scalar::secp256k1_random();
        let zero = Scalar::secp256k1_zero();

        assert!(random.is_secp256k1());
        assert!(zero.is_secp256k1());
        assert_ne!(random, zero);
    }

    #[test]
    fn curv_secp256k1_scalar_conversion_preserves_value() {
        let curv_scalar = curv::elliptic::curves::Scalar::random();
        let scalar = Scalar::from_curv_secp256k1(curv_scalar.clone());

        match scalar {
            Scalar::Secp256k1(s) => {
                assert_eq!(s, curv_scalar);
            }
        }
    }

    #[test]
    fn same_scheme_scalars_match_types() {
        let scalar1 = Scalar::random(&DEFAULT_SCHEME);
        let scalar2 = Scalar::random(&DEFAULT_SCHEME);

        assert!(scalar1.is_same_type(&scalar2));
    }

    #[test]
    fn same_scheme_scalar_match_point() {
        let scalar = Scalar::random(&DEFAULT_SCHEME);
        let point = Point::zero(DEFAULT_SCHEME);

        assert!(scalar.is_same_type_point(&point));
    }

    #[test]
    fn secp256k1_raw_accessor_returns_underlying_scalar() {
        let curv_scalar = curv::elliptic::curves::Scalar::random();
        let scalar = Scalar::from_curv_secp256k1(curv_scalar.clone());

        let raw = scalar.get_secp256k1_raw().unwrap();
        assert_eq!(raw, &curv_scalar);
    }

    #[test]
    fn secp256k1_type_check_identifies_variant() {
        let scalar = Scalar::random(&Scheme::Secp256k1);
        assert!(scalar.is_secp256k1());
    }

    #[test]
    fn verification_succeeds_with_valid_commitments() {
        let (scalar, commitments) = create_valid_scalar_and_commitments();
        let index = DEFAULT_INDEX_ONE_BASE;

        let result = scalar.verify(index, &commitments);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn verification_fails_with_invalid_commitments() {
        let (scalar, _) = create_valid_scalar_and_commitments();
        let invalid_commitments = vec![Point::zero(Scheme::Secp256k1)];

        let result = scalar.verify(DEFAULT_INDEX_ONE_BASE, &invalid_commitments);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn serialization_roundtrip_preserves_scalar_value() {
        let original = Scalar::random(&DEFAULT_SCHEME);

        let bytes = original.to_vec().unwrap();
        let deserialized = Scalar::from_slice(&bytes).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn sum_of_scalars_produces_correct_result() {
        let scalar1 = Scalar::random(&DEFAULT_SCHEME);
        let scalar2 = Scalar::random(&DEFAULT_SCHEME);
        let scalar3 = Scalar::random(&DEFAULT_SCHEME);

        let scalars = vec![scalar1.clone(), scalar2.clone(), scalar3.clone()];
        let sum = Scalar::sum(scalars.into_iter()).unwrap();

        match (scalar1, scalar2, scalar3) {
            (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2), Scalar::Secp256k1(s3)) => {
                let expected_sum = Scalar::Secp256k1(s1 + s2 + s3);
                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn sum_with_empty_iterator_returns_error() {
        let empty_iter: Vec<Scalar> = vec![];

        let result = Scalar::sum(empty_iter.into_iter());
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::IteratorEmpty => {}
            _ => panic!("Expected IteratorEmpty error"),
        }
    }

    #[test]
    fn from_trait_converts_curv_scalar_to_scalar() {
        let curv_scalar = curv::elliptic::curves::Scalar::random();
        let scalar: Scalar = curv_scalar.clone().into();

        match scalar {
            Scalar::Secp256k1(s) => {
                assert_eq!(s, curv_scalar);
            }
        }
    }
}
