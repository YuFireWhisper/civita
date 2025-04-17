use curv::{
    elliptic::curves::secp256_k1::Secp256k1 as CurvSecp256k1,
    elliptic::curves::{Point as CurvPoint, Scalar as CurvScalar},
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
    pub fn random(scheme: &Scheme) -> Self {
        match scheme {
            Scheme::Secp256k1 => Point::secp256k1_random(),
        }
    }

    fn secp256k1_random() -> Self {
        let random_scalar = CurvScalar::<CurvSecp256k1>::random();
        let random_point = CurvPoint::<CurvSecp256k1>::generator() * random_scalar;
        Point::Secp256k1(random_point)
    }

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

    pub fn sum<'a, I: Iterator<Item = &'a Self>>(iter: I) -> Result<Self> {
        let mut iter = iter.peekable();
        let mut sum = iter.next().ok_or(Error::IteratorEmpty)?.clone();

        for next in iter {
            if !sum.is_same_type(next) {
                return Err(Error::InconsistentVariants);
            }
            sum = match (sum, next) {
                (Point::Secp256k1(s), Point::Secp256k1(n)) => Point::Secp256k1(s + n),
            };
        }

        Ok(sum)
    }
}

impl From<CurvPoint<CurvSecp256k1>> for Point {
    fn from(point: CurvPoint<CurvSecp256k1>) -> Self {
        Point::Secp256k1(point)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::primitives::algebra::{Point, Scalar, Scheme};

    const DEFAULT_SCHEME: Scheme = Scheme::Secp256k1;

    #[test]
    fn zero_create_additive_identity() {
        let zero_point = Point::zero(DEFAULT_SCHEME);
        let random_point = Point::random(&DEFAULT_SCHEME);

        match (zero_point, random_point.clone()) {
            (Point::Secp256k1(z), Point::Secp256k1(r)) => {
                let sum = Point::Secp256k1(z + r);
                assert_eq!(sum, random_point);
            }
        }
    }

    #[test]
    fn point_random_are_randomly_generated() {
        let point1 = Point::random(&DEFAULT_SCHEME);
        let point2 = Point::random(&DEFAULT_SCHEME);

        assert_ne!(point1, point2);
    }

    #[test]
    fn same_scheme_point_match_type() {
        let point1 = Point::random(&DEFAULT_SCHEME);
        let point2 = Point::random(&DEFAULT_SCHEME);

        assert!(point1.is_same_type(&point2));
    }

    #[test]
    fn same_scheme_point_match_scalar() {
        let point = Point::random(&DEFAULT_SCHEME);
        let scalar = Scalar::random(&DEFAULT_SCHEME);

        assert!(point.is_same_type_scalar(&scalar));
    }

    #[test]
    fn serialization_roundtrip_preserves_point_value() {
        let point = Point::random(&DEFAULT_SCHEME);
        let serialized = point.to_vec().unwrap();
        let deserialized = Point::from_slice(&serialized).unwrap();

        assert_eq!(point, deserialized);
    }

    #[test]
    fn deserialization_fails_on_invalid_data() {
        let invalid_data = vec![0, 1, 2, 3, 4, 5];
        let result = Point::from_slice(&invalid_data);

        assert!(result.is_err());
    }

    #[test]
    fn sum_of_points() {
        let point1 = Point::random(&DEFAULT_SCHEME);
        let point2 = Point::random(&DEFAULT_SCHEME);
        let point3 = Point::random(&DEFAULT_SCHEME);

        let points = vec![point1.clone(), point2.clone(), point3.clone()];
        let sum = Point::sum(points.iter()).unwrap();

        match (point1, point2, point3) {
            (Point::Secp256k1(p1), Point::Secp256k1(p2), Point::Secp256k1(p3)) => {
                let expected_sum = Point::Secp256k1(p1 + p2 + p3);
                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn sum_with_empty_iterator_returns_error() {
        let empty_iter: Vec<Point> = vec![];

        let result = Point::sum(empty_iter.iter());
        assert!(result.is_err());
    }

    #[test]
    fn from_trait_converts_curv_point_to_point() {
        let curv_point = curv::elliptic::curves::Point::zero();
        let point: Point = curv_point.clone().into();

        match point {
            Point::Secp256k1(p) => {
                assert_eq!(p, curv_point);
            }
        }
    }
}
