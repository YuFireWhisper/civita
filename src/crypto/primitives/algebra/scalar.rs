use curv::{
    arithmetic::Converter,
    elliptic::curves::{
        secp256_k1::Secp256k1 as CurvSecp256k1, Curve as CurvCurve, Point as CurvPoint,
        Scalar as CurvScalar,
    },
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
        self.scheme() == other.scheme()
    }

    pub fn is_same_type_point(&self, other: &Point) -> bool {
        self.scheme() == other.scheme()
    }

    pub fn get_secp256k1_raw(&self) -> Result<&CurvScalar<CurvSecp256k1>> {
        match self {
            Scalar::Secp256k1(scalar) => Ok(scalar),
        }
    }

    pub fn is_secp256k1(&self) -> bool {
        self.scheme() == Scheme::Secp256k1
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
        if scalar.is_zero() {
            return Err(Error::ZeroScalar);
        }

        let g = CurvPoint::<CurvSecp256k1>::generator();
        let s_point = g * scalar;
        let commitments = commitments
            .iter()
            .map(|point| {
                if !point.is_same_type_scalar(self) {
                    return Err(Error::InconsistentVariants);
                }
                if point.is_zero() {
                    return Err(Error::ZeroPoint);
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

    pub fn sum<'a, I: Iterator<Item = &'a Self>>(iter: I) -> Result<Self> {
        let mut iter = iter.peekable();
        let mut sum = iter.next().ok_or(Error::IteratorEmpty)?.clone();

        for scalar in iter {
            if !sum.is_same_type(scalar) {
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

    pub fn add(&self, other: &Self) -> Result<Self> {
        if !self.is_same_type(other) {
            return Err(Error::InconsistentVariants);
        }
        match (self, other) {
            (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2)) => Ok(Scalar::Secp256k1(s1 + s2)),
        }
    }

    pub fn mul(&self, scalar: &Self) -> Result<Self> {
        if !self.is_same_type(scalar) {
            return Err(Error::InconsistentVariants);
        }
        match (self, scalar) {
            (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2)) => Ok(Scalar::Secp256k1(s1 * s2)),
        }
    }

    pub fn scheme(&self) -> Scheme {
        match self {
            Scalar::Secp256k1(_) => Scheme::Secp256k1,
        }
    }

    pub fn lagrange_interpolation(indices: &[u16], values: &[Scalar]) -> Result<Self> {
        let scheme = values.first().ok_or(Error::IteratorEmpty)?.scheme();

        match scheme {
            Scheme::Secp256k1 => {
                let values = values
                    .iter()
                    .map(|scalar| scalar.get_secp256k1_raw())
                    .collect::<Result<Vec<_>>>()?;
                let result = Self::curv_lagrange_interpolation::<CurvSecp256k1>(indices, &values);
                Ok(Scalar::Secp256k1(result))
            }
        }
    }

    fn curv_lagrange_interpolation<E: CurvCurve>(
        indices: &[u16],
        scalars: &[&CurvScalar<E>],
    ) -> CurvScalar<E> {
        assert_eq!(
            indices.len(),
            scalars.len(),
            "Indices and scalars must have the same length"
        );

        let points = indices
            .iter()
            .map(|p| (*p).into())
            .collect::<Vec<CurvScalar<E>>>();

        let mut result = CurvScalar::<E>::zero();

        for (i, (xi, yi)) in points.iter().zip(scalars.iter()).enumerate() {
            let mut coeff = CurvScalar::<E>::from(1);
            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    let num = CurvScalar::<E>::zero() - xj;
                    let denom = xi - xj;
                    if !denom.is_zero() {
                        let term = num * &denom.invert().unwrap();
                        coeff = coeff * &term;
                    }
                }
            }

            result = result + (coeff * (*yi));
        }

        result
    }

    pub fn from_bytes(bytes: &[u8], scheme: &Scheme) -> Self {
        match scheme {
            Scheme::Secp256k1 => Self::from_bytes_secp256k1(bytes),
        }
    }

    fn from_bytes_secp256k1(bytes: &[u8]) -> Self {
        let bigint = curv::BigInt::from_bytes(bytes);
        let scalar = CurvScalar::<CurvSecp256k1>::from(bigint);
        Scalar::Secp256k1(scalar)
    }
}

impl From<CurvScalar<CurvSecp256k1>> for Scalar {
    fn from(scalar: CurvScalar<CurvSecp256k1>) -> Self {
        Scalar::Secp256k1(scalar)
    }
}

#[cfg(test)]
mod tests {
    use curv::{
        arithmetic::Converter,
        elliptic::curves::{secp256_k1::Secp256k1 as CurvSecp256k1, Scalar as CurvScalar},
    };

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
        (
            scalars.get(&DEFAULT_INDEX_ONE_BASE).unwrap().clone(),
            commitments,
        )
    }

    fn create_polynomial_points(
        coefficients: &[u16],
        evaluation_points: &[u16],
    ) -> (Vec<u16>, Vec<Scalar>) {
        let indices = evaluation_points.to_vec();
        let values = evaluation_points
            .iter()
            .map(|&x| {
                let mut y_value = 0u16;
                for (i, &coeff) in coefficients.iter().enumerate() {
                    y_value = y_value.wrapping_add((x as u32).pow(i as u32) as u16 * coeff);
                }

                let scalar = CurvScalar::<CurvSecp256k1>::from(y_value);
                Scalar::from(scalar)
            })
            .collect();

        (indices, values)
    }

    fn get_expected_secret(coefficients: &[u16]) -> Scalar {
        let secret = CurvScalar::<CurvSecp256k1>::from(coefficients[0]);
        Scalar::from(secret)
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
    fn verification_fails_with_zero_scalar() {
        let zero_scalar = Scalar::zero(Scheme::Secp256k1);
        let (_, commitments) = create_valid_scalar_and_commitments();
        let index = DEFAULT_INDEX_ONE_BASE;

        let result = zero_scalar.verify(index, &commitments);
        assert!(matches!(result, Err(Error::ZeroScalar)));
    }

    #[test]
    fn verification_fails_with_zero_commitments() {
        let zero_scalar = Scalar::random(&Scheme::Secp256k1);
        let zero_commitments = vec![Point::zero(Scheme::Secp256k1)];
        let index = DEFAULT_INDEX_ONE_BASE;

        let result = zero_scalar.verify(index, &zero_commitments);
        assert!(matches!(result, Err(Error::ZeroPoint)));
    }

    #[test]
    fn verification_fails_with_zero_scalar_and_commitments() {
        let zero_scalar = Scalar::zero(Scheme::Secp256k1);
        let zero_commitments = vec![Point::zero(Scheme::Secp256k1)];
        let index = DEFAULT_INDEX_ONE_BASE;

        let result = zero_scalar.verify(index, &zero_commitments);
        assert!(result.is_err());
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

        let scalars = [scalar1.clone(), scalar2.clone(), scalar3.clone()];
        let sum = Scalar::sum(scalars.iter()).unwrap();

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

        let result = Scalar::sum(empty_iter.iter());
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

    #[test]
    fn addition_of_scalars() {
        let scalar1 = Scalar::random(&DEFAULT_SCHEME);
        let scalar2 = Scalar::random(&DEFAULT_SCHEME);

        let sum = scalar1.add(&scalar2).unwrap();

        match (scalar1, scalar2) {
            (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2)) => {
                let expected_sum = Scalar::Secp256k1(s1 + s2);
                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn multiplication_of_scalars() {
        let scalar1 = Scalar::random(&DEFAULT_SCHEME);
        let scalar2 = Scalar::random(&DEFAULT_SCHEME);

        let product = scalar1.mul(&scalar2).unwrap();

        match (scalar1, scalar2) {
            (Scalar::Secp256k1(s1), Scalar::Secp256k1(s2)) => {
                let expected_product = Scalar::Secp256k1(s1 * s2);
                assert_eq!(product, expected_product);
            }
        }
    }

    #[test]
    fn return_correct_scheme() {
        let scalar = Scalar::random(&DEFAULT_SCHEME);
        assert_eq!(scalar.scheme(), DEFAULT_SCHEME);
    }

    #[test]
    fn interpolation_recovers_constant_polynomial() {
        let coefficients = [42];
        let evaluation_points = [1, 2, 3, 4];

        let (indices, values) = create_polynomial_points(&coefficients, &evaluation_points);
        let expected = get_expected_secret(&coefficients);

        let result = Scalar::lagrange_interpolation(&indices, &values).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn interpolation_matches_shares_from_vss() {
        const NUM_SHARES: u16 = 5;
        const THRESHOLD: u16 = 3;

        let (shares, _) = Vss::share(&Scheme::Secp256k1, THRESHOLD, NUM_SHARES);

        let mut indices = Vec::new();
        let mut values = Vec::new();
        for i in 1..=NUM_SHARES {
            indices.push(i);
            values.push(shares.get(&i).unwrap().clone());
        }

        let result = Scalar::lagrange_interpolation(&indices, &values).unwrap();

        let mut all_indices = Vec::new();
        let mut all_values = Vec::new();
        for i in 1..=NUM_SHARES {
            all_indices.push(i);
            all_values.push(shares.get(&i).unwrap().clone());
        }

        let reference = Scalar::lagrange_interpolation(&all_indices, &all_values).unwrap();

        assert_eq!(result, reference);
    }

    #[test]
    fn interpolation_with_zero_values_works() {
        let indices = vec![1u16, 2u16, 3u16];
        let values = vec![
            Scalar::zero(Scheme::Secp256k1),
            Scalar::zero(Scheme::Secp256k1),
            Scalar::zero(Scheme::Secp256k1),
        ];

        let result = Scalar::lagrange_interpolation(&indices, &values).unwrap();

        let expected = Scalar::zero(DEFAULT_SCHEME);
        assert_eq!(result, expected);
    }

    #[test]
    fn interpolation_at_x_equals_zero_recovers_secret() {
        const NUM_POINTS: usize = 5;

        let secret = Scalar::random(&DEFAULT_SCHEME);
        let random_coeff = Scalar::random(&DEFAULT_SCHEME);

        let mut indices = Vec::new();
        let mut values = Vec::new();

        for i in 1..=NUM_POINTS {
            let index = i as u16;
            indices.push(index);

            let index_scalar =
                Scalar::from_curv_secp256k1(CurvScalar::<CurvSecp256k1>::from(index));
            let term = match (random_coeff.clone(), index_scalar) {
                (Scalar::Secp256k1(r), Scalar::Secp256k1(i_scalar)) => {
                    Scalar::Secp256k1(r * &i_scalar)
                }
            };
            let value = secret.add(&term).unwrap();
            values.push(value);
        }

        let result = Scalar::lagrange_interpolation(&indices, &values).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn verify_lagrange_basis_polynomials_sum_to_one() {
        let indices = [1u16, 2u16, 3u16];
        let x_target = 0u16;

        let x_target = CurvScalar::<CurvSecp256k1>::from(x_target);
        let points = indices
            .iter()
            .map(|p| CurvScalar::<CurvSecp256k1>::from(*p))
            .collect::<Vec<_>>();

        let mut sum = CurvScalar::<CurvSecp256k1>::zero();

        for (i, xi) in points.iter().enumerate() {
            let mut term = CurvScalar::<CurvSecp256k1>::from(1);

            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    let num = x_target.clone() - xj;
                    let denom = xi - xj;
                    term = term * &(num * &denom.invert().unwrap());
                }
            }

            sum = sum + term;
        }

        let one = CurvScalar::<CurvSecp256k1>::from(1);
        assert_eq!(sum, one);
    }

    #[test]
    fn from_bytes_creates_valid_scalar() {
        let bytes = [1, 2, 3, 4, 5];

        let scalar = Scalar::from_bytes(&bytes, &Scheme::Secp256k1);

        assert!(scalar.is_secp256k1());

        let inner_scalar = scalar.get_secp256k1_raw().unwrap();

        let bigint = curv::BigInt::from_bytes(&bytes);
        let expected_scalar = CurvScalar::<CurvSecp256k1>::from(bigint);
        assert_eq!(*inner_scalar, expected_scalar);
    }

    #[test]
    fn from_bytes_with_zero_bytes_creates_zero_scalar() {
        let bytes = [0, 0, 0, 0];
        let zero = Scalar::zero(Scheme::Secp256k1);

        let result = Scalar::from_bytes(&bytes, &Scheme::Secp256k1);

        assert_eq!(result, zero);
    }
}
