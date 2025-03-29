use curv::elliptic::curves::{Curve, Point, Scalar};

pub struct PublicKey<E: Curve>(pub Point<E>);
pub struct PrivateKey<E: Curve>(pub Scalar<E>);
pub struct KeyPair<E: Curve> {
    pub public_key: PublicKey<E>,
    pub private_key: PrivateKey<E>,
}

impl<E: Curve> KeyPair<E> {
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
}

impl<E: Curve> From<&[Point<E>]> for PublicKey<E> {
    fn from(points: &[Point<E>]) -> Self {
        assert!(!points.is_empty(), "Public key points cannot be empty");
        Self(points.iter().sum())
    }
}

impl<E: Curve> From<&[Scalar<E>]> for PrivateKey<E> {
    fn from(scalars: &[Scalar<E>]) -> Self {
        assert!(!scalars.is_empty(), "Private key scalars cannot be empty");
        Self(scalars.iter().sum())
    }
}
