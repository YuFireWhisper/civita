pub mod point;
pub mod scalar;

pub use point::Point;
pub use scalar::Scalar;

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

    #[error("Scalar cannot be zero")]
    ZeroScalar,

    #[error("Point cannot be zero")]
    ZeroPoint,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
pub enum Scheme {
    Secp256k1,
}
