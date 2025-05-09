use ark_ec::AffineRepr;
use ark_ff::Field;

pub mod sw;

pub trait MapToCurve {
    fn map_to_curve<F>(u: F) -> impl AffineRepr
    where
        F: Field;
}
