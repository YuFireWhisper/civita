use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};

pub fn clear_cofactor<C: SWCurveConfig>(point: Affine<C>) -> Affine<C> {
    point.mul_by_cofactor()
}
