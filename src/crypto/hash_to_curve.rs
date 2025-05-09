use ark_ec::short_weierstrass::{Affine, SWCurveConfig};

use crate::crypto::hash_to_curve::map_to_curve::sw;

mod clear_cofactor;
mod expand_message_xmd;
mod hash_to_field;
mod map_to_curve;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    HashToField(#[from] hash_to_field::Error),
}

pub fn hash_to_curve<C: SWCurveConfig>(
    msg: impl AsRef<[u8]>,
    dst: impl AsRef<[u8]>,
    count: usize,
) -> Result<Vec<Affine<C>>> {
    let field_elements = hash_to_field::hash_to_field::<C::BaseField>(msg, dst, count)?;

    Ok(field_elements
        .into_iter()
        .map(|u| {
            let point = sw::map_to_curve::<C>(u);
            clear_cofactor::clear_cofactor(point)
        })
        .collect())
}
