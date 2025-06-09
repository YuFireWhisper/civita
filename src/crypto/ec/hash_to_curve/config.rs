use ark_ec::short_weierstrass::SWCurveConfig;

use crate::crypto::ec::hash_to_curve::{expand_message::ExpandMessage, map_to_curve::MapToCurve};

pub trait Config: SWCurveConfig + MapToCurve<Self::BaseField> {
    const ACTUAL_A: Self::BaseField;
    const ACTUAL_B: Self::BaseField;

    const L: usize;
    const Z: Self::BaseField;

    const DST: &'static [u8];

    type ExpandMessage: ExpandMessage;
}
