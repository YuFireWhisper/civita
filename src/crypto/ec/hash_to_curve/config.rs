use crate::crypto::ec::{
    base_config::BaseConfig,
    hash_to_curve::{expand_message::ExpandMessage, map_to_curve::MapToCurve},
};

pub trait Config: BaseConfig + MapToCurve<Self::BaseField> {
    const ACTUAL_A: Self::BaseField;
    const ACTUAL_B: Self::BaseField;

    const L: usize;
    const Z: Self::BaseField;

    const DST: &'static [u8];

    type ExpandMessage: ExpandMessage<Self::Hasher>;
}
