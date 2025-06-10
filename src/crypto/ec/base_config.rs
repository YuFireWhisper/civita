use ark_ec::short_weierstrass::SWCurveConfig;

use crate::crypto::traits::Hasher;

pub trait BaseConfig: SWCurveConfig {
    type Hasher: Hasher;
}
