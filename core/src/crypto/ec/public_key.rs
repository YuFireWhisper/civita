use ark_ec::short_weierstrass::{Affine, SWCurveConfig};

use crate::crypto::traits::PublicKey;

impl<C: SWCurveConfig> PublicKey for Affine<C> {}
