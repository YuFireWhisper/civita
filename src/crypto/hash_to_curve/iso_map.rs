use ark_ec::short_weierstrass::SWCurveConfig;

pub trait IsoMap: SWCurveConfig {
    fn iso_map(x: Self::BaseField, y: Self::BaseField) -> (Self::BaseField, Self::BaseField);
}
