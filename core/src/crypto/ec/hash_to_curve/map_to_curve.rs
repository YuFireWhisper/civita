pub mod simple_swu;

pub trait MapToCurve<F> {
    fn map_to_curve(u: F) -> (F, F);
}
