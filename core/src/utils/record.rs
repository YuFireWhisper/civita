use std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, AddAssign},
};

use civita_serialize::Serialize;

pub trait Weight:
    Add<Output = Self>
    + AddAssign
    + Sum
    + Clone
    + Copy
    + Debug
    + Default
    + Eq
    + Ord
    + Serialize
    + Send
    + Sync
    + 'static
{
    fn mul_f64(self, factor: f64) -> Self;
}

pub trait Operation: Clone + Eq + Serialize + Send + Sync + 'static {
    fn is_empty(&self) -> bool;
    fn is_order_dependent(&self, key: &[u8]) -> bool;
}

pub trait Record:
    Clone + Default + Eq + Serialize + Send + Sync + 'static + std::fmt::Debug
{
    type Weight: Weight;
    type Operation: Operation;

    fn weight(&self) -> Self::Weight;
    fn try_apply(&mut self, operation: Self::Operation) -> bool;
}

impl Weight for u64 {
    fn mul_f64(self, factor: f64) -> Self {
        (self as f64 * factor) as Self
    }
}
