use std::{collections::HashMap, fmt::Display};

use crate::{constants::HashArray, mocks, resident};

pub mod collector;
pub mod pool;
pub mod publisher;
pub mod system;
pub mod vrf_elector;

#[mockall::automock(type Error = mocks::MockError;)]
pub trait Proposal: Sized + Send + Sync + 'static {
    type Error: Display;

    fn verify(&self, current: &HashMap<HashArray, resident::Record>) -> Result<bool, Self::Error>;
    fn apply(&self, current: &mut HashMap<HashArray, resident::Record>) -> Result<(), Self::Error>;
    fn impact(&self) -> Result<Vec<HashArray>, Self::Error>;
    fn impact_stakes(&self) -> Result<i32, Self::Error>;
    fn from_slice(slice: &[u8]) -> Result<Self, Self::Error>;
    fn to_vec(&self) -> Result<Vec<u8>, Self::Error>;
}
