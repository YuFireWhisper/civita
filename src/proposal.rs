use std::{collections::HashMap, fmt::Display};

use crate::constants::HashArray;

pub struct Diff {
    pub impacted_residents: Vec<HashArray>,
    pub total_stakes: i32,
}

pub trait Proposal: Sized {
    type Error: Display;

    fn verify(&self, current: &mut HashMap<HashArray, Vec<u8>>) -> Result<bool, Self::Error>;
    fn diff(&self) -> Result<Diff, Self::Error>;
    fn from_slice(slice: &[u8]) -> Result<Self, Self::Error>;
    fn to_vec(&self) -> Result<Vec<u8>, Self::Error>;
}
