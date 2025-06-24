use std::{collections::HashMap, fmt::Display};

use crate::{constants::HashArray, mocks, resident, traits::serializable::Serializable};

// #[mockall::automock(type Error = mocks::MockError;)]
pub trait Proposal: Ord + Serializable + Sized + Send + Sync + 'static {
    type Error: Display;

    fn verify(&self, current: &HashMap<HashArray, resident::Record>) -> Result<bool, Self::Error>;
    fn apply(&self, current: &mut HashMap<HashArray, resident::Record>) -> Result<(), Self::Error>;
    fn impact(&self) -> Result<Vec<HashArray>, Self::Error>;
    fn impact_stakes(&self) -> Result<i32, Self::Error>;
}

// impl Eq for MockProposal {}
//
// impl PartialEq for MockProposal {
//     fn eq(&self, other: &Self) -> bool {
//         self.to_vec().unwrap() == other.to_vec().unwrap()
//     }
// }
//
// impl Ord for MockProposal {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.to_vec().unwrap().cmp(&other.to_vec().unwrap())
//     }
// }
//
// impl PartialOrd for MockProposal {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         Some(self.cmp(other))
//     }
// }
