use std::{collections::HashMap, hash::Hash};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct QuorumCertificate<T, P, S>
where
    P: Eq + Hash,
{
    pub view_number: u64,
    pub node: T,
    pub sig: HashMap<P, S>,
}
