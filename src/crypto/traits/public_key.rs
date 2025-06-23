use std::{fmt::Debug, hash::Hash};

use crate::traits::serializable::Serializable;

pub trait PublicKey: Clone + Debug + Eq + Hash + Serializable + Sync + Send + 'static {}
