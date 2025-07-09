use std::{fmt::Debug, hash::Hash};

use crate::traits::serializable::{ConstantSize, Serializable};

pub trait PublicKey:
    Clone + Debug + Eq + Hash + Serializable + ConstantSize + Sync + Send + 'static
{
}
