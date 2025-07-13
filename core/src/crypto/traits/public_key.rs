use std::{fmt::Debug, hash::Hash};

pub trait PublicKey: Clone + Debug + Eq + Hash + Sync + Send + 'static {}
