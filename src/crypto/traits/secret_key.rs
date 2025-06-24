use std::fmt::Debug;

use crate::traits::serializable::{ConstantSize, Serializable};

pub trait SecretKey:
    Clone + Debug + Eq + Serializable + ConstantSize + Sync + Send + 'static
{
    type PublicKey;

    fn random() -> Self;
    fn public_key(&self) -> Self::PublicKey;
}
