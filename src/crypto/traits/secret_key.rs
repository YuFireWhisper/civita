use std::fmt::Debug;

use crate::traits::serializable::Serializable;

pub trait SecretKey: Clone + Debug + Eq + Serializable + Sync + Send + 'static {
    type PublicKey;

    fn random() -> Self;
    fn public_key(&self) -> Self::PublicKey;
}
