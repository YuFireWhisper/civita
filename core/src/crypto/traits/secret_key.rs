use std::fmt::Debug;

use civita_serialize::Serialize;

pub trait SecretKey: Clone + Debug + Eq + Serialize + Sync + Send + 'static {
    type PublicKey;

    fn random() -> Self;
    fn public_key(&self) -> Self::PublicKey;
}
