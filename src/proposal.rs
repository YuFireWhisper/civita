use std::fmt::Display;

use crate::{
    crypto::Hasher, network::traits::Storage, resident, traits::serializable::Serializable,
    utils::mpt::Mpt,
};

#[async_trait::async_trait]
pub trait Proposal: Clone + Ord + Serializable + Sized + Send + Sync + 'static {
    type Error: Display;

    async fn verify<H: Hasher, S: Storage>(
        &self,
        records: &Mpt<resident::Record, S>,
    ) -> Result<bool, Self::Error>;
    async fn apply<H: Hasher, S: Storage>(
        &self,
        records: &mut Mpt<resident::Record, S>,
    ) -> Result<(), Self::Error>;
    fn impact_stakes(&self) -> Result<i32, Self::Error>;
}
