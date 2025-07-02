use std::fmt::Display;

use crate::{crypto::Hasher, resident, traits::serializable::Serializable, utils::mpt::Mpt};

#[async_trait::async_trait]
pub trait Proposal: Clone + Ord + Serializable + Sized + Send + Sync + 'static {
    type Error: Display;

    async fn verify<H: Hasher>(&self, records: &Mpt<resident::Record>)
        -> Result<bool, Self::Error>;
    async fn apply<H: Hasher, P>(
        &self,
        records: &mut Mpt<resident::Record>,
    ) -> Result<(), Self::Error>;
    fn impact_stakes(&self) -> Result<i32, Self::Error>;
}
