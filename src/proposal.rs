use crate::network::{connection::Connection, record::Record};

pub trait Proposal: TryFrom<Vec<u8>> + TryInto<Vec<u8>> {
    type Error: std::error::Error;
    type CustomValue;

    fn validate<C: Connection>(&self, connection: &C) -> Result<bool, <Self as Proposal>::Error>;
    fn to_record<C: Connection>(
        &self,
        connection: &C,
    ) -> Result<Record<Self::CustomValue, Self>, <Self as Proposal>::Error>;
}
