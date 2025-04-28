use crate::network::{connection::Connection, record::RecordValue};

pub trait ToRecord {
    type Error: std::error::Error;
}

pub trait Proposal {
    type Error: std::error::Error;
    type CustomValue;

    fn validate<C: Connection>(&self, connection: &C) -> Result<bool, Self::Error>;
    fn to_record<C: Connection>(
        &self,
        connection: &C,
    ) -> Result<RecordValue<Self::CustomValue, Self>, Self::Error>
    where
        Self: Sized;
}
