use crate::network::{
    connection::Connection,
    record::{RecordKey, RecordValue},
};

pub trait ToRecord<const N: usize> {
    type Error: std::error::Error;

    fn to_record(&self) -> Result<[(RecordKey, RecordValue); N], Self::Error>;
}

pub trait Proposal<const N: usize>: ToRecord<N> {
    type Error: std::error::Error;

    fn validate<C: Connection>(&self, connection: &C) -> Result<(), Self::Error>;
}
