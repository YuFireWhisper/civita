use std::collections::BTreeSet;

use crate::{
    crypto::Multihash,
    traits::{serializable, Serializable},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Block<P, PK, S> {
    pub leader: (PK, S),
    pub proposals: BTreeSet<P>,
    pub executed_root_hash: Multihash,
    pub executed_total_stakes: u32,
}

impl<P, PK, S> Serializable for Block<P, PK, S>
where
    P: Serializable + Ord,
    PK: Serializable,
    S: Serializable,
{
    fn serialized_size(&self) -> usize {
        unimplemented!()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            leader: (PK::from_reader(reader)?, S::from_reader(reader)?),
            proposals: BTreeSet::from_reader(reader)?,
            executed_root_hash: Multihash::from_reader(reader)?,
            executed_total_stakes: u32::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.leader.0.to_writer(writer)?;
        self.leader.1.to_writer(writer)?;
        self.executed_root_hash.to_writer(writer)?;
        self.executed_total_stakes.to_writer(writer)?;
        self.proposals.to_writer(writer)?;
        Ok(())
    }
}
