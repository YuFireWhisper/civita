use std::collections::BTreeSet;

use crate::traits::{serializable, ConstantSize, Serializable};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Block<H, P> {
    pub root_hash: H,
    pub total_stakes: u32,
    pub proposals: BTreeSet<P>,
}

impl<H, P> Serializable for Block<H, P>
where
    H: Serializable + ConstantSize,
    P: Serializable + Ord,
{
    fn serialized_size(&self) -> usize {
        unimplemented!()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Block {
            root_hash: H::from_reader(reader)?,
            total_stakes: u32::from_reader(reader)?,
            proposals: BTreeSet::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.root_hash.to_writer(writer)?;
        self.total_stakes.to_writer(writer)?;
        self.proposals.to_writer(writer)?;

        Ok(())
    }
}
