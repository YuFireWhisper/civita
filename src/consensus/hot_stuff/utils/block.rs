use std::collections::{BTreeMap, HashMap};

use crate::{
    consensus::hot_stuff::utils::ProofPair,
    crypto::{Multihash, PublicKey},
    proposal::MultiProposal,
    traits::{serializable, Serializable},
    utils::mpt::Node,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Block {
    pub leader: (PublicKey, ProofPair),
    pub props: BTreeMap<Multihash, MultiProposal>,
    pub executed_root_hash: Multihash,
    pub executed_mpt_diff: HashMap<Multihash, Node>,
    pub executed_total_stakes: u32,
}

impl Serializable for Block {
    fn serialized_size(&self) -> usize {
        self.leader.serialized_size()
            + self.props.serialized_size()
            + self.executed_mpt_diff.serialized_size()
            + self.executed_root_hash.serialized_size()
            + self.executed_total_stakes.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        type Leader = (PublicKey, ProofPair);
        Ok(Block {
            leader: Leader::from_reader(reader)?,
            props: BTreeMap::from_reader(reader)?,
            executed_mpt_diff: HashMap::from_reader(reader)?,
            executed_root_hash: Multihash::from_reader(reader)?,
            executed_total_stakes: u32::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.leader.to_writer(writer)?;
        self.executed_root_hash.to_writer(writer)?;
        self.executed_mpt_diff.to_writer(writer)?;
        self.executed_total_stakes.to_writer(writer)?;
        self.props.to_writer(writer)?;
        Ok(())
    }
}
