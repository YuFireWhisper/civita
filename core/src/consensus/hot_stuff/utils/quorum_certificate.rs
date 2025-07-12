use std::collections::HashMap;

use crate::{
    consensus::hot_stuff::utils::ProofPair,
    crypto::{Multihash, PublicKey, Signature},
    traits::{serializable, Serializable},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
pub struct QuorumCertificate {
    pub view: Multihash,
    pub proofs: HashMap<PublicKey, (ProofPair, Signature)>,
}

impl Serializable for QuorumCertificate {
    fn serialized_size(&self) -> usize {
        self.view.serialized_size() + self.proofs.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(QuorumCertificate {
            view: Multihash::from_reader(reader)?,
            proofs: HashMap::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.view.to_writer(writer)?;
        self.proofs.to_writer(writer)?;

        Ok(())
    }
}
