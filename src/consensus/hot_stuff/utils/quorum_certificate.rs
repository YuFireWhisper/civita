use std::{collections::HashMap, hash::Hash};

use crate::traits::{serializable, Serializable};

#[derive(Clone)]
#[derive(Debug, Default)]
pub struct QuorumCertificate<N, P, S> {
    pub view: N,
    pub sigs: HashMap<P, S>,
}

impl<N, P, S> Serializable for QuorumCertificate<N, P, S>
where
    N: Serializable,
    P: Serializable + Eq + Hash,
    S: Serializable,
{
    fn serialized_size(&self) -> usize {
        self.view.serialized_size() + self.sigs.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(QuorumCertificate {
            view: N::from_reader(reader)?,
            sigs: HashMap::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.view.to_writer(writer)?;
        self.sigs.to_writer(writer)?;

        Ok(())
    }
}
