use std::{collections::HashMap, hash::Hash};

use crate::traits::{serializable, Serializable};

#[derive(Clone)]
#[derive(Debug)]
pub struct QuorumCertificate<T, P, S> {
    pub view: T,
    pub sigs: HashMap<P, S>,
}

impl<T, P, S> Default for QuorumCertificate<T, P, S>
where
    T: Default,
{
    fn default() -> Self {
        QuorumCertificate {
            view: T::default(),
            sigs: HashMap::default(),
        }
    }
}

impl<T, P, S> Serializable for QuorumCertificate<T, P, S>
where
    T: Serializable,
    P: Serializable + Eq + Hash,
    S: Serializable,
{
    fn serialized_size(&self) -> usize {
        self.view.serialized_size() + self.sigs.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(QuorumCertificate {
            view: T::from_reader(reader)?,
            sigs: HashMap::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.view.to_writer(writer)?;
        self.sigs.to_writer(writer)?;

        Ok(())
    }
}
