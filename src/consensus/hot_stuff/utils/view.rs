use std::hash::Hash;

use crate::{
    consensus::hot_stuff::utils::{QuorumCertificate, ViewNumber},
    crypto::{traits::hasher::Multihash, Hasher},
    traits::{serializable, ConstantSize, Serializable},
};

#[derive(Clone)]
#[derive(Debug)]
pub struct View<T, P, S> {
    pub number: ViewNumber,
    pub hash: Multihash,
    pub parent_hash: Multihash,
    pub cmd: Option<T>,
    pub justify: Option<QuorumCertificate<Multihash, P, S>>,
}

impl<T, P, S> View<T, P, S>
where
    T: Serializable,
    P: Serializable + ConstantSize + Eq + Hash,
    S: Serializable + ConstantSize,
{
    pub fn new<H: Hasher>(
        number: ViewNumber,
        parent_hash: Multihash,
        cmd: Option<T>,
        justify: Option<QuorumCertificate<Multihash, P, S>>,
    ) -> Self {
        let mut bytes = Vec::new();
        number.to_writer(&mut bytes).unwrap();
        parent_hash.to_writer(&mut bytes).unwrap();
        cmd.to_writer(&mut bytes).unwrap();
        justify.to_writer(&mut bytes).unwrap();

        let hash = H::hash(&bytes);

        Self {
            number,
            hash,
            parent_hash,
            cmd,
            justify,
        }
    }
}

impl<T, P, S> Serializable for View<T, P, S>
where
    T: Serializable,
    P: Serializable + ConstantSize + Eq + Hash,
    S: Serializable + ConstantSize,
{
    fn serialized_size(&self) -> usize {
        self.number.serialized_size()
            + self.hash.serialized_size()
            + self.parent_hash.serialized_size()
            + self.cmd.serialized_size()
            + self.justify.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            number: ViewNumber::from_reader(reader)?,
            hash: Multihash::from_reader(reader)?,
            parent_hash: Multihash::from_reader(reader)?,
            cmd: Option::<T>::from_reader(reader)?,
            justify: Option::<QuorumCertificate<Multihash, P, S>>::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.number.to_writer(writer)?;
        self.hash.to_writer(writer)?;
        self.parent_hash.to_writer(writer)?;
        self.cmd.to_writer(writer)?;
        self.justify.to_writer(writer)?;

        Ok(())
    }
}
