use crate::{
    consensus::hot_stuff::utils::{Block, QuorumCertificate, ViewNumber},
    crypto::{Hasher, Multihash},
    traits::{serializable, Serializable},
};

#[derive(Clone)]
#[derive(Debug)]
pub struct View {
    pub number: ViewNumber,
    pub hash: Multihash,
    pub parent_hash: Multihash,
    pub block: Block,
    pub justify: QuorumCertificate,
}

impl View {
    pub fn new<H: Hasher>(
        number: ViewNumber,
        parent_hash: Multihash,
        block: Block,
        justify: QuorumCertificate,
    ) -> Self {
        let mut bytes = Vec::new();
        number.to_writer(&mut bytes).unwrap();
        parent_hash.to_writer(&mut bytes).unwrap();
        block.to_writer(&mut bytes).unwrap();
        justify.to_writer(&mut bytes).unwrap();

        let hash = H::hash(&bytes);

        Self {
            number,
            hash,
            parent_hash,
            block,
            justify,
        }
    }
}

impl Serializable for View {
    fn serialized_size(&self) -> usize {
        self.number.serialized_size()
            + self.hash.serialized_size()
            + self.parent_hash.serialized_size()
            + self.block.serialized_size()
            + self.justify.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            number: ViewNumber::from_reader(reader)?,
            hash: Multihash::from_reader(reader)?,
            parent_hash: Multihash::from_reader(reader)?,
            block: Block::from_reader(reader)?,
            justify: QuorumCertificate::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.number.to_writer(writer)?;
        self.hash.to_writer(writer)?;
        self.parent_hash.to_writer(writer)?;
        self.block.to_writer(writer)?;
        self.justify.to_writer(writer)?;
        Ok(())
    }
}
