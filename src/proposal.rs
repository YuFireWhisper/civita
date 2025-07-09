use std::{collections::BTreeMap, sync::OnceLock};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, Signature},
    resident,
    traits::{serializable, ConstantSize, Serializable},
    utils::mpt::Proof,
};

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub struct MultiProposal {
    pub code: u8,
    pub diff: BTreeMap<PublicKey, (Proof, resident::Record)>,
    pub total_stakes_diff: i32,
    pub initiator: PublicKey,
    pub initiator_data: Vec<u8>,
    pub initiator_sig: Signature,
    id_cache: OnceLock<Multihash>,
}

impl MultiProposal {
    pub fn base_verify<H: Hasher>(&self, root_hash: &Multihash) -> bool {
        if self.diff.is_empty() {
            return false;
        }

        for (pk, (proof, _)) in &self.diff {
            let key = pk.to_hash::<H>().to_bytes();
            if !proof.verify_with_key::<H>(root_hash, &key) {
                return false;
            }
        }

        let id = self.generate_id::<H>().to_bytes();

        if !self.initiator.verify_signature(&id, &self.initiator_sig) {
            return false;
        }

        true
    }

    pub fn generate_id<H: Hasher>(&self) -> Multihash {
        if let Some(id) = self.id_cache.get() {
            return *id;
        }

        let mut data = Vec::new();

        self.code
            .to_writer(&mut data)
            .expect("Failed to serialize code");

        for (pk, (_, record)) in &self.diff {
            pk.to_writer(&mut data)
                .expect("Failed to serialize public key");
            record
                .to_writer(&mut data)
                .expect("Failed to serialize record");
        }

        self.total_stakes_diff
            .to_writer(&mut data)
            .expect("Failed to serialize total stakes diff");
        self.initiator
            .to_writer(&mut data)
            .expect("Failed to serialize initiator");
        self.initiator_data
            .to_writer(&mut data)
            .expect("Failed to serialize initiator data");

        let id = H::hash(&data);
        self.id_cache.set(id).expect("Failed to set id cache");

        id
    }
}

impl Serializable for MultiProposal {
    fn serialized_size(&self) -> usize {
        u8::SIZE
            + self.diff.serialized_size()
            + self.total_stakes_diff.serialized_size()
            + self.initiator.serialized_size()
            + self.initiator_data.serialized_size()
            + self.initiator_sig.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            code: u8::from_reader(reader)?,
            diff: BTreeMap::<PublicKey, (Proof, resident::Record)>::from_reader(reader)?,
            total_stakes_diff: i32::from_reader(reader)?,
            initiator: PublicKey::from_reader(reader)?,
            initiator_data: Vec::from_reader(reader)?,
            initiator_sig: Signature::from_reader(reader)?,
            id_cache: OnceLock::new(),
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.code.to_writer(writer)?;
        self.diff.to_writer(writer)?;
        self.total_stakes_diff.to_writer(writer)?;
        self.initiator.to_writer(writer)?;
        self.initiator_data.to_writer(writer)?;
        self.initiator_sig.to_writer(writer)?;
        Ok(())
    }
}
