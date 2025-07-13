use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::*;

impl Serialize for ark_secp256k1::Fq {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        ark_secp256k1::Fq::deserialize_compressed(reader).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.serialize_compressed(writer)
            .expect("Failed to serialize ark_secp256k1::Fq")
    }
}

impl Serialize for ark_secp256k1::Fr {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        ark_secp256k1::Fr::deserialize_compressed(reader).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.serialize_compressed(writer)
            .expect("Failed to serialize ark_secp256k1::Fr")
    }
}

impl Serialize for ark_secp256k1::Affine {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        ark_secp256k1::Affine::deserialize_compressed(reader).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.serialize_compressed(writer)
            .expect("Failed to serialize ark_secp256k1::Affine")
    }
}

impl Serialize for ark_secp256k1::Projective {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        ark_secp256k1::Projective::deserialize_compressed(reader).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.serialize_compressed(writer)
            .expect("Failed to serialize ark_secp256k1::Projective")
    }
}
