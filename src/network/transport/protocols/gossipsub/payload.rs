use libp2p::Multiaddr;

use crate::{
    crypto::traits::hasher::Multihash,
    traits::{serializable, ConstantSize, Serializable},
};

enum PayloadType {
    Proposal,
    ConsensusCandidate,
    View,
    Vote,
    Raw,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Payload {
    // VSSComponent {
    //     id: Vec<u8>,
    //     encrypted_shares: EncryptedShares,
    //     commitments: Vec<Point>,
    // },
    //
    // VSSReport {
    //     id: Vec<u8>,
    //     decrypted_shares: DecryptedShares,
    // },
    //
    // VSSReportResponse {
    //     id: Vec<u8>,
    //     decrypted_shares: DecryptedShares,
    // },
    //
    // TssNonceShare {
    //     id: Vec<u8>,
    //     share: Scalar,
    // },
    //
    // TssSignatureShare {
    //     id: Vec<u8>,
    //     share: Scalar,
    // },
    Proposal(Vec<u8>),

    ConsensusCandidate {
        seed: Multihash,
        proof: Vec<u8>,
        pk: Vec<u8>,
        addr: Multiaddr,
    },

    View {
        data: Vec<u8>,
        proof: Vec<u8>,
        pk: Vec<u8>,
    },

    Vote {
        pk: Vec<u8>,
        proof: Vec<u8>,
        sign: Vec<u8>,
    },

    // For testing
    Raw(Vec<u8>),
}

impl PayloadType {
    pub fn as_u8(&self) -> u8 {
        match self {
            PayloadType::Proposal => 0,
            PayloadType::ConsensusCandidate => 1,
            PayloadType::View => 2,
            PayloadType::Raw => 3,
            PayloadType::Vote => 4,
        }
    }

    pub fn from_payload(payload: &Payload) -> Self {
        match payload {
            Payload::Proposal(_) => PayloadType::Proposal,
            Payload::ConsensusCandidate { .. } => PayloadType::ConsensusCandidate,
            Payload::View { .. } => PayloadType::View,
            Payload::Raw(_) => PayloadType::Raw,
            Payload::Vote { .. } => PayloadType::Vote,
        }
    }
}

impl Serializable for PayloadType {
    fn serialized_size(&self) -> usize {
        1
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let value: u8 = u8::from_reader(reader)?;
        match value {
            0 => Ok(PayloadType::Proposal),
            1 => Ok(PayloadType::ConsensusCandidate),
            2 => Ok(PayloadType::View),
            3 => Ok(PayloadType::Raw),
            4 => Ok(PayloadType::Vote),
            _ => Err(serializable::Error("Unknown payload type".to_string())),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.as_u8().to_writer(writer)
    }
}

impl ConstantSize for PayloadType {
    const SIZE: usize = 1;
}

impl Serializable for Payload {
    fn serialized_size(&self) -> usize {
        PayloadType::SIZE
            + match self {
                Payload::Proposal(data) => data.serialized_size(),
                Payload::ConsensusCandidate {
                    seed,
                    proof,
                    pk,
                    addr,
                } => {
                    seed.serialized_size()
                        + proof.serialized_size()
                        + pk.serialized_size()
                        + addr.serialized_size()
                }
                Payload::View { data, proof, pk } => {
                    data.serialized_size() + proof.serialized_size() + pk.serialized_size()
                }
                Payload::Vote { pk, proof, sign } => {
                    pk.serialized_size() + proof.serialized_size() + sign.serialized_size()
                }
                Payload::Raw(data) => data.serialized_size(),
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let payload_type = PayloadType::from_reader(reader)?;

        let payload = match payload_type {
            PayloadType::Proposal => Payload::Proposal(Vec::<u8>::from_reader(reader)?),
            PayloadType::ConsensusCandidate => Payload::ConsensusCandidate {
                seed: Multihash::from_reader(reader)?,
                proof: Vec::<u8>::from_reader(reader)?,
                pk: Vec::<u8>::from_reader(reader)?,
                addr: Multiaddr::from_reader(reader)?,
            },
            PayloadType::View => Payload::View {
                data: Vec::<u8>::from_reader(reader)?,
                proof: Vec::<u8>::from_reader(reader)?,
                pk: Vec::<u8>::from_reader(reader)?,
            },
            PayloadType::Vote => Payload::Vote {
                pk: Vec::<u8>::from_reader(reader)?,
                proof: Vec::<u8>::from_reader(reader)?,
                sign: Vec::<u8>::from_reader(reader)?,
            },
            PayloadType::Raw => Payload::Raw(Vec::<u8>::from_reader(reader)?),
        };

        Ok(payload)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        let payload_type = PayloadType::from_payload(self);
        payload_type.to_writer(writer)?;

        match self {
            Payload::Proposal(data) => data.to_writer(writer)?,
            Payload::ConsensusCandidate {
                seed,
                proof,
                pk,
                addr,
            } => {
                seed.to_writer(writer)?;
                proof.to_writer(writer)?;
                pk.to_writer(writer)?;
                addr.to_writer(writer)?;
            }
            Payload::View { data, proof, pk } => {
                data.to_writer(writer)?;
                proof.to_writer(writer)?;
                pk.to_writer(writer)?;
            }
            Payload::Vote { pk, proof, sign } => {
                pk.to_writer(writer)?;
                proof.to_writer(writer)?;
                sign.to_writer(writer)?;
            }
            Payload::Raw(data) => data.to_writer(writer)?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{network::transport::protocols::gossipsub::Payload, traits::Serializable};

    #[test]
    fn success_convert_with_vec() {
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let payload = Payload::Raw(PAYLOAD.to_vec());

        let payload_vec = payload.to_vec().unwrap();
        let payload_from_vec = Payload::from_slice(&payload_vec).unwrap();

        assert_eq!(payload, payload_from_vec);
    }

    #[test]
    fn error_when_decoding_invalid_payload() {
        let invalid_payload = vec![0, 1, 2, 3, 4];

        let result = Payload::from_slice(&invalid_payload);

        assert!(
            result.is_err(),
            "Expected error when decoding invalid payload"
        );
    }
}
