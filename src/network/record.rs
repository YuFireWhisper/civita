use std::fmt::Debug;

use bincode::Decode;

use crate::{proposal::Proposal, traits::Byteable};

type CerditType = u64;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
}

/// A 32-byte key used to identify a `Record`.
/// - For the `Resident` variant, the `RecordKey` is the [`PeerId`] of the resident
/// - For the `Proposal` variant, the `RecordKey` is the hash of the proposal.
///
/// [`PeerId`]: https://docs.rs/libp2p/latest/libp2p/struct.PeerId.html
pub type RecordKey = [u8; 32];

pub enum Record<P: Proposal> {
    Resident {
        cerdit: CerditType,
        custom: P::CustomValue,
    },
    Proposal(P),
}

impl<P> Record<P>
where
    P: Proposal,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.try_into()
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        bincode::decode_from_slice(bytes.as_ref(), bincode::config::standard())
            .map(|(record, _)| record)
            .map_err(Error::from)
    }
}

impl<P: Proposal> bincode::Encode for Record<P> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        match self {
            Record::Resident { cerdit, custom } => {
                0u8.encode(encoder)?;
                cerdit.encode(encoder)?;
                let custom_bytes: Vec<u8> = custom.to_bytes().map_err(|e| {
                    bincode::error::EncodeError::OtherString(format!(
                        "Failed to convert custom value to bytes: {:?}",
                        e
                    ))
                })?;
                custom_bytes.encode(encoder)?;
            }
            Record::Proposal(proposal) => {
                1u8.encode(encoder)?;
                let proposal_bytes: Vec<u8> = proposal.to_bytes().map_err(|e| {
                    bincode::error::EncodeError::OtherString(format!(
                        "Failed to convert proposal to bytes: {:?}",
                        e
                    ))
                })?;
                proposal_bytes.encode(encoder)?;
            }
        }
        Ok(())
    }
}

impl<Context, P: Proposal> bincode::Decode<Context> for Record<P> {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let tag: u8 = Decode::decode(decoder)?;

        match tag {
            0 => {
                let cerdit: CerditType = Decode::decode(decoder)?;

                let custom_bytes: Vec<u8> = Decode::decode(decoder)?;

                let custom = P::CustomValue::from_bytes(custom_bytes).map_err(|e| {
                    bincode::error::DecodeError::OtherString(format!(
                        "Failed to convert bytes to custom value: {:?}",
                        e
                    ))
                })?;

                Ok(Record::Resident { cerdit, custom })
            }
            1 => {
                let proposal_bytes: Vec<u8> = Decode::decode(decoder)?;

                let proposal = P::from_bytes(proposal_bytes).map_err(|e| {
                    bincode::error::DecodeError::OtherString(format!(
                        "Failed to convert bytes to proposal: {:?}",
                        e
                    ))
                })?;

                Ok(Record::Proposal(proposal))
            }
            _ => Err(bincode::error::DecodeError::Other(
                "Invalid Record variant tag",
            )),
        }
    }
}

impl<P: Proposal> TryFrom<Record<P>> for Vec<u8> {
    type Error = Error;

    fn try_from(value: Record<P>) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<P: Proposal> TryFrom<&Record<P>> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Record<P>) -> Result<Self, Self::Error> {
        bincode::encode_to_vec(value, bincode::config::standard()).map_err(Error::from)
    }
}

impl<P> Clone for Record<P>
where
    P: Proposal + Clone,
    P::CustomValue: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Record::Resident { cerdit, custom } => Record::Resident {
                cerdit: *cerdit,
                custom: custom.clone(),
            },
            Record::Proposal(proposal) => Record::Proposal(proposal.clone()),
        }
    }
}

impl<P> Debug for Record<P>
where
    P: Proposal + Debug,
    P::CustomValue: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Record::Resident { cerdit, custom } => f
                .debug_struct("Record::Resident")
                .field("cerdit", cerdit)
                .field("custom", custom)
                .finish(),
            Record::Proposal(proposal) => f
                .debug_struct("Record::Proposal")
                .field("proposal", proposal)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        network::record::{CerditType, Error, Record},
        proposal::MockProposal,
    };

    const DEFAULT_CREDIT: CerditType = 100;
    const CUSTOM_VALUE_BYTES: &[u8] = &[1, 2, 3, 4];

    fn create_resident_record() -> Record<MockProposal> {
        Record::Resident {
            cerdit: DEFAULT_CREDIT,
            custom: CUSTOM_VALUE_BYTES.to_vec(),
        }
    }

    fn create_proposal_record() -> Record<MockProposal> {
        Record::Proposal(MockProposal::default())
    }

    #[test]
    fn success_convert_with_bytes() {
        let resident_record = create_resident_record();
        let proposal_record = create_proposal_record();

        let resident_bytes = resident_record.to_bytes().unwrap();
        let proposal_bytes = proposal_record.to_bytes().unwrap();

        let resident_decoded = Record::<MockProposal>::from_bytes(&resident_bytes).unwrap();
        let proposal_decoded = Record::<MockProposal>::from_bytes(&proposal_bytes).unwrap();

        match (resident_decoded, proposal_decoded) {
            (Record::Resident { cerdit, custom }, Record::Proposal(_)) => {
                assert_eq!(cerdit, DEFAULT_CREDIT);
                assert_eq!(custom, CUSTOM_VALUE_BYTES.to_vec());
            }
            _ => panic!("Expected Resident and Proposal records"),
        }
    }

    #[test]
    fn returns_error_invalid_tag() {
        let invalid_bytes = vec![2u8, 0, 0, 0, 0, 0, 0, 0, 0]; // Tag '2' is invalid

        let result = Record::<MockProposal>::from_bytes(&invalid_bytes);

        assert!(result.is_err());
        if let Err(Error::Decode(e)) = result {
            assert!(e.to_string().contains("Invalid Record variant tag"));
        } else {
            panic!("Expected Decode error with invalid tag message");
        }
    }

    #[test]
    fn successfully_clones_record() {
        let resident_record = create_resident_record();
        let proposal_record = create_proposal_record();

        let cloned_resident = resident_record.clone();
        let cloned_proposal = proposal_record.clone();

        match (resident_record, cloned_resident) {
            (
                Record::Resident {
                    cerdit: c1,
                    custom: cu1,
                },
                Record::Resident {
                    cerdit: c2,
                    custom: cu2,
                },
            ) => {
                assert_eq!(c1, c2);
                assert_eq!(cu1, cu2);
            }
            _ => panic!("Expected both to be Resident records"),
        }

        match (proposal_record, cloned_proposal) {
            (Record::Proposal(_), Record::Proposal(_)) => (), // Success
            _ => panic!("Expected both to be Proposal records"),
        }
    }

    #[test]
    fn debug_implementation_works() {
        let resident_record = create_resident_record();
        let proposal_record = create_proposal_record();

        let resident_debug = format!("{:?}", resident_record);
        let proposal_debug = format!("{:?}", proposal_record);

        assert!(resident_debug.contains("Record::Resident"));
        assert!(resident_debug.contains(&DEFAULT_CREDIT.to_string()));

        assert!(proposal_debug.contains("Record::Proposal"));
    }

    #[test]
    fn successfully_converts_record_with_bytes() {
        let record = create_resident_record();

        let bytes: Vec<u8> = record.try_into().unwrap();

        assert!(!bytes.is_empty());
        let decoded = Record::<MockProposal>::from_bytes(&bytes).unwrap();
        match decoded {
            Record::Resident { cerdit, .. } => assert_eq!(cerdit, DEFAULT_CREDIT),
            _ => panic!("Expected Resident record"),
        }
    }
}
