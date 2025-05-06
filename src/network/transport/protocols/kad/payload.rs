use std::{f64, fmt::Display, time::SystemTime};

use serde::{Deserialize, Serialize};

use crate::committee;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Conversion error: {0}")]
    Conversion(String),

    #[error("Variant mismatch, expected {0}, found {1}")]
    VariantMismatch(Variant, Variant),

    #[error("Variant must be one of: {0:?}, but it is {1}")]
    VariantFieldMismatch(String, Variant),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Variant {
    ResidentKey,
    Resident,
    CommitteeKey,
    Committee,
    Proposal,
    SelectionFactorKey,
    SelectionFactor,
    Raw,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    ResidentKey([u8; 32]),

    Resident {
        id: libp2p::PeerId,
        data: Vec<u8>,
        timestamp: SystemTime,
    },

    CommitteeKey([u8; 32]),

    Committee(committee::Info),

    Proposal(Vec<u8>),

    SelectionFactorKey([u8; 32]),

    SelectionFactor(f64),

    Raw(Vec<u8>),
}

impl Payload {
    pub fn extract<T>(self, expected: Variant) -> Result<T>
    where
        T: TryFrom<Payload>,
        T::Error: std::fmt::Display,
    {
        if self.variant() != expected {
            return Err(Error::VariantMismatch(expected, self.variant()));
        }

        T::try_from(self).map_err(|e| Error::Conversion(e.to_string()))
    }

    pub fn variant(&self) -> Variant {
        match self {
            Payload::ResidentKey(_) => Variant::ResidentKey,
            Payload::Resident { .. } => Variant::Resident,
            Payload::CommitteeKey(_) => Variant::CommitteeKey,
            Payload::Committee(_) => Variant::Committee,
            Payload::Proposal(_) => Variant::Proposal,
            Payload::SelectionFactorKey(_) => Variant::SelectionFactorKey,
            Payload::SelectionFactor(_) => Variant::SelectionFactor,
            Payload::Raw(_) => Variant::Raw,
        }
    }
}

impl Display for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Variant::ResidentKey => write!(f, "ResidentKey"),
            Variant::Resident => write!(f, "Resident"),
            Variant::CommitteeKey => write!(f, "CommitteeKey"),
            Variant::Committee => write!(f, "Committee"),
            Variant::Proposal => write!(f, "Proposal"),
            Variant::SelectionFactorKey => write!(f, "SelectionFactorKey"),
            Variant::SelectionFactor => write!(f, "SelectionFactor"),
            Variant::Raw => write!(f, "Raw"),
        }
    }
}

impl TryFrom<Payload> for [u8; 32] {
    type Error = Error;

    fn try_from(payload: Payload) -> Result<Self> {
        const EXPECTED_MESSAGE: &str =
            "Variant::ResidentKey, Variant::CommitteeKey, Variant::SelectionFactorKey";

        match payload {
            Payload::ResidentKey(key) => Ok(key),
            Payload::CommitteeKey(key) => Ok(key),
            Payload::SelectionFactorKey(key) => Ok(key),
            _ => Err(Error::VariantFieldMismatch(
                EXPECTED_MESSAGE.to_string(),
                payload.variant(),
            )),
        }
    }
}

impl TryFrom<Payload> for (libp2p::PeerId, Vec<u8>, SystemTime) {
    type Error = Error;

    fn try_from(payload: Payload) -> Result<Self> {
        const EXPECTED_MESSAGE: &str = "Variant::Resident";

        if let Payload::Resident {
            id,
            data,
            timestamp,
        } = payload
        {
            Ok((id, data, timestamp))
        } else {
            Err(Error::VariantFieldMismatch(
                EXPECTED_MESSAGE.to_string(),
                payload.variant(),
            ))
        }
    }
}

impl TryFrom<Payload> for f64 {
    type Error = Error;

    fn try_from(payload: Payload) -> Result<Self> {
        const EXPECTED_MESSAGE: &str = "Variant::SelectionFactor";

        if let Payload::SelectionFactor(factor) = payload {
            Ok(factor)
        } else {
            Err(Error::VariantFieldMismatch(
                EXPECTED_MESSAGE.to_string(),
                payload.variant(),
            ))
        }
    }
}
