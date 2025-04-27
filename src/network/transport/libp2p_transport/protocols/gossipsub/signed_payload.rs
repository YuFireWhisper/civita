use serde::{Deserialize, Serialize};

use crate::{
    crypto::tss::Signature, network::transport::libp2p_transport::protocols::gossipsub::Payload,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Payload needs a signature")]
    MissingSignature,

    #[error("Payload doesn't need a signature")]
    SignatureNotNeeded,

    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    payload: Payload,

    /// The signature of the payload, if payload does't need a signature, this field should be None
    committee_signature: Option<Signature>,
}

impl SignedPayload {
    pub fn new(payload: Payload, committee_signature: Option<Signature>) -> Result<Self> {
        if payload.require_committee_signature() && committee_signature.is_none() {
            return Err(Error::MissingSignature);
        }

        if !payload.require_committee_signature() && committee_signature.is_some() {
            return Err(Error::SignatureNotNeeded);
        }

        Ok(Self {
            payload,
            committee_signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.try_into()
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn committee_signature(&self) -> Option<&Signature> {
        self.committee_signature.as_ref()
    }

    pub fn take_payload_and_signature(self) -> (Payload, Option<Signature>) {
        (self.payload, self.committee_signature)
    }
}

impl TryFrom<SignedPayload> for Vec<u8> {
    type Error = Error;

    fn try_from(value: SignedPayload) -> Result<Self> {
        bincode::serde::encode_to_vec(&value, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<&SignedPayload> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &SignedPayload) -> Result<Self> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).map_err(Error::from)
    }
}

impl TryFrom<Vec<u8>> for SignedPayload {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        bincode::serde::decode_from_slice(&value, bincode::config::standard())
            .map(|(p, _)| p)
            .map_err(Error::from)
    }
}

impl TryFrom<&Vec<u8>> for SignedPayload {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(p, _)| p)
            .map_err(Error::from)
    }
}

impl TryFrom<&[u8]> for SignedPayload {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(p, _)| p)
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{
            primitives::algebra::{Point, Scalar},
            tss::{schnorr, Signature},
        },
        network::transport::libp2p_transport::protocols::gossipsub::{
            signed_payload::SignedPayload, Payload,
        },
    };

    fn create_signature() -> Signature {
        Signature::Schnorr(schnorr::signature::Signature {
            sig: Scalar::secp256k1_random(),
            public_random: Point::secp256k1_zero(),
        })
    }

    #[test]
    fn fails_when_payload_needs_signature() {
        let payload = Payload::RawWithSignature { raw: vec![] };
        let result = SignedPayload::new(payload, None);

        assert!(result.is_err());
    }

    #[test]
    fn fails_when_payload_doesnt_need_signature() {
        let payload = Payload::Raw(vec![]);
        let result = SignedPayload::new(payload, Some(create_signature()));

        assert!(result.is_err());
    }

    #[test]
    fn succeeds_when_payload_needs_signature() {
        let payload = Payload::RawWithSignature { raw: vec![] };
        let result = SignedPayload::new(payload, Some(create_signature()));

        assert!(result.is_ok());
    }

    #[test]
    fn succeeds_when_payload_doesnt_need_signature() {
        let payload = Payload::Raw(vec![]);
        let result = SignedPayload::new(payload, None);

        assert!(result.is_ok());
    }

    #[test]
    fn success_convert_with_vec() {
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let payload = Payload::Raw(PAYLOAD.to_vec());
        let signed_payload = SignedPayload::new(payload, None).unwrap();

        let signed_payload_vec = signed_payload.to_vec().unwrap();
        let signed_payload_from_vec = SignedPayload::try_from(signed_payload_vec).unwrap();

        assert_eq!(signed_payload, signed_payload_from_vec);
    }
}
