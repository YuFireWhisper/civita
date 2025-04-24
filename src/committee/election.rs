use sha2::{Digest, Sha256};
use tokio::sync::RwLock as TokioRwLock;

use crate::{
    crypto::{
        keypair::{self, PublicKey, SecretKey},
        tss::{self, Tss},
    },
    network::transport::libp2p_transport::protocols::gossipsub,
};

const SEED_GENERATION_ID: &[u8] = b"election_seed_generation";
const SEED_GENERATION_INPUT: &[u8] = b"election_seed_generation_input";
const ELECTION_MESSAGE_SIGN_ID: &[u8] = b"election_message_sign_id";

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Keypair(#[from] keypair::Error),

    #[error("{0}")]
    Tss(String),

    #[error("{0}")]
    Signature(#[from] tss::SignatureError),

    #[error("{0}")]
    Payload(#[from] gossipsub::payload::Error),
}

#[derive(Debug)]
pub struct Election {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Election {
    pub fn new(secret_key: SecretKey, public_key: PublicKey) -> Self {
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn generate_election_response(&self, seed: Vec<u8>) -> Result<gossipsub::Payload> {
        let proof = self.secret_key.prove(&seed)?;

        Ok(gossipsub::Payload::CommitteeElectionResponse {
            seed,
            public_key: self.public_key.clone(),
            proof,
        })
    }

    pub async fn generate_new_election_request<T: Tss>(
        &self,
        tss: &TokioRwLock<T>,
    ) -> Result<gossipsub::Payload> {
        let seed = tss
            .read()
            .await
            .sign(SEED_GENERATION_ID.to_vec(), SEED_GENERATION_INPUT)
            .await
            .map_err(|e| Error::Tss(e.to_string()))?;
        let seed = Sha256::digest(&seed.to_vec()?);

        let mut payload = gossipsub::Payload::CommitteeElection {
            seed: seed.to_vec(),
            signature: None,
        };

        let signature = tss
            .read()
            .await
            .sign(ELECTION_MESSAGE_SIGN_ID.to_vec(), &payload.to_vec()?)
            .await
            .map_err(|e| Error::Tss(e.to_string()))?;

        payload.set_signature(signature);

        Ok(payload)
    }
}
