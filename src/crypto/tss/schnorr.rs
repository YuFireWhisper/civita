use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use sha2::{Digest, Sha256};

use crate::{
    crypto::{
        algebra::{self, Point, Scalar},
        dkg::{Dkg, GenerateResult},
        threshold,
        tss::{
            self,
            schnorr::{collector::CollectionResult, signature::Signature},
            SignResult, Tss,
        },
    },
    network::transport::protocols::gossipsub,
    traits::{byteable, Byteable},
    utils::IndexedMap,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

mod collector;
pub mod signature;

type Result<T> = std::result::Result<T, Error>;

const DEFAULT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(120);
const DEFAULT_TOPIC: &str = "tss/schnorr";

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Algebra(#[from] algebra::Error),

    #[error("{0}")]
    Dkg(String),

    #[error("{0}")]
    Collector(#[from] collector::Error),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("{0}")]
    Byteable(#[from] byteable::Error),
}

enum RandomGenerateResult {
    Success((Scalar, Point)),
    Failure(HashSet<libp2p::PeerId>),
}

#[derive(Debug)]
pub struct Config {
    pub threshold_counter: threshold::Counter,
    pub topic: String,
    pub timeout: tokio::time::Duration,
}

pub struct Schnorr<D: Dkg> {
    transport: Arc<Transport>,
    dkg: Arc<D>,
    secret: Option<Scalar>,
    global_pk: Option<Point>,
    collector: collector::Collector,
    peer_index: Option<IndexedMap<libp2p::PeerId, ()>>,
    config: Config,
}

impl<D: Dkg> Schnorr<D> {
    pub fn new(dkg: Arc<D>, transport: Arc<Transport>, config: Config) -> Self {
        let collector_config = collector::Config {
            threshold_counter: config.threshold_counter,
            topic: config.topic.clone(),
            timeout: config.timeout,
        };

        let collector = collector::Collector::new(transport.clone(), collector_config);

        Self {
            transport,
            dkg,
            secret: None,
            global_pk: None,
            collector,
            peer_index: None,
            config,
        }
    }

    pub async fn set_keypair(
        &mut self,
        secret: Scalar,
        public: Point,
        global_commitments: Vec<Point>,
        peers: IndexedMap<libp2p::PeerId, ()>,
    ) -> Result<()> {
        self.secret = Some(secret);
        self.global_pk = Some(public);
        self.peer_index = Some(peers.clone());
        self.collector.stop().await;
        self.collector.start(global_commitments, peers).await?;

        Ok(())
    }

    pub async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Result<SignResult> {
        let (random_share, random_point) = match self.generate_random_share(id.clone()).await? {
            RandomGenerateResult::Success(secret) => secret,
            RandomGenerateResult::Failure(invalid_peers) => {
                return Ok(SignResult::Failure(invalid_peers));
            }
        };

        let challenge = self.compute_challenge(msg, &random_point)?;
        let own_sig = self.calculate_signature(&random_share, &challenge)?;

        self.publish_signature(id.clone(), own_sig.clone()).await?;
        let result = self.collector.query_signature_share(id.clone()).await?;

        match result {
            CollectionResult::Success(mut shares) => {
                shares.insert(self.transport.self_peer(), own_sig);
                let (indices, shares) = self.get_indices_and_shares(shares);

                let sig = Scalar::lagrange_interpolation(&indices, &shares)?;
                let sig = Signature::new(sig, random_point);

                Ok(SignResult::Success(tss::Signature::Schnorr(sig)))
            }
            collector::CollectionResult::Failure(invalid_peers) => {
                Ok(SignResult::Failure(invalid_peers))
            }
        }
    }

    fn get_indices_and_shares(
        &self,
        map: HashMap<libp2p::PeerId, Scalar>,
    ) -> (Vec<u16>, Vec<Scalar>) {
        let peer_index = self.peer_index.as_ref().expect("Peer index is not set");

        let mut indices = Vec::new();
        let mut shares = Vec::new();

        for (peer_id, share) in map {
            let index = peer_index
                .get_index(&peer_id)
                .expect("Peer ID not found in peer index");
            indices.push(index);
            shares.push(share);
        }

        (indices, shares)
    }

    async fn generate_random_share(&self, id: Vec<u8>) -> Result<RandomGenerateResult> {
        let result = self
            .dkg
            .generate(id)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))?;

        match result {
            GenerateResult::Success { secret, public, .. } => {
                Ok(RandomGenerateResult::Success((secret, public)))
            }
            GenerateResult::Failure { invalid_peers } => {
                Ok(RandomGenerateResult::Failure(invalid_peers))
            }
        }
    }

    fn compute_challenge(&self, msg: &[u8], random_point: &Point) -> Result<Scalar> {
        let global_pk = self
            .global_pk
            .as_ref()
            .expect("Global public key is not set");
        calculate_challenge(msg, random_point, global_pk)
    }

    fn calculate_signature(&self, random_share: &Scalar, challenge: &Scalar) -> Result<Scalar> {
        let secret = self.secret.as_ref().expect("Secret key is not set");
        random_share
            .sub(&(challenge.mul(secret)?))
            .map_err(Error::from) // random_share - secret * challenge
    }

    async fn publish_signature(&self, id: Vec<u8>, signature: Scalar) -> Result<()> {
        let payload = gossipsub::Payload::TssSignatureShare {
            id,
            share: signature,
        };

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}

pub fn calculate_challenge(msg: &[u8], public_random: &Point, global_pk: &Point) -> Result<Scalar> {
    const DOMAIN_SEPARATOR: &[u8] = b"SCHNORR_SIGNATURE";

    let public_random_bytes = public_random.to_vec()?;
    let global_pk_bytes = global_pk.to_vec()?;
    let input = [
        DOMAIN_SEPARATOR,
        msg,
        &public_random_bytes,
        &global_pk_bytes,
    ]
    .concat();

    let hash = Sha256::new().chain(&input).finalize();
    Ok(Scalar::from_bytes(hash.as_slice(), &public_random.scheme()))
}

#[async_trait::async_trait]
impl<D: Dkg> Tss for Schnorr<D> {
    type Error = Error;

    async fn set_keypair(
        &mut self,
        secret_key: Scalar,
        public_key: Point,
        global_commitments: Vec<Point>,
        peers: IndexedMap<libp2p::PeerId, ()>,
    ) -> Result<()> {
        self.set_keypair(secret_key, public_key, global_commitments, peers)
            .await
    }

    async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Result<SignResult> {
        self.sign(id, msg).await
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold_counter: threshold::Counter::default(),
            topic: DEFAULT_TOPIC.to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}
