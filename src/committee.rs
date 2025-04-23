use std::{collections::HashSet, sync::Arc};

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc::Receiver as TokioReceiver, Mutex as TokioMutex, RwLock as TokioRwLock};

use crate::{
    committee::config::Config,
    crypto::{
        dkg::{self, Dkg},
        index_map::IndexedMap,
        keypair::PublicKey,
        primitives::algebra::{self, Point, Scalar},
        tss::{Signature, Tss},
    },
    network::transport::{
        libp2p_transport::protocols::gossipsub::{Message, Payload},
        Transport,
    },
};

pub mod config;
mod timer;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Signature verification failed, message from: {0}")]
    SignatureVerificationFailed(libp2p::PeerId),

    #[error("{0}")]
    Dkg(String),

    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Transport(String),

    #[error("{0}")]
    Algebra(#[from] algebra::Error),

    #[error("{0}")]
    Tss(String),
}

#[allow(dead_code)]
#[derive(Debug)]
enum Action {
    Start,
    Stop,
}

pub struct Committee<T, D, S>
where
    T: Transport + Send + Sync + 'static,
    D: Dkg + Send + Sync + 'static,
    S: Tss + 'static,
{
    transport: Arc<T>,
    dkg: TokioRwLock<D>,
    tss: TokioRwLock<S>,
    committee_pk: TokioRwLock<Point>,
    config: Config,
    handler: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<T, D, S> Committee<T, D, S>
where
    T: Transport + Send + Sync + 'static,
    D: Dkg + Send + Sync + 'static,
    S: Tss + Send + Sync + 'static,
{
    pub async fn new(
        transport: Arc<T>,
        dkg: D,
        tss: S,
        committee_pk: Point,
        config: Config,
    ) -> Result<Arc<Self>> {
        let dkg = TokioRwLock::new(dkg);
        let tss = TokioRwLock::new(tss);
        let committee_pk = TokioRwLock::new(committee_pk);

        let self_arc = Arc::new(Self {
            transport,
            dkg,
            tss,
            committee_pk,
            config,
            handler: TokioMutex::new(None),
        });

        self_arc.clone().start().await?;

        Ok(self_arc)
    }

    async fn start(self: Arc<Self>) -> Result<()> {
        let gossipsub_rx = self
            .transport
            .listen_on_topic(&self.config.topic)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let self_arc = Arc::clone(&self);
        let handler = tokio::spawn({
            async move {
                self_arc.run_loop(gossipsub_rx).await;
            }
        });

        self.handler.lock().await.replace(handler);
        Ok(())
    }

    async fn run_loop(self: Arc<Self>, mut gossipsub_rx: TokioReceiver<Message>) {
        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = self.process_message(msg).await {
                        log::error!("Error processing message: {:?}", e);
                    }
                }
                else => {
                    break;
                }
            }
        }
    }

    async fn process_message(self: &Arc<Self>, msg: Message) -> Result<()> {
        match msg.payload {
            Payload::CommitteeCandiates {
                candidates,
                signature,
            } => {
                self.process_new_candidates(msg.source, candidates, &signature)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn process_new_candidates(
        self: &Arc<Self>,
        source: libp2p::PeerId,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
        signature: &Signature,
    ) -> Result<()> {
        if !candidates.contains_key(&self.transport.self_peer()) {
            return Ok(());
        }

        let bytes = bincode::serde::encode_to_vec(&candidates, bincode::config::standard())?;
        let hash = Sha256::digest(&bytes).to_vec();

        if !signature.verify(&hash, &*self.committee_pk.read().await) {
            return Err(Error::SignatureVerificationFailed(source));
        }

        let result = {
            let mut dkg = self.dkg.write().await;
            dkg.set_peers(candidates.clone())
                .await
                .map_err(|e| Error::Dkg(e.to_string()))?;
            dkg.generate(hash.clone()).await
        }
        .map_err(|e| Error::Dkg(e.to_string()))?;

        match result {
            dkg::GenerateResult::Success {
                secret,
                partial_publics,
            } => {
                self.process_dkg_generate_success(hash, secret, partial_publics)
                    .await?;
            }
            dkg::GenerateResult::Failure { invalid_peers } => {
                self.process_dkg_generate_failure(hash, invalid_peers)
                    .await?;
            }
        }

        Ok(())
    }

    async fn process_dkg_generate_success(
        self: &Arc<Self>,
        candidates_hash: Vec<u8>,
        secret: Scalar,
        partial_publics: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let public_key = Point::sum(
            partial_publics
                .values()
                .map(|p| p.first().expect("Publics is empty")),
        )?;

        self.tss
            .write()
            .await
            .set_keypair(secret, partial_publics)
            .await
            .map_err(|e| Error::Tss(e.to_string()))?;

        let input = Self::generate_input(&candidates_hash, &public_key)?;

        let signature = self
            .tss
            .read()
            .await
            .sign(candidates_hash.clone(), &input)
            .await
            .map_err(|e| Error::Tss(e.to_string()))?;

        let payload = Payload::CommitteeGenerateSuccess {
            candidates_hash,
            committee_pub_key: public_key,
            signature,
        };

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    fn generate_input(candidates_hash: &[u8], public_key: &Point) -> Result<Vec<u8>> {
        let mut input = Vec::new();
        input.extend_from_slice(candidates_hash);
        input.extend_from_slice(&public_key.to_vec()?);
        Ok(input)
    }

    async fn process_dkg_generate_failure(
        self: &Arc<Self>,
        candidates_hash: Vec<u8>,
        invalid_peers: HashSet<libp2p::PeerId>,
    ) -> Result<()> {
        let payload = Payload::CommitteeGenerateFailure {
            candidates_hash,
            invalid_peers,
        };

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}
