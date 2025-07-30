use std::sync::Arc;

use civita_serialize::Serialize;
use libp2p::PeerId;

use crate::{
    consensus::{
        self,
        block::{
            self,
            tree::{Mode, SyncState},
        },
        engine::Validator,
    },
    crypto::Hasher,
    network::{request_response, Transport},
};

const PROPOSAL_TOPIC: u8 = 0;
const BLOCK_TOPIC: u8 = 1;
const REQUEST_RESPONSE_TOPIC: u8 = 2;
const BOOTSTRAP_TOPIC: u8 = 3;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RequestResponse(#[from] request_response::Error),

    #[error("Bootstrap timeout")]
    BootstrapTimeout,

    #[error("Invalid Message")]
    InvalidMessage,

    #[error("Mismatched Mode")]
    MismatchedMode,

    #[error("Mismatched peer")]
    MismatchedPeer,

    #[error("Failed to create tree")]
    FailedToCreateTree,
}

pub struct Config {
    vdf_param: u16,
    vdf_difficulty: u64,
    mode: Mode,
    bootstrap_peer: PeerId,
    bootstrap_timeout: tokio::time::Duration,
}

pub struct Resident<H: Hasher, V> {
    transport: Arc<Transport>,
    engine: Arc<consensus::Engine<H, V>>,
}

impl<H: Hasher, V: Validator> Resident<H, V> {
    pub async fn new(transport: Arc<Transport>, validator: V, mut config: Config) -> Result<Self> {
        let tree = Self::bootstrap(transport.clone(), &mut config).await?;

        let engine_config = consensus::engine::Config {
            proposal_topic: PROPOSAL_TOPIC,
            block_topic: BLOCK_TOPIC,
            request_response_topic: REQUEST_RESPONSE_TOPIC,
            vdf_params: config.vdf_param,
            vdf_difficulty: config.vdf_difficulty,
        };

        let consensus_engine = Arc::new(consensus::Engine::new(
            transport.clone(),
            tree,
            validator,
            engine_config,
        ));

        let engine = consensus_engine.clone();
        tokio::spawn(async move {
            engine.run().await.expect("Failed to run consensus engine");
        });

        Ok(Self {
            transport,
            engine: consensus_engine,
        })
    }

    async fn bootstrap(transport: Arc<Transport>, config: &mut Config) -> Result<block::Tree<H>> {
        let req_resp = transport.request_response();
        let msg = config.mode.to_vec();

        req_resp
            .send_request(config.bootstrap_peer, msg, BOOTSTRAP_TOPIC)
            .await;

        let mut rx = req_resp.subscribe(BOOTSTRAP_TOPIC);
        let response = tokio::time::timeout(config.bootstrap_timeout, async {
            while let Some(msg) = rx.recv().await {
                if let request_response::Message::Response { peer, response } = msg {
                    if peer == config.bootstrap_peer {
                        return response;
                    }
                }
            }
            panic!("Channel closed before receiving response");
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)?;
        req_resp.unsubscribe(REQUEST_RESPONSE_TOPIC);

        let state = SyncState::from_slice(&response).map_err(|_| Error::InvalidMessage)?;

        let mode = std::mem::replace(&mut config.mode, Mode::Archive);
        block::Tree::<H>::from_sync_state(transport.secret_key().clone(), state, mode)
            .ok_or(Error::FailedToCreateTree)
    }
}
