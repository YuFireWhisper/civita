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
    utils::Record,
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

    #[error("No bootstrap peers configured")]
    NoBootstrapPeers,
}

pub struct Config {
    vdf_param: u16,
    vdf_difficulty: u64,
    mode: Mode,
    bootstrap_peers: Vec<PeerId>,
    bootstrap_timeout: tokio::time::Duration,
}

pub struct Resident<H: Hasher, V, T: Record> {
    transport: Arc<Transport>,
    engine: Arc<consensus::Engine<H, V, T>>,
}

impl<H: Hasher, V: Validator, T: Record> Resident<H, V, T> {
    pub async fn new(
        transport: Arc<Transport>,
        validator: V,
        mut config: Config,
    ) -> Result<Arc<Self>> {
        let is_archive = config.mode.is_archive();

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

        let resident = Self {
            transport,
            engine: consensus_engine,
        };

        let resident = Arc::new(resident);

        if is_archive {
            let resident_clone = Arc::clone(&resident);
            resident_clone.start_recving();
        }

        Ok(resident)
    }

    async fn bootstrap(
        transport: Arc<Transport>,
        config: &mut Config,
    ) -> Result<block::Tree<H, T>> {
        if config.bootstrap_peers.is_empty() {
            return Err(Error::NoBootstrapPeers);
        }

        let req_resp = transport.request_response();
        let msg = config.mode.to_vec();

        for &peer in &config.bootstrap_peers {
            req_resp
                .send_request(peer, msg.clone(), BOOTSTRAP_TOPIC)
                .await;
        }

        let mut rx = req_resp.subscribe(BOOTSTRAP_TOPIC);

        let response = tokio::time::timeout(config.bootstrap_timeout, async {
            while let Some(msg) = rx.recv().await {
                if let request_response::Message::Response { peer, response } = msg {
                    if config.bootstrap_peers.contains(&peer) {
                        return response;
                    }
                }
            }
            panic!("Channel closed before receiving response");
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)?;

        req_resp.unsubscribe(BOOTSTRAP_TOPIC);

        let state = SyncState::from_slice(&response).map_err(|_| Error::InvalidMessage)?;

        let mode = std::mem::replace(&mut config.mode, Mode::Archive);
        block::Tree::<H, T>::from_sync_state(transport.secret_key().clone(), state, mode)
            .ok_or(Error::FailedToCreateTree)
    }

    fn start_recving(self: Arc<Self>) {
        let req_resp = self.transport.request_response();
        let mut rx = req_resp.subscribe(BOOTSTRAP_TOPIC);

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let request_response::Message::Request {
                    peer,
                    request,
                    channel,
                } = msg
                {
                    if request.is_empty() {
                        continue;
                    }

                    let Ok(mode) = Mode::from_slice(&request) else {
                        continue; // Invalid message, skip
                    };

                    let state = self.engine.generate_sync_state(mode);
                    let response = state.to_vec();

                    if let Err(e) = req_resp
                        .send_response(channel, response, BOOTSTRAP_TOPIC)
                        .await
                    {
                        log::error!("Failed to send response to {peer}: {e}");
                        continue; // Log error and continue
                    }
                }
            }
        });
    }
}
