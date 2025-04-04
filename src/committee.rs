use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use libp2p::{
    gossipsub::MessageId,
    identity::{DecodingError, PublicKey},
    PeerId,
};
use log::error;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{
        builder::Component, message_channels::MessageChannels,
        signature_collector::SignatureResult, state::State, timer::Timer,
    },
    crypto::{
        dkg::{Data, Dkg},
        vrf::Vrf,
    },
    network::transport::{
        self,
        libp2p_transport::{
            protocols::{
                gossipsub::{self, Payload},
                kad,
            },
            Message,
        },
        Transport,
    },
};

pub mod builder;
pub mod config;
mod message_channels;
mod signature_collector;
mod state;
mod timer;

pub use builder::Builder;
pub use config::Config;

type Result<T> = std::result::Result<T, Error>;

pub const COMMITTEE_TOPIC: &str = "committee";
pub const SIGNATURE_REQUEST_TOPIC: &str = "signature_request";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create VRF: {0}")]
    Vrf(String),
    #[error("Failed to create DKG: {0}")]
    Dkg(String),
    #[error("{0}")]
    Transport(#[from] transport::Error),
    #[error("{0}")]
    KadPayload(#[from] kad::payload::Error),
    #[error("Failed to decode public key: {0}")]
    DecodingPublicKey(#[from] DecodingError),
    #[error("Peer info verification failed. Source PeerId: {0}")]
    PeerInfoVerificationFailed(PeerId),
    #[error("Failed to decode payload: {0}. Source PeerId: {1}")]
    DecodePayload(String, PeerId),
    #[error("Unexpected payload type")]
    UnexpectedPayloadType,
    #[error("Failed to get peer index")]
    PeerIndexNotFound,
    #[error("Signature channel closed")]
    SignatureChannelClosed,
    #[error("Committee channel closed")]
    CommitteeChannelClosed,
    #[error("Timer channel closed")]
    TimerChannelClosed,
    #[error("Failed to aggregate signature")]
    SignatureAggregation(String),
}

#[derive(Debug)]
enum Action {
    Start,
    Stop,
}

pub struct Committee<T, V, D>
where
    T: Transport + Send + Sync + 'static,
    V: Vrf + Send + Sync + 'static,
    D: Dkg + Send + Sync + 'static,
{
    transport: Arc<T>,
    #[allow(dead_code)]
    vrf: Arc<V>,
    dkg: D,
    config: Config,
    state: Mutex<State>,
    timer: Mutex<Timer<Action>>,
    channels: Mutex<MessageChannels>,
    is_member: AtomicBool,
    self_peer: PeerId,
}

impl<T, V, D> Committee<T, V, D>
where
    T: Transport + Send + Sync + 'static,
    V: Vrf + Send + Sync + 'static,
    D: Dkg + Send + Sync + 'static,
{
    async fn from_component(component: Component<T, V, D>) -> Result<Arc<Self>> {
        let transport = component.transport;
        let vrf = component.vrf;
        let dkg = component.dkg;
        let config = component.config;

        let state = Mutex::new(State::new(config.threshold_counter.clone_box()));
        let (timer, timer_rx) = Timer::new().await;
        let timer = Mutex::new(timer);
        let committee_rx = transport.listen_on_topic(COMMITTEE_TOPIC).await?;
        let sig_req_rx = transport.listen_on_topic(SIGNATURE_REQUEST_TOPIC).await?;
        let channels = Mutex::new(MessageChannels::new(committee_rx, sig_req_rx, timer_rx));
        let is_member = AtomicBool::new(false);
        let self_peer = transport.self_peer();

        let committee = Arc::new(Self {
            transport,
            vrf,
            dkg,
            config,
            state,
            timer,
            channels,
            is_member,
            self_peer,
        });

        committee.clone().run().await?;

        Ok(committee)
    }

    async fn run(self: Arc<Self>) -> Result<()> {
        tokio::spawn(async move {
            if let Err(e) = self.process_messages().await {
                error!("Committee processing error: {}", e);
            }
        });
        Ok(())
    }

    async fn process_messages(self: &Arc<Self>) -> Result<()> {
        let channels = self.channels.lock().await;
        let mut committee_rx = channels.lock_committee_rx().await;
        let mut sig_req_rx = channels.lock_sig_req_rx().await;
        let mut timer_rx = channels.lock_timer_rx().await;

        loop {
            tokio::select! {
                Some(msg) = committee_rx.recv() => {
                    self.handle_committee_message(msg).await?;
                }
                Some(action) = timer_rx.recv() => {
                    self.handle_timer_action(action).await?;
                }
                Some(msg) = sig_req_rx.recv() => {
                    self.handle_signature_request(msg).await?;
                }
                else => break,
            }
        }

        Err(Error::CommitteeChannelClosed)
    }

    async fn handle_committee_message(self: &Arc<Self>, msg: Message) -> Result<()> {
        let gossip_msg = gossipsub::Message::try_from(msg).map_err(|_| {
            Error::DecodePayload("Invalid gossip message".to_string(), PeerId::random())
        })?;

        match gossip_msg.payload {
            Payload::CommitteeChange {
                new_members,
                new_committee_pub_key,
                ..
            } => {
                let mut state = self.state.lock().await;
                state.update_members(new_members.clone());
                state.set_pub_key(new_committee_pub_key);

                if new_members.contains(&self.self_peer) {
                    let timer = self.timer.lock().await;
                    timer
                        .schedule(Action::Start, self.config.committee_change_buffer_time)
                        .await;
                }

                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_timer_action(self: &Arc<Self>, action: Action) -> Result<()> {
        match action {
            Action::Start => {
                self.is_member.store(true, Ordering::SeqCst);

                let timer = self.timer.lock().await;
                timer
                    .schedule(Action::Stop, self.config.committee_term_duration)
                    .await;
            }
            Action::Stop => {
                self.is_member.store(false, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    async fn handle_signature_request(self: &Arc<Self>, msg: Message) -> Result<()> {
        if !self.is_member.load(Ordering::SeqCst) {
            return Ok(());
        }

        let gossip_msg = match gossipsub::Message::try_from(msg) {
            Ok(msg) => msg,
            Err(_) => {
                error!("Failed to decode signature request message");
                return Ok(());
            }
        };

        match gossip_msg.payload {
            Payload::CommitteeSignatureRequest(payload) => {
                self.process_signature_reqeust(gossip_msg.message_id, payload)
                    .await?;
            }
            Payload::CommitteeSignatureResponse {
                request_msg_id,
                partial_sig,
            } => {
                self.process_signature_response(request_msg_id, gossip_msg.source, partial_sig)
                    .await?;
            }
            _ => {}
        }

        Ok(())
    }

    async fn process_signature_reqeust(
        self: &Arc<Self>,
        msg_id: MessageId,
        payload: kad::Payload,
    ) -> Result<()> {
        if let kad::Payload::PeerInfo { .. } = payload {
            self.validate_peer_info(&payload).await?;
        }

        self.process_validated_signature_request(msg_id, payload)
            .await
    }

    async fn validate_peer_info(self: &Arc<Self>, payload: &kad::Payload) -> Result<()> {
        if let kad::Payload::PeerInfo { peer_id, pub_key } = payload {
            let pub_key = PublicKey::try_decode_protobuf(pub_key)?;
            let expected = PeerId::from_public_key(&pub_key);

            if expected != *peer_id {
                return Err(Error::PeerInfoVerificationFailed(*peer_id));
            }
        }

        Ok(())
    }

    async fn process_validated_signature_request(
        self: &Arc<Self>,
        msg_id: MessageId,
        kad_payload: kad::Payload,
    ) -> Result<()> {
        let signature = self
            .dkg
            .sign(&msg_id.to_string().into_bytes(), &kad_payload.to_vec()?);

        self.publish_signature(msg_id.clone(), signature.clone())
            .await?;

        self.process_signature_aggregation(msg_id, self.self_peer, signature, Some(kad_payload))
            .await
    }

    async fn publish_signature(
        self: &Arc<Self>,
        request_msg_id: MessageId,
        partial_signature: Data,
    ) -> Result<()> {
        let payload = Payload::CommitteeSignatureResponse {
            request_msg_id,
            partial_sig: partial_signature,
        };

        self.transport
            .publish(SIGNATURE_REQUEST_TOPIC, payload)
            .await
            .map_err(Error::Transport)?;
        Ok(())
    }

    async fn process_signature_aggregation(
        self: &Arc<Self>,
        msg_id: MessageId,
        peer: PeerId,
        signature: Data,
        payload: Option<kad::Payload>,
    ) -> Result<()> {
        let mut state = self.state.lock().await;

        let index = state.get_peer_index(peer).ok_or(Error::PeerIndexNotFound)?;

        if let Some(result) = state
            .add_signature(msg_id.clone(), index, signature)
            .or_else(|| payload.and_then(|p| state.set_payload(msg_id, p)))
        {
            drop(state);
            self.finalize_aggregated_signature(result).await?;
        }

        Ok(())
    }

    async fn finalize_aggregated_signature(
        self: &Arc<Self>,
        result: SignatureResult,
    ) -> Result<()> {
        let aggregated_signature = self
            .dkg
            .aggregate(&result.indices, result.signatures)
            .map_err(|e| Error::SignatureAggregation(e.to_string()))?;

        self.transport
            .put(result.payload, aggregated_signature)
            .await
            .map_err(Error::Transport)
    }

    async fn process_signature_response(
        self: &Arc<Self>,
        msg_id: MessageId,
        peer: PeerId,
        signature: Data,
    ) -> Result<()> {
        self.process_signature_aggregation(msg_id, peer, signature, None)
            .await
    }
}
