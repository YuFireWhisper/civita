use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc::Receiver as TokioReceiver, Mutex as TokioMutex, RwLock as TokioRwLock};

use crate::{
    committee::{config::Config, timer::Timer},
    crypto::{
        dkg::{self, Dkg},
        index_map::IndexedMap,
        keypair::PublicKey,
        primitives::algebra::{self, Point, Scalar},
        tss::Tss,
    },
    network::transport::{
        libp2p_transport::protocols::gossipsub::{payload, Message, Payload},
        Transport,
    },
};

pub mod config;
mod timer;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid signature from {0}")]
    InvalidSignature(libp2p::PeerId),

    #[error("Message should from committee member, message source: {0}")]
    NotCommitteeMember(libp2p::PeerId),

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

    #[error("{0}")]
    Payload(#[from] payload::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
enum Action {
    RemoveOldCommittee,
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
    handler: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
    timer: TokioMutex<Timer<Action>>,
    members: TokioRwLock<IndexedMap<libp2p::PeerId, PublicKey>>,
    next_members: TokioRwLock<Option<IndexedMap<libp2p::PeerId, PublicKey>>>,
    committee_pk: TokioRwLock<Point>,
    next_committee_pk: TokioRwLock<Option<Point>>,
    is_member: AtomicBool,
    config: Config,
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
        member: IndexedMap<libp2p::PeerId, PublicKey>,
        config: Config,
    ) -> Result<Arc<Self>> {
        let (timer, timer_rx) = Timer::new().await;
        let timer = TokioMutex::new(timer);

        let self_arc = Arc::new(Self {
            transport,
            dkg: TokioRwLock::new(dkg),
            tss: TokioRwLock::new(tss),
            handler: TokioMutex::new(None),
            timer,
            members: TokioRwLock::new(member),
            next_members: TokioRwLock::new(None),
            committee_pk: TokioRwLock::new(committee_pk),
            next_committee_pk: TokioRwLock::new(None),
            is_member: AtomicBool::new(false),
            config,
        });

        self_arc.clone().start(timer_rx).await?;

        Ok(self_arc)
    }

    async fn start(self: Arc<Self>, timer_rx: TokioReceiver<Action>) -> Result<()> {
        let gossipsub_rx = self
            .transport
            .listen_on_topic(&self.config.topic)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let self_arc = Arc::clone(&self);
        let handler = tokio::spawn({
            async move {
                self_arc.run_loop(gossipsub_rx, timer_rx).await;
            }
        });

        self.handler.lock().await.replace(handler);
        Ok(())
    }

    async fn run_loop(
        self: Arc<Self>,
        mut gossipsub_rx: TokioReceiver<Message>,
        mut timer_rx: TokioReceiver<Action>,
    ) {
        loop {
            tokio::select! {
                Some(msg) = gossipsub_rx.recv() => {
                    if let Err(e) = self.process_message(msg).await {
                        log::error!("Error processing message: {:?}", e);
                    }
                }
                Some(action) = timer_rx.recv() => {
                    match action {
                        Action::RemoveOldCommittee => {
                            self.process_remove_old_member().await;
                        }
                    }
                }
                else => {
                    break;
                }
            }
        }
    }

    async fn process_message(&self, mut msg: Message) -> Result<()> {
        let hash = self.verify_signature(&mut msg).await?;

        match msg.payload {
            Payload::CommitteeCandiates { candidates, .. } => {
                self.process_new_candidates(hash, candidates).await
            }
            Payload::CommitteeChange {
                members,
                new_public_key,
                ..
            } => {
                self.process_committee_change(members, new_public_key).await;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn process_new_candidates(
        &self,
        msg_hash: Vec<u8>,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<()> {
        if !candidates.contains_key(&self.transport.self_peer()) {
            return Ok(());
        }

        let result = {
            let mut dkg = self.dkg.write().await;
            dkg.set_peers(candidates)
                .await
                .map_err(|e| Error::Dkg(e.to_string()))?;
            dkg.generate(msg_hash.clone()).await
        }
        .map_err(|e| Error::Dkg(e.to_string()))?;

        match result {
            dkg::GenerateResult::Success {
                secret,
                partial_publics,
            } => {
                self.process_dkg_generate_success(msg_hash, secret, partial_publics)
                    .await?;
            }
            dkg::GenerateResult::Failure { invalid_peers } => {
                self.process_dkg_generate_failure(msg_hash, invalid_peers)
                    .await?;
            }
        }

        Ok(())
    }

    async fn verify_signature(&self, msg: &mut Message) -> Result<Vec<u8>> {
        if !msg.payload.is_need_committee_signature() {
            let hash = Sha256::digest(&msg.payload.to_vec()?);
            return Ok(hash.to_vec());
        }

        if !self.is_peer_in_committee(&msg.source).await {
            return Err(Error::NotCommitteeMember(msg.source));
        }

        let signature = match msg.payload.take_signature() {
            Some(signature) => signature,
            None => return Err(Error::InvalidSignature(msg.source)),
        };

        let hash = Sha256::digest(&msg.payload.to_vec()?);
        let hash_vec = hash.to_vec();

        let public_key = self.committee_pk.read().await;

        if signature.verify(&hash, &public_key) {
            return Ok(hash_vec);
        }

        if let Some(next_committee_pk) = self.next_committee_pk.read().await.as_ref() {
            if signature.verify(&hash, next_committee_pk) {
                return Ok(hash_vec);
            }
        }

        Err(Error::InvalidSignature(msg.source))
    }

    async fn is_peer_in_committee(&self, peer_id: &libp2p::PeerId) -> bool {
        if self.members.read().await.contains_key(peer_id) {
            return true;
        }

        if let Some(next_committee) = self.next_members.read().await.as_ref() {
            if next_committee.contains_key(peer_id) {
                return true;
            }
        }

        false
    }

    async fn process_dkg_generate_success(
        &self,
        request_hash: Vec<u8>,
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

        let payload = Payload::CommitteeGenerateSuccess {
            request_hash,
            committee_pub_key: public_key,
        };

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn process_dkg_generate_failure(
        &self,
        request_hash: Vec<u8>,
        invalid_peers: HashSet<libp2p::PeerId>,
    ) -> Result<()> {
        let payload = Payload::CommitteeGenerateFailure {
            request_hash,
            invalid_peers,
        };

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn process_committee_change(
        &self,
        member: IndexedMap<libp2p::PeerId, PublicKey>,
        new_public_key: Point,
    ) {
        if member.contains_key(&self.transport.self_peer()) {
            self.is_member.store(true, Ordering::SeqCst);
        } else {
            self.is_member.store(false, Ordering::SeqCst);
        }

        self.next_committee_pk.write().await.replace(new_public_key);
        self.next_members.write().await.replace(member);
        self.timer
            .lock()
            .await
            .schedule(Action::RemoveOldCommittee, self.config.buffer_time)
            .await;
    }

    async fn process_remove_old_member(&self) {
        if let (Some(old_committee_pk), Some(old_committee)) = (
            self.next_committee_pk.write().await.take(),
            self.next_members.write().await.take(),
        ) {
            *self.committee_pk.write().await = old_committee_pk;
            *self.members.write().await = old_committee;
        } else {
            panic!("Next committee public key or members is not set");
        }
    }
}
