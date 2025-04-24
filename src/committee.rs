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
    committee::{config::Config, info::Info, timer::Timer},
    crypto::{
        dkg::{self, Dkg},
        index_map::IndexedMap,
        keypair::{self, PublicKey, SecretKey},
        primitives::algebra::{self, Point, Scalar},
        tss::{self, Tss},
    },
    network::transport::{
        libp2p_transport::protocols::gossipsub::{payload, Message, Payload},
        Transport,
    },
};

pub mod config;
mod election;
pub mod info;
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

    #[error("{0}")]
    Signature(#[from] tss::SignatureError),

    #[error("{0}")]
    Keypair(#[from] keypair::Error),

    #[error("{0}")]
    Election(#[from] election::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
enum Action {
    RemoveOldCommittee,
    ElectNewCommittee,
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
    secret_key: SecretKey,
    public_key: PublicKey,
    handler: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
    timer: TokioMutex<Timer<Action>>,
    current_committee: TokioRwLock<Info>,
    next_committee: TokioRwLock<Option<Info>>,
    is_member: AtomicBool,
    config: Config,
    election: election::Election,
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
        secret_key: SecretKey,
        public_key: PublicKey,
        current_committee: Info,
        config: Config,
    ) -> Result<Arc<Self>> {
        let (timer, timer_rx) = Timer::new().await;
        let timer = TokioMutex::new(timer);

        let election = election::Election::new(secret_key.clone(), public_key.clone());

        let self_arc = Arc::new(Self {
            transport,
            dkg: TokioRwLock::new(dkg),
            tss: TokioRwLock::new(tss),
            secret_key,
            public_key,
            handler: TokioMutex::new(None),
            timer,
            current_committee: TokioRwLock::new(current_committee),
            next_committee: TokioRwLock::new(None),
            is_member: AtomicBool::new(false),
            config,
            election,
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
                        Action::ElectNewCommittee => {
                            if let Err(e) = self.processs_elect_new_committee_action().await {
                                log::error!("Error electing new committee: {:?}", e);
                            }
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
                epoch,
                members,
                public_key,
                ..
            } => {
                self.process_committee_change(epoch, members, public_key)
                    .await;
                Ok(())
            }
            Payload::CommitteeElection { seed, .. } => {
                self.process_committee_election_request(&seed).await
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

        {
            let curr_committee_pk = &self.current_committee.read().await.public_key;
            if signature.verify(&hash, curr_committee_pk) {
                return Ok(hash_vec);
            }
        }

        if let Some(next_committee) = self.next_committee.read().await.as_ref() {
            let next_committee_pk = &next_committee.public_key;
            if signature.verify(&hash, next_committee_pk) {
                return Ok(hash_vec);
            }
        }

        Err(Error::InvalidSignature(msg.source))
    }

    async fn is_peer_in_committee(&self, peer_id: &libp2p::PeerId) -> bool {
        {
            let curr_members = &self.current_committee.read().await.members;
            if curr_members.contains_key(peer_id) {
                return true;
            }
        }

        if let Some(next_committee) = self.next_committee.read().await.as_ref() {
            let next_members = &next_committee.members;
            if next_members.contains_key(peer_id) {
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
        epoch: u64,
        member: IndexedMap<libp2p::PeerId, PublicKey>,
        public_key: Point,
    ) {
        if member.contains_key(&self.transport.self_peer()) {
            self.is_member.store(true, Ordering::SeqCst);
            self.timer
                .lock()
                .await
                .schedule(Action::RemoveOldCommittee, self.config.buffer_time)
                .await;
        } else {
            self.is_member.store(false, Ordering::SeqCst);
        }

        let info = Info::new(epoch, member, public_key);
        self.next_committee.write().await.replace(info);
    }

    async fn process_committee_election_request(&self, seed: &[u8]) -> Result<()> {
        let payload = self.election.generate_election_response(seed.to_vec())?;

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn process_remove_old_member(&self) {
        if let Some(next_committee) = self.next_committee.write().await.take() {
            *self.current_committee.write().await = next_committee;
        } else {
            panic!("Next committee is not set");
        }

        self.timer
            .lock()
            .await
            .schedule(Action::ElectNewCommittee, self.config.epoch_duration)
            .await;
    }

    async fn processs_elect_new_committee_action(&self) -> Result<()> {
        let payload = self
            .election
            .generate_new_election_request(&self.tss)
            .await?;

        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}
