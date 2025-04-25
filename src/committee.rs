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
    committee::{config::Config, info::Info, pending_election::PendingElection, timer::Timer},
    crypto::{
        dkg::{self, Dkg},
        index_map::IndexedMap,
        keypair::{self, PublicKey, SecretKey, VrfProof},
        primitives::algebra::{self, Point, Scalar},
        tss::{self, Tss},
    },
    network::transport::{
        libp2p_transport::protocols::gossipsub::{payload, Message, Payload},
        Transport,
    },
};

pub mod config;
pub mod info;
mod pending_election;
mod timer;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid signature from {0}")]
    InvalidSignature(libp2p::PeerId),

    #[error("Message should from committee member, message source: {0}")]
    NotCommitteeMember(libp2p::PeerId),

    #[error("Meessage should from candidate, message source: {0}")]
    NotCandidate(libp2p::PeerId),

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
}

#[derive(Debug)]
enum Action {
    RemoveOldCommittee,
    ElectNewCommittee,
    VoteCollectionDone([u8; 32]),
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
    pending_election: TokioRwLock<Option<PendingElection>>,
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
            pending_election: TokioRwLock::new(None),
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
                self_arc.event_loop(gossipsub_rx, timer_rx).await;
            }
        });

        self.handler.lock().await.replace(handler);

        Ok(())
    }

    async fn event_loop(
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
                    if let Err(e) = self.process_action(action).await {
                        log::error!("Error processing action: {:?}", e);
                    }
                }
                else => {
                    break;
                }
            }
        }
    }

    async fn process_message(&self, mut msg: Message) -> Result<()> {
        if self.is_need_in_committee(&msg) && !self.is_member() {
            return Ok(());
        }

        self.verify_source(&msg).await?;

        let hash = self.verify_signature(&mut msg).await?;

        match msg.payload {
            Payload::CommitteeCandiates { candidates, .. } => {
                self.process_candidate_proposal(hash, candidates).await
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
            Payload::CommitteeElection { seed, .. } => self.process_election_request(seed).await,
            Payload::CommitteeElectionResponse {
                seed,
                public_key,
                proof,
                ..
            } => {
                self.process_election_response(msg.source, seed, public_key, proof)
                    .await
            }
            Payload::CommitteeGenerateSuccess {
                request_hash,
                committee_pub_key,
            } => {
                self.process_dkg_generate_success_reqeust(request_hash, committee_pub_key)
                    .await
            }
            Payload::CommitteeGenerateFailure {
                request_hash,
                invalid_peers,
            } => {
                self.process_dkg_generate_failure_request(request_hash, invalid_peers)
                    .await
            }
            _ => Ok(()),
        }
    }

    fn is_need_in_committee(&self, msg: &Message) -> bool {
        matches!(
            msg.payload,
            Payload::CommitteeElectionResponse { .. }
                | Payload::CommitteeGenerateSuccess { .. }
                | Payload::CommitteeGenerateFailure { .. }
        )
    }

    async fn verify_source(&self, msg: &Message) -> Result<()> {
        if msg.payload.is_need_from_committee() && !self.is_peer_in_committee(&msg.source).await {
            return Err(Error::NotCommitteeMember(msg.source));
        }

        if matches!(
            msg.payload,
            Payload::CommitteeGenerateSuccess { .. } | Payload::CommitteeGenerateFailure { .. }
        ) && !self.is_peer_is_candidate(&msg.source).await
        {
            return Err(Error::NotCandidate(msg.source));
        }

        Ok(())
    }

    async fn is_peer_in_committee(&self, peer_id: &libp2p::PeerId) -> bool {
        self.is_peer_contains_in_current_committee(peer_id).await
            || self.is_peer_contains_in_next_committee(peer_id).await
    }

    async fn is_peer_contains_in_current_committee(&self, peer_id: &libp2p::PeerId) -> bool {
        let curr_members = &self.current_committee.read().await.members;
        curr_members.contains_key(peer_id)
    }

    async fn is_peer_contains_in_next_committee(&self, peer_id: &libp2p::PeerId) -> bool {
        if let Some(next_committee) = self.next_committee.read().await.as_ref() {
            let next_members = &next_committee.members;
            next_members.contains_key(peer_id)
        } else {
            false
        }
    }

    async fn is_peer_is_candidate(&self, source: &libp2p::PeerId) -> bool {
        self.pending_election
            .read()
            .await
            .as_ref()
            .is_some_and(|e| e.is_candidate(source))
    }

    async fn verify_signature(&self, msg: &mut Message) -> Result<[u8; 32]> {
        if !msg.payload.is_need_from_committee() {
            let hash = Sha256::digest(&msg.payload.to_vec()?);
            return Ok(hash.into());
        }

        if !self.is_peer_in_committee(&msg.source).await {
            return Err(Error::NotCommitteeMember(msg.source));
        }

        let signature = match msg.payload.take_signature() {
            Some(signature) => signature,
            None => return Err(Error::InvalidSignature(msg.source)),
        };

        let hash = Sha256::digest(&msg.payload.to_vec()?);

        if self
            .verfiy_signature_with_current_committee(&hash, &signature)
            .await
        {
            return Ok(hash.into());
        }

        if self
            .verify_signature_with_next_committee(&hash, &signature)
            .await
        {
            return Ok(hash.into());
        }

        Err(Error::InvalidSignature(msg.source))
    }

    async fn verfiy_signature_with_current_committee(
        &self,
        hash: &[u8],
        signature: &tss::Signature,
    ) -> bool {
        let curr_committee_pk = &self.current_committee.read().await.public_key;
        signature.verify(hash, curr_committee_pk)
    }

    async fn verify_signature_with_next_committee(
        &self,
        hash: &[u8],
        signature: &tss::Signature,
    ) -> bool {
        if let Some(next_committee) = self.next_committee.read().await.as_ref() {
            if signature.verify(hash, &next_committee.public_key) {
                return true;
            }
        }
        false
    }

    async fn process_candidate_proposal(
        &self,
        msg_hash: [u8; 32],
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<()> {
        if !candidates.contains_key(&self.transport.self_peer()) {
            return Ok(());
        }

        match self.generate_dkg(msg_hash.to_vec(), candidates).await? {
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

    async fn generate_dkg(
        &self,
        msg_hash: Vec<u8>,
        candidates: IndexedMap<libp2p::PeerId, PublicKey>,
    ) -> Result<dkg::GenerateResult> {
        let mut dkg = self.dkg.write().await;
        dkg.set_peers(candidates)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))?;
        dkg.generate(msg_hash)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))
    }

    async fn process_dkg_generate_success(
        &self,
        request_hash: [u8; 32],
        secret: Scalar,
        partial_publics: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let public_key = Point::sum(
            partial_publics
                .values()
                .map(|p| p.first().expect("Publics is empty")),
        )?;

        self.set_tss_keypair(secret, partial_publics).await?;

        let payload = Payload::CommitteeGenerateSuccess {
            request_hash,
            committee_pub_key: public_key,
        };

        self.publish_payload(payload).await?;

        Ok(())
    }

    async fn set_tss_keypair(
        &self,
        secret: Scalar,
        partial_publics: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let mut tss = self.tss.write().await;

        tss.set_keypair(secret, partial_publics)
            .await
            .map_err(|e| Error::Tss(e.to_string()))?;

        Ok(())
    }

    async fn publish_payload(&self, payload: Payload) -> Result<()> {
        self.transport
            .publish(&self.config.topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn process_dkg_generate_failure(
        &self,
        request_hash: [u8; 32],
        invalid_peers: HashSet<libp2p::PeerId>,
    ) -> Result<()> {
        let payload = Payload::CommitteeGenerateFailure {
            request_hash,
            invalid_peers,
        };

        self.publish_payload(payload).await?;

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
            self.schedule_action(Action::RemoveOldCommittee).await;
        } else {
            self.is_member.store(false, Ordering::SeqCst);
        }

        let info = Info::new(epoch, member, public_key);
        self.next_committee.write().await.replace(info);
    }

    async fn schedule_action(&self, action: Action) {
        let delay = match &action {
            Action::RemoveOldCommittee => self.config.buffer_time,
            Action::ElectNewCommittee => self.config.epoch_duration,
            Action::VoteCollectionDone(_) => self.config.vrf_collection_duration,
        };

        self.timer.lock().await.schedule(action, delay).await;
    }

    async fn process_election_request(&self, seed: [u8; 32]) -> Result<()> {
        let proof = self.secret_key.prove(&seed)?;

        let payload = Payload::CommitteeElectionResponse {
            seed,
            public_key: self.public_key.clone(),
            proof,
        };

        self.publish_payload(payload).await?;

        Ok(())
    }

    async fn process_election_response(
        &self,
        source: libp2p::PeerId,
        seed: [u8; 32],
        public_key: PublicKey,
        proof: VrfProof,
    ) -> Result<()> {
        self.add_vote(seed, source, proof.output(), public_key)
            .await
    }

    async fn process_dkg_generate_success_reqeust(
        &self,
        request_hash: [u8; 32],
        public_key: Point,
    ) -> Result<()> {
        if !self.verify_request_hash(request_hash).await {
            return Ok(());
        }

        let next_epoch = self.current_committee.read().await.epoch + 1;
        let memeber = self
            .pending_election
            .write()
            .await
            .as_mut()
            .unwrap()
            .take_candidates()
            .expect("Candidates is empty");

        let mut payload = Payload::CommitteeChange {
            epoch: next_epoch,
            members: memeber.clone(),
            public_key: public_key.clone(),
            signature: None,
        };

        let hash = Sha256::digest(&payload.to_vec()?);
        let signature = self.sign_message(hash.to_vec(), &payload).await?;

        payload.set_signature(signature);

        let info = Info::new(next_epoch, memeber, public_key);

        self.next_committee.write().await.replace(info);

        self.publish_payload(payload).await?;

        Ok(())
    }

    async fn verify_request_hash(&self, request_hash: [u8; 32]) -> bool {
        let guard = self.pending_election.read().await;
        let pending_election = match guard.as_ref() {
            Some(pending_election) => pending_election,
            None => return false,
        };

        let expected_hash = match pending_election.message_hash() {
            Some(hash) => hash,
            None => return false,
        };

        expected_hash == request_hash
    }

    async fn process_dkg_generate_failure_request(
        &self,
        request_hash: [u8; 32],
        invalid_peers: HashSet<libp2p::PeerId>,
    ) -> Result<()> {
        self.pending_election
            .write()
            .await
            .as_mut()
            .expect("Pending election is not set")
            .remove_votes(invalid_peers.iter());

        if !self.verify_request_hash(request_hash).await {
            return Ok(());
        }

        self.generate_and_publish_new_candidate(request_hash)
            .await?;

        Ok(())
    }

    async fn add_vote(
        &self,
        seed: [u8; 32],
        peer_id: libp2p::PeerId,
        output: [u8; 32],
        public_key: PublicKey,
    ) -> Result<()> {
        if let Some(pending_election) = self.pending_election.write().await.as_mut() {
            if pending_election.seed() != seed {
                return Ok(());
            }
            pending_election.add_vote(peer_id, output, public_key);
        }
        Ok(())
    }

    fn is_member(&self) -> bool {
        self.is_member.load(Ordering::SeqCst)
    }

    async fn process_action(&self, action: Action) -> Result<()> {
        match action {
            Action::RemoveOldCommittee => self.process_remove_old_member().await,
            Action::ElectNewCommittee => self.processs_elect_new_committee_action().await?,
            Action::VoteCollectionDone(seed) => self.process_vote_collection_done(seed).await?,
        }
        Ok(())
    }

    async fn process_remove_old_member(&self) {
        self.replace_committee().await;
        self.schedule_action(Action::ElectNewCommittee).await;
    }

    async fn replace_committee(&self) {
        if let Some(next_committee) = self.next_committee.write().await.take() {
            *self.current_committee.write().await = next_committee;
        } else {
            panic!("Next committee is not set");
        }
    }

    async fn processs_elect_new_committee_action(&self) -> Result<()> {
        let (payload, seed) = self.generate_election_request().await?;

        self.publish_payload(payload).await?;
        self.set_empty_pending_election(seed).await;
        self.schedule_action(Action::VoteCollectionDone(seed)).await;

        Ok(())
    }

    async fn generate_election_request(&self) -> Result<(Payload, [u8; 32])> {
        const SEED: &[u8] = b"election_request";

        let seed = Sha256::digest(SEED);
        let mut payload = Payload::CommitteeElection {
            seed: seed.into(),
            signature: None,
        };

        let signature = self.sign_message(seed.to_vec(), &payload).await?;
        payload.set_signature(signature);

        Ok((payload, seed.into()))
    }

    async fn set_empty_pending_election(&self, seed: [u8; 32]) {
        self.pending_election
            .write()
            .await
            .replace(PendingElection::new(seed));
    }

    async fn process_vote_collection_done(&self, seed: [u8; 32]) -> Result<()> {
        self.generate_and_publish_new_candidate(seed).await
    }

    async fn generate_and_publish_new_candidate(&self, seed: [u8; 32]) -> Result<()> {
        let (candidates, generate_count) = self
            .pending_election
            .write()
            .await
            .as_mut()
            .expect("Pending election is not set")
            .generate_candidates(self.config.max_num_members);

        let mut payload = Payload::CommitteeCandiates {
            count: generate_count,
            candidates,
            signature: None,
        };

        let hash = Sha256::digest(&payload.to_vec()?);
        self.pending_election
            .write()
            .await
            .as_mut()
            .expect("Pending election is not set")
            .set_message_hash(hash.into());

        let signature = self.sign_message(seed.to_vec(), &payload).await?;
        payload.set_signature(signature);

        self.publish_payload(payload).await?;

        Ok(())
    }

    async fn sign_message(&self, seed: Vec<u8>, payload: &Payload) -> Result<tss::Signature> {
        self.tss
            .read()
            .await
            .sign(seed, &payload.to_vec()?)
            .await
            .map_err(|e| Error::Tss(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        committee::{self},
        crypto::{
            dkg::MockDkg,
            keypair::{self},
            primitives::algebra::Point,
            tss::MockTss,
        },
        network::transport::MockTransport,
    };

    fn setup_mock_transport() -> Arc<MockTransport> {
        let mut transport = MockTransport::new();

        transport
            .expect_self_peer()
            .returning(libp2p::PeerId::random);

        transport.expect_listen_on_topic().returning(|_| {
            let (_, rx) = tokio::sync::mpsc::channel(100);
            Ok(rx)
        });

        Arc::new(transport)
    }

    #[tokio::test]
    async fn initialize_correctly() {
        let transport = setup_mock_transport();
        let dkg = MockDkg::new();
        let tss = MockTss::new();
        let (secret_key, public_key) = keypair::generate_secp256k1();
        let current_committee =
            committee::Info::new(1, Default::default(), Point::secp256k1_zero());
        let config = committee::Config::default();

        let committee = committee::Committee::new(
            transport,
            dkg,
            tss,
            secret_key.clone(),
            public_key.clone(),
            current_committee,
            config,
        )
        .await;

        assert!(
            committee.is_ok(),
            "Failed to initialize committee: {:?}",
            committee.err()
        );
        let committee = committee.unwrap();
        assert_eq!(committee.secret_key, secret_key);
        assert_eq!(committee.public_key, public_key);
        assert_eq!(committee.current_committee.read().await.epoch, 1);
    }
}
