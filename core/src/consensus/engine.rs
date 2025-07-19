use std::sync::Arc;

use civita_serialize::Serialize;
use dashmap::DashMap;
use derivative::Derivative;
use libp2p::{gossipsub::MessageAcceptance, request_response::Message, PeerId};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use vdf::{WesolowskiVDF, VDF};

use crate::{
    consensus::{
        block::{self, tree::Tree, Block},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    network::{
        gossipsub,
        request_response::{self, RequestResponse},
        Gossipsub, Transport,
    },
    resident,
    utils::{
        bi_channel::{self, BiChannel},
        trie,
    },
};

type Trie<H> = trie::Trie<H>;
type Result<T, E = Error> = std::result::Result<T, E>;
type ValidationChannel = BiChannel<Proposal, Option<Proposal>>;

const TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(1);

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    BiChannel(#[from] bi_channel::Error),

    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),

    #[error(transparent)]
    RequestResponse(#[from] request_response::Error),

    #[error(transparent)]
    Proposal(#[from] proposal::Error),
}

#[derive(Default)]
struct Proposals {
    validated: DashMap<Multihash, (Proposal, proposal::Witness)>,
    waiting_parent: DashMap<Multihash, Vec<(Proposal, proposal::Witness)>>,
}

struct VdfExecutor {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<(Vec<u8>, u64)>,
    vdf: WesolowskiVDF,
    cur_task: Option<oneshot::Receiver<Vec<u8>>>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct EngineBuilder<H: Hasher> {
    gossipsub: Option<Arc<Gossipsub>>,
    req_resp: Option<Arc<RequestResponse>>,
    validation_channel: Option<Mutex<ValidationChannel>>,
    block_tree: Option<RwLock<Tree<H>>>,
    sk: Option<SecretKey>,
    vdf: Option<WesolowskiVDF>,
    vdf_difficulty: Option<u64>,
    proposal_topic: Option<u8>,
    block_topic: Option<u8>,
}

pub struct Engine<H: Hasher> {
    gossipsub: Arc<Gossipsub>,
    req_resp: Arc<RequestResponse>,
    props: Proposals,
    waiting_blocks: DashMap<Multihash, Vec<Block>>,
    validation_channel: Mutex<ValidationChannel>,
    block_tree: RwLock<Tree<H>>,
    sk: SecretKey,
    vdf: WesolowskiVDF,
    vdf_difficulty: u64,
    proposal_topic: u8,
    block_topic: u8,
    vdf_task_tx: mpsc::UnboundedSender<(Vec<u8>, u64)>,
    vdf_result_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl VdfExecutor {
    pub async fn spawn(
        vdf: WesolowskiVDF,
    ) -> (
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedSender<(Vec<u8>, u64)>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = mpsc::unbounded_channel();

        let executor = Self {
            tx: result_tx,
            rx,
            vdf,
            cur_task: None,
        };

        tokio::spawn(executor.run());

        (result_rx, tx)
    }

    async fn run(mut self) {
        let mut cur: Option<oneshot::Receiver<Vec<u8>>> = None;

        loop {
            tokio::select! {
                Some((challenge, difficulty)) = self.rx.recv() => {
                    self.on_recv_task(challenge, difficulty).await;
                }
                Some(res) = async {
                    match &mut cur {
                        Some(rx) => Some(rx.await),
                        None => None,
                    }
                } => {
                    cur = None;

                    if let Ok(res) = res {
                        self.tx.send(res).expect("Failed to send VDF result");
                    }
                }
            }
        }
    }

    async fn on_recv_task(&mut self, challenge: Vec<u8>, difficulty: u64) {
        if let Some(task) = self.cur_task.take() {
            drop(task);
        }

        let (tx, rx) = oneshot::channel();
        let vdf = self.vdf.clone();

        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                vdf.solve(&challenge, difficulty)
                    .expect("VDF proof should be valid")
            })
            .await;

            if let Ok(res) = res {
                let _ = tx.send(res);
            }
        });

        self.cur_task = Some(rx);
    }
}

#[allow(dead_code)]
impl<H: Hasher> EngineBuilder<H> {
    pub fn with_transport(mut self, transport: Arc<Transport>) -> Self {
        self.gossipsub = Some(transport.gossipsub());
        self.req_resp = Some(transport.request_response());
        self.sk = Some(transport.secret_key().clone());
        self
    }

    pub fn with_validation_channel(mut self, channel: ValidationChannel) -> Self {
        self.validation_channel = Some(Mutex::new(channel));
        self
    }

    pub fn with_block_tree(mut self, tree: Tree<H>) -> Self {
        self.block_tree = Some(RwLock::new(tree));
        self
    }

    pub fn with_vdf(mut self, vdf: WesolowskiVDF, difficulty: u64) -> Self {
        self.vdf = Some(vdf);
        self.vdf_difficulty = Some(difficulty);
        self
    }

    pub fn with_topics(mut self, proposal_topic: u8, block_topic: u8) -> Self {
        self.proposal_topic = Some(proposal_topic);
        self.block_topic = Some(block_topic);
        self
    }

    pub async fn build(self) -> Option<Engine<H>> {
        let gossipsub = self.gossipsub?;
        let req_resp = self.req_resp?;
        let props = Proposals::default();
        let waiting_blocks = DashMap::new();
        let validation_channel = self.validation_channel?;
        let block_tree = self.block_tree?;
        let sk = self.sk?;
        let vdf = self.vdf?;
        let vdf_difficulty = self.vdf_difficulty?;
        let proposal_topic = self.proposal_topic?;
        let block_topic = self.block_topic?;

        let (vdf_result_rx, vdf_task_tx) = VdfExecutor::spawn(vdf.clone()).await;

        Some(Engine {
            gossipsub,
            req_resp,
            props,
            waiting_blocks,
            validation_channel,
            block_tree,
            sk,
            vdf,
            vdf_difficulty,
            proposal_topic,
            block_topic,
            vdf_task_tx,
            vdf_result_rx: Some(vdf_result_rx),
        })
    }
}

impl<H: Hasher> Engine<H> {
    #[allow(dead_code)]
    pub async fn propose(&self, prop: Proposal) -> Result<()> {
        let witness = prop.generate_witness(
            &self.sk,
            self.block_tree.read().await.get_leaf_trie(),
            &self.vdf,
            self.vdf_difficulty,
        )?;

        let mut bytes = Vec::new();
        prop.to_writer(&mut bytes);
        witness.to_writer(&mut bytes);

        self.gossipsub.publish(self.proposal_topic, bytes).await?;
        self.props
            .validated
            .insert(prop.hash::<H>(), (prop, witness));

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn run(&mut self) -> Result<()> {
        let mut prop_rx = self.gossipsub.subscribe(self.proposal_topic).await?;
        let mut block_rx = self.gossipsub.subscribe(self.block_topic).await?;
        let req_resp = self.req_resp.clone();
        let mut vdf_result_rx = self
            .vdf_result_rx
            .take()
            .expect("VDF result receiver should be set");

        self.start_vdf_mining().await;

        loop {
            tokio::select! {
                Some(msg) = prop_rx.recv() => {
                    self.on_recv_proposal(msg).await;
                }
                Some(msg) = block_rx.recv() => {
                    self.on_recv_block(msg).await;
                }
                Some(msg) = req_resp.recv() => {
                    if let Message::Request { request, channel, .. } = msg {
                        let Ok(hash) = Multihash::from_slice(&request) else {
                            continue;
                        };

                        if let Some(entry) = self.props.validated.get(&hash) {
                            let bytes = (entry.value()).to_vec();
                            req_resp.send_response(channel, bytes).await?;
                        }
                    }
                },
                Some(vdf_result) = vdf_result_rx.recv() => {
                    if let Err(e) = self.on_vdf_solved(vdf_result).await {
                        log::error!("Failed to handle VDF result: {e}");
                    }
                }
            }
        }
    }

    async fn start_vdf_mining(&self) {
        let leaf_hash = self.block_tree.read().await.get_leaf_hash().to_vec();
        let self_pk_bytes = self.sk.public_key().to_hash::<H>().to_vec();

        let mut challenge_data = Vec::with_capacity(leaf_hash.len() + self_pk_bytes.len());
        challenge_data.extend_from_slice(&leaf_hash);
        challenge_data.extend_from_slice(&self_pk_bytes);
        let challenge = H::hash(&challenge_data).to_bytes();

        if let Err(e) = self.vdf_task_tx.send((challenge, self.vdf_difficulty)) {
            log::error!("Failed to send VDF task: {e}");
        }
    }

    async fn on_recv_proposal(&self, msg: gossipsub::Message) {
        let acceptance = self.verify_proposal(msg.data.as_ref()).await;

        self.gossipsub
            .report_validation_result(&msg.id, &msg.propagation_source, acceptance)
            .await;
    }

    async fn verify_proposal(&self, bytes: &[u8]) -> MessageAcceptance {
        let Ok(prop) = Proposal::from_slice(bytes) else {
            return MessageAcceptance::Reject;
        };

        let Ok(witness) = proposal::Witness::from_slice(bytes) else {
            return MessageAcceptance::Reject;
        };

        self.verify_proposal_with_deserialized(prop, witness).await
    }

    async fn verify_proposal_with_deserialized(
        &self,
        prop: Proposal,
        witness: proposal::Witness,
    ) -> MessageAcceptance {
        let hash = prop.hash::<H>();

        if self.props.validated.contains_key(&hash) {
            return MessageAcceptance::Accept;
        }

        if !prop.verify_signature::<H>(&witness) {
            return MessageAcceptance::Reject;
        }

        if !prop.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            return MessageAcceptance::Reject;
        }

        let tree = self.block_tree.read().await;

        if prop.parent_checkpoint != tree.checkpoint_hash() {
            return MessageAcceptance::Ignore;
        }

        let Some(parent_node) = tree.get_node(&prop.parent) else {
            self.props
                .waiting_parent
                .entry(prop.parent)
                .or_default()
                .push((prop, witness));
            return MessageAcceptance::Ignore;
        };

        let parent = &parent_node.block;

        if parent.height <= tree.checkpoint().height {
            return MessageAcceptance::Reject;
        }

        if !prop.verify_proposer_weight::<H>(&witness, parent_node.trie.root_hash()) {
            return MessageAcceptance::Reject;
        }

        if !prop.verify_diffs(&witness, parent_node.trie.root_hash()) {
            return MessageAcceptance::Reject;
        }

        let mut channel = self.validation_channel.lock().await;

        if let Some(prop) = channel.send_and_recv(prop).await.ok().flatten() {
            self.props.validated.insert(hash, (prop, witness));
            return MessageAcceptance::Accept;
        }

        MessageAcceptance::Reject
    }

    async fn on_recv_block(&self, msg: gossipsub::Message) {
        let acceptance = self.verify_block(msg.data.as_ref()).await;

        if matches!(acceptance, MessageAcceptance::Accept) {
            self.start_vdf_mining().await;
        }

        self.gossipsub
            .report_validation_result(&msg.id, &msg.propagation_source, acceptance)
            .await;
    }

    async fn verify_block(&self, msg: &[u8]) -> MessageAcceptance {
        let Ok(block) = Block::from_slice(msg) else {
            return MessageAcceptance::Reject;
        };

        let Ok(witness) = block::Witness::from_slice(msg) else {
            return MessageAcceptance::Reject;
        };

        if !block.verify_signature::<H>(&witness) {
            return MessageAcceptance::Reject;
        }

        if !block.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            return MessageAcceptance::Reject;
        }

        let tree = self.block_tree.read().await;

        let checkpoint = tree.checkpoint();

        if block.parent_checkpoint != checkpoint.hash::<H>() {
            return MessageAcceptance::Ignore;
        }

        let Some(parent_node) = tree.get_node(&block.parent) else {
            self.waiting_blocks
                .entry(block.parent)
                .or_default()
                .push(block);
            return MessageAcceptance::Ignore;
        };

        if block.height != parent_node.block.height.wrapping_add(1) {
            return MessageAcceptance::Reject;
        }

        if block.height <= checkpoint.height {
            return MessageAcceptance::Reject;
        }

        if !block.verify_proposer_weight::<H>(&witness, parent_node.trie.root_hash()) {
            return MessageAcceptance::Reject;
        }

        let block_hash = block.hash::<H>();
        let acceptance = self.try_update_block(block).await;

        if !matches!(acceptance, MessageAcceptance::Accept) {
            return acceptance;
        }

        if let Some(blocks) = self.waiting_blocks.remove(&block_hash) {
            for block in blocks.1.into_iter().rev() {
                let _ = self.try_update_block(block).await;
            }
        }

        let leaf = tree.get_leaf_hash();
        self.props.validated.retain(|_, v| v.0.parent == leaf);

        MessageAcceptance::Accept
    }

    async fn try_update_block(&self, block: Block) -> MessageAcceptance {
        let pk_hash = block.proposer_pk.to_hash::<H>();
        let peer = PeerId::from_multihash(pk_hash).expect("PeerId should be valid");

        let Some(trie) = self
            .block_tree
            .read()
            .await
            .get_trie(&block.parent)
            .cloned()
        else {
            return MessageAcceptance::Ignore;
        };

        let (acceptance, trie_opt) = self.collect_proposals(peer, &block.proposals, trie).await;

        if !matches!(acceptance, MessageAcceptance::Accept) {
            return acceptance;
        }

        let Some((trie, total_weight_diff)) = trie_opt else {
            unreachable!("If acceptance is Accept, trie should be Some");
        };

        if self
            .block_tree
            .write()
            .await
            .update(block, trie, total_weight_diff)
        {
            MessageAcceptance::Accept
        } else {
            MessageAcceptance::Ignore
        }
    }

    async fn collect_proposals<'a, I>(
        &self,
        peer: PeerId,
        hashes: I,
        mut trie: Trie<H>,
    ) -> (MessageAcceptance, Option<(Trie<H>, i32)>)
    where
        I: IntoIterator<Item = &'a Multihash>,
    {
        let mut total_weight_diff = 0;

        for hash in hashes {
            if let Some((_, pair)) = self.props.validated.remove(hash) {
                total_weight_diff += pair.0.total_weight_diff;
                continue;
            }

            let Some(bytes) = self.fetch_proposal(peer, hash).await else {
                return (MessageAcceptance::Ignore, None);
            };

            let acceptance = self.verify_proposal(&bytes).await;

            if !matches!(acceptance, MessageAcceptance::Accept) {
                return (acceptance, None);
            }

            let entry = self
                .props
                .validated
                .get(hash)
                .expect("Proposal should be validated");
            let prop = &entry.value().0;
            let proofs = Some(&entry.value().1.proofs);

            for (key, diff) in prop.diffs.iter() {
                if !trie.update(key, diff.to.to_vec(), proofs) {
                    return (MessageAcceptance::Reject, None);
                }
            }

            total_weight_diff += prop.total_weight_diff;
        }

        trie.commit();

        let own_pk_bytes = self.sk.public_key().to_hash::<H>().to_bytes();
        trie.reduce_one(&own_pk_bytes);

        (MessageAcceptance::Accept, Some((trie, total_weight_diff)))
    }

    async fn fetch_proposal(&self, peer: PeerId, hash: &Multihash) -> Option<Vec<u8>> {
        self.req_resp
            .send_reqeust_and_wait(peer, hash.to_bytes(), TIMEOUT)
            .await
            .ok()
    }

    async fn on_vdf_solved(&self, proof: Vec<u8>) -> Result<()> {
        let tree = self.block_tree.read().await;

        let proposer_weight = tree
            .get_leaf_trie()
            .get(&self.sk.public_key().to_hash::<H>().to_bytes())
            .map_or(0, |v| resident::Record::from_slice(&v).unwrap().weight);

        let block = block::Builder::new()
            .with_parent_block::<H>(tree.get_leaf())
            .with_checkpoint::<H>(tree.checkpoint())
            .with_proposals(self.props.validated.iter().map(|v| *v.key()))
            .with_proposer_pk(self.sk.public_key())
            .with_proposer_weight(proposer_weight)
            .build();

        let witness = block
            .generate_witness(&self.sk, tree.get_leaf_trie(), proof)
            .expect("Failed to generate block witness");

        let bytes = (block, witness).to_vec();

        self.gossipsub.publish(self.block_topic, bytes).await?;

        Ok(())
    }
}
