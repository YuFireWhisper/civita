use std::{
    collections::{BTreeSet, HashMap},
    ops::Deref,
    sync::{Arc, OnceLock},
};

use civita_serialize::Serialize;
use dashmap::DashMap;
use derivative::Derivative;
use libp2p::{request_response::Message, PeerId};
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
    mpt: Option<RwLock<Trie<H>>>,
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
    mpt: RwLock<Trie<H>>,
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

    pub fn with_mpt(mut self, mpt: Trie<H>) -> Self {
        self.mpt = Some(RwLock::new(mpt));
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
        let mpt = self.mpt?;
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
            mpt,
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
            self.mpt.read().await.deref(),
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
                Some(bytes) = prop_rx.recv() => {
                    let mut bytes = bytes.as_slice();

                    let Ok(prop) = Proposal::from_reader(&mut bytes) else {
                        log::error!("Failed to deserialize proposal");
                        continue;
                    };

                    let Ok(witness) = proposal::Witness::from_reader(&mut bytes) else {
                        log::error!("Failed to deserialize proposal witness");
                        continue;
                    };

                    if let Err(e) = self.on_recv_proposal(prop, witness).await {
                        log::error!("Failed to handle proposal: {e}");
                    }
                }
                Some(bytes) = block_rx.recv() => {
                    let mut bytes = bytes.as_slice();

                    let Ok(block) = Block::from_reader(&mut bytes) else {
                        log::error!("Failed to deserialize block");
                        continue;
                    };

                    let Ok(witness) = block::Witness::from_reader(&mut bytes) else {
                        log::error!("Failed to deserialize block witness");
                        continue;
                    };

                    match self.on_recv_block(block, witness).await {
                        Ok(true) => {
                            self.start_vdf_mining().await;
                        }
                        Ok(false) => {
                            continue;
                        }
                        Err(e) => {
                            log::error!("Failed to handle block: {e}");
                        }
                    }
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

    async fn on_recv_proposal(&self, prop: Proposal, witness: proposal::Witness) -> Result<()> {
        let hash = prop.hash::<H>();

        if self.props.validated.contains_key(&hash) {
            return Ok(());
        }

        let tree = self.block_tree.read().await;
        let Some(node) = tree.get_node(&prop.parent) else {
            self.props
                .waiting_parent
                .entry(prop.parent)
                .or_default()
                .push((prop, witness));
            return Ok(());
        };

        let parent = &node.block;
        let trie_root = node.trie.root_hash();

        if let Some(prop) = self
            .verify_proposal(prop, &witness, parent, trie_root)
            .await
        {
            self.props.validated.insert(hash, (prop, witness));
        }

        Ok(())
    }

    async fn verify_proposal(
        &self,
        prop: Proposal,
        witness: &proposal::Witness,
        parent: &Block,
        trie_root: Multihash,
    ) -> Option<Proposal> {
        if !prop.verify::<H>(
            witness,
            parent,
            self.block_tree.read().await.checkpoint(),
            trie_root,
            &self.vdf,
            self.vdf_difficulty,
        ) {
            return None;
        }

        let mut channel = self.validation_channel.lock().await;
        channel.send_and_recv(prop).await.ok().flatten()
    }

    async fn on_recv_block(&self, block: Block, witness: block::Witness) -> Result<bool> {
        if !block.verify::<H>(
            &witness,
            self.block_tree.read().await.checkpoint(),
            &self.vdf,
            self.vdf_difficulty,
        ) {
            return Ok(false);
        }

        let hash = block.hash::<H>();

        let tree = self.block_tree.read().await;
        let Some(parent) = tree.get_block(&block.parent) else {
            let mut bs = self
                .waiting_blocks
                .remove(&hash)
                .map(|(_, bs)| bs)
                .unwrap_or_default();
            let p = block.parent;
            bs.push(block);
            self.waiting_blocks.insert(p, bs);
            return Ok(false);
        };

        if parent.height != block.height.wrapping_add(1) {
            return Ok(false);
        }

        let mut bs = self
            .waiting_blocks
            .remove(&hash)
            .map(|(_, bs)| bs)
            .unwrap_or_default();
        bs.push(block);

        for block in bs.into_iter().rev() {
            if !self.try_update_block(block).await {
                return Ok(false);
            }
        }

        let leaf_hash = self.block_tree.read().await.get_leaf_hash();
        self.props.validated.retain(|_, v| v.0.parent == leaf_hash);

        Ok(true)
    }

    async fn try_update_block(&self, block: Block) -> bool {
        let pk_hash = block.proposer_pk.to_hash::<H>();
        let peer = PeerId::from_multihash(pk_hash).expect("PeerId should be valid");

        let Some(trie) = self
            .block_tree
            .read()
            .await
            .get_trie(&block.parent)
            .cloned()
        else {
            return false;
        };

        let Some((props, trie)) = self
            .collect_proposals(peer, &block, &block.proposals, trie)
            .await
        else {
            return false;
        };

        self.block_tree.write().await.update(block, &props, trie)
    }

    async fn collect_proposals<'a, I>(
        &self,
        peer: PeerId,
        parent: &Block,
        hashes: I,
        mut trie: Trie<H>,
    ) -> Option<(HashMap<Multihash, Proposal>, Trie<H>)>
    where
        I: IntoIterator<Item = &'a Multihash>,
    {
        let trie_root = trie.root_hash();

        let mut props = HashMap::new();

        for hash in hashes {
            if let Some((_, pair)) = self.props.validated.remove(hash) {
                props.insert(*hash, pair.0);
                continue;
            }

            let Some(((prop, witness), checked)) = self.take_or_fetch_proposal(peer, hash).await
            else {
                continue;
            };

            if checked {
                props.insert(*hash, prop);
                continue;
            }

            let prop = self
                .verify_proposal(prop, &witness, parent, trie_root)
                .await?;

            let proofs = Some(&witness.proofs);

            for (key, diff) in prop.diffs.iter() {
                if !trie.update(key, diff.to.to_vec(), proofs) {
                    return None;
                }
            }

            props.insert(*hash, prop);
        }

        trie.commit();

        let own_pk_bytes = self.sk.public_key().to_hash::<H>().to_bytes();
        trie.reduce_one(&own_pk_bytes);

        Some((props, trie))
    }

    async fn take_or_fetch_proposal(
        &self,
        peer: PeerId,
        hash: &Multihash,
    ) -> Option<((Proposal, proposal::Witness), bool)> {
        if let Some((_, pair)) = self.props.validated.remove(hash) {
            return Some((pair, true));
        }

        let bytes = self
            .req_resp
            .send_reqeust_and_wait(peer, hash.to_bytes(), TIMEOUT)
            .await
            .ok()?;

        let prop = Proposal::from_slice(&bytes).ok()?;
        let witness = proposal::Witness::from_slice(&bytes).ok()?;

        Some(((prop, witness), false))
    }

    async fn on_vdf_solved(&self, proof: Vec<u8>) -> Result<()> {
        let tree = self.block_tree.read().await;
        let leaf = tree.get_leaf();

        let parent = leaf.hash();
        let parent_checkpoint = tree.checkpoint_hash();
        let height = leaf.block.height.wrapping_add(1);
        let props = self
            .props
            .validated
            .iter()
            .map(|v| *v.key())
            .collect::<BTreeSet<_>>();
        let proposer_pk = self.sk.public_key();
        let proposer_weight = self
            .mpt
            .read()
            .await
            .get(&proposer_pk.to_hash::<H>().to_bytes())
            .map_or(0, |v| resident::Record::from_slice(&v).unwrap().weight);

        let block = Block {
            parent,
            parent_checkpoint,
            height,
            proposals: props,
            proposer_pk,
            proposer_weight,
            hash_cache: OnceLock::new(),
        };

        let witness = block
            .generate_witness(&self.sk, &leaf.trie, proof)
            .expect("Failed to generate block witness");

        let bytes = (block, witness).to_vec();

        self.gossipsub.publish(self.block_topic, bytes).await?;

        Ok(())
    }
}
