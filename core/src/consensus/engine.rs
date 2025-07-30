use std::sync::Arc;

use civita_serialize::Serialize;
use libp2p::PeerId;
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::{
        block::{self, tree::Tree, Block},
        proposal::{self, Operation, Proposal},
    },
    crypto::{Hasher, Multihash, PublicKey, SecretKey},
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        Gossipsub, Transport,
    },
    utils::trie::{Record, Trie},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),

    #[error(transparent)]
    Proposal(#[from] proposal::Error),
}

pub trait Validator: Sync + Send + 'static {
    fn validate_proposal<'a, I>(
        &self,
        opt_iter: I,
        propoer_pk: &PublicKey,
        metadata: Option<&[u8]>,
    ) -> bool
    where
        I: IntoIterator<Item = &'a Operation>;
}

#[derive(Clone, Copy)]
pub struct Config {
    pub proposal_topic: u8,
    pub block_topic: u8,
    pub request_response_topic: u8,
    pub vdf_params: u16,
    pub vdf_difficulty: u64,
}

pub struct Engine<H: Hasher, V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,
    proposal_topic: u8,
    block_topic: u8,
    req_resp_topic: u8,
    block_tree: Tree<H>,
    sk: SecretKey,
    vdf: WesolowskiVDF,
    vdf_difficulty: u64,
    validator: V,
}

impl<H: Hasher, V: Validator> Engine<H, V> {
    pub fn new(
        transport: Arc<Transport>,
        block_tree: Tree<H>,
        validator: V,
        config: Config,
    ) -> Self {
        let gossipsub = transport.gossipsub();
        let request_response = transport.request_response();
        let sk = transport.secret_key().clone();
        let vdf = WesolowskiVDFParams(config.vdf_params).new();
        let vdf_difficulty = config.vdf_difficulty;

        Self {
            transport,
            gossipsub,
            request_response,
            proposal_topic: config.proposal_topic,
            block_topic: config.block_topic,
            req_resp_topic: config.request_response_topic,
            block_tree,
            sk,
            vdf,
            vdf_difficulty,
            validator,
        }
    }

    pub async fn propose(&self, prop: Proposal) -> Result<()> {
        let witness = prop.generate_witness(
            &self.sk,
            &self.block_tree.tip_trie(),
            &self.vdf,
            self.vdf_difficulty,
        )?;

        let mut bytes = Vec::new();
        prop.to_writer(&mut bytes);
        witness.to_writer(&mut bytes);

        let source = self.transport.local_peer_id();
        self.block_tree.update_proposal(prop, witness, source);
        self.gossipsub.publish(self.proposal_topic, bytes).await?;

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let mut prop_rx = self.gossipsub.subscribe(self.proposal_topic).await?;
        let mut block_rx = self.gossipsub.subscribe(self.block_topic).await?;
        let mut request_response_rx = self.request_response.subscribe(self.req_resp_topic);

        let mut vdf_task = Some(self.start_vdf_task());

        loop {
            tokio::select! {
                Some(msg) = prop_rx.recv() => {
                    self.on_recv_proposal(msg).await;
                }
                Some(msg) = block_rx.recv() => {
                    self.on_recv_block(msg).await;
                }
                Some(msg) = request_response_rx.recv() => {
                    self.on_recv_reqeust_response(msg).await;
                }
                result = vdf_task.as_mut().unwrap() => {
                    match result {
                        Ok((tip, vdf_proof)) => {
                            if let Some(pair) = self.block_tree.create_and_update_block(
                                tip,
                                vdf_proof,
                            ) {
                                let bytes = pair.to_vec();

                                if let Err(e) = self.gossipsub.publish(self.block_topic, bytes).await {
                                    log::error!("Failed to publish block: {e}");
                                }

                                log::debug!("Block created and published");
                            }

                            vdf_task = Some(self.start_vdf_task());
                        }
                        Err(e) => {
                            log::error!("VDF task failed: {e}");
                            vdf_task = Some(self.start_vdf_task());
                        }
                    }
                }
            }
        }
    }

    fn start_vdf_task(&self) -> JoinHandle<(Multihash, Vec<u8>)> {
        let tip = self.block_tree.tip_hash();

        let pk_bytes = self.sk.public_key().to_hash::<H>().to_bytes();
        let challenge_bytes = [pk_bytes, tip.to_bytes()].concat();
        let challenge = H::hash(&challenge_bytes).to_bytes();

        let vdf = self.vdf.clone();
        let difficulty = self.vdf_difficulty;
        tokio::spawn(async move {
            (
                tip,
                vdf.solve(&challenge, difficulty)
                    .expect("Failed to solve VDF"),
            )
        })
    }

    async fn on_recv_proposal(&self, msg: gossipsub::Message) {
        let source = msg.propagation_source;

        let mut data = msg.data.as_slice();

        let Ok(prop) = Proposal::from_reader(&mut data) else {
            self.disconnect_peer(source).await;
            return;
        };

        let Ok(witness) = proposal::Witness::from_reader(&mut data) else {
            self.disconnect_peer(source).await;
            return;
        };

        self.verify_proposal(prop.clone(), witness, source).await;
    }

    async fn verify_proposal(&self, prop: Proposal, witness: proposal::Witness, source: PeerId) {
        if !prop.verify_signature::<H>(&witness) {
            self.disconnect_peer(source).await;
            return;
        }

        if !prop.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            self.disconnect_peer(source).await;
            return;
        }

        if !self.validator.validate_proposal(
            prop.operations.values(),
            &prop.proposer_pk,
            prop.metadata.as_deref(),
        ) {
            self.disconnect_peer(source).await;
            return;
        }

        let res = self.block_tree.update_proposal(prop, witness, source);

        for source in res.invalidated {
            self.disconnect_peer(source).await;
        }
    }

    async fn disconnect_peer(&self, source: PeerId) {
        if let Err(e) = self.transport.disconnect(source).await {
            log::error!("Failed to disconnect peer: {e}");
        }
    }

    async fn on_recv_block(&self, msg: gossipsub::Message) {
        let source = msg.propagation_source;

        let mut data = msg.data.as_slice();

        let Ok(block) = Block::from_reader(&mut data) else {
            self.disconnect_peer(source).await;
            return;
        };

        let Ok(witness) = block::Witness::from_reader(&mut data) else {
            self.disconnect_peer(source).await;
            return;
        };

        self.verify_block(block, witness, source).await;
    }

    async fn verify_block(&self, block: Block, witness: block::Witness, source: PeerId) {
        if !block.verify_signature::<H>(&witness) {
            self.disconnect_peer(source).await;
            return;
        }

        if !block.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            self.disconnect_peer(source).await;
            return;
        }

        let res = self.block_tree.update_block(block, witness, source);

        for source in res.invalidated {
            self.disconnect_peer(source).await;
        }

        if !res.phantoms.is_empty() {
            let bytes = res.phantoms.to_vec();
            self.request_response
                .send_request(source, bytes, self.req_resp_topic)
                .await;
        }
    }

    async fn on_recv_reqeust_response(&self, msg: Message) {
        match msg {
            Message::Request {
                peer,
                request,
                channel,
            } => {
                let hashes = Vec::from_reader(&mut request.as_slice()).unwrap_or_default();

                if hashes.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                let bytes = self.block_tree.get_proposals(hashes).to_vec();

                if bytes.is_empty() {
                    return;
                }

                if let Err(e) = self
                    .request_response
                    .send_response(channel, bytes, self.req_resp_topic)
                    .await
                {
                    log::error!("Failed to send response: {e}");
                }
            }
            Message::Response { peer, response } => {
                let props = Vec::from_reader(&mut response.as_slice()).unwrap_or_default();

                if props.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                for (prop, witness) in props {
                    self.verify_proposal(prop, witness, peer).await;
                }
            }
        }
    }

    pub fn get_self_record(&self) -> Record {
        let key = self.sk.public_key().to_hash::<H>().to_bytes();
        self.block_tree.tip_trie().get(&key).unwrap_or_default()
    }

    pub fn tip_hash(&self) -> Multihash {
        self.block_tree.tip_hash()
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.block_tree.tip_trie()
    }

    pub fn checkpoint_hash(&self) -> Multihash {
        self.block_tree.checkpoint_hash()
    }
}
