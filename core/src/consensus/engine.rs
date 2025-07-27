use std::sync::Arc;

use civita_serialize::Serialize;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::Message,
    PeerId,
};
use tokio::task::JoinHandle;
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::{
        block::{self, tree::Tree, Block},
        proposal::{self, Operation, Proposal},
    },
    crypto::{Hasher, Multihash, PublicKey, SecretKey},
    network::{gossipsub, request_response::RequestResponse, Gossipsub, Transport},
    utils::trie::{Record, Trie},
};

type Result<T, E = Error> = std::result::Result<T, E>;
type Metadata = (MessageId, PeerId);

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),

    #[error(transparent)]
    Proposal(#[from] proposal::Error),
}

pub trait Validator {
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
    pub vdf_params: u16,
    pub vdf_difficulty: u64,
}

pub struct Engine<H: Hasher, V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,
    proposal_topic: u8,
    block_topic: u8,
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

        self.block_tree.update_proposal(prop, witness, None);
        self.gossipsub.publish(self.proposal_topic, bytes).await?;

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let mut prop_rx = self.gossipsub.subscribe(self.proposal_topic).await?;
        let mut block_rx = self.gossipsub.subscribe(self.block_topic).await?;

        let mut vdf_task = Some(self.start_vdf_task());

        loop {
            tokio::select! {
                Some(msg) = prop_rx.recv() => {
                    self.on_recv_proposal(msg).await;
                }
                Some(msg) = block_rx.recv() => {
                    self.on_recv_block(msg).await;
                }
                Some((source, msg)) = self.request_response.recv() => {
                    self.on_recv_reqeust_response(source, msg).await;
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
        let mut data = msg.data.as_slice();

        let Ok(prop) = Proposal::from_reader(&mut data) else {
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        };

        let Ok(witness) = proposal::Witness::from_reader(&mut data) else {
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        };

        let metadata = Some((msg.id, msg.propagation_source));
        let res = self.verify_proposal(prop.clone(), witness, metadata).await;

        for (id, source, acceptance) in res {
            self.gossipsub
                .report_validation_result(&id, &source, acceptance)
                .await;
        }
    }

    async fn verify_proposal(
        &self,
        prop: Proposal,
        witness: proposal::Witness,
        metadata: Option<Metadata>,
    ) -> Vec<(MessageId, PeerId, MessageAcceptance)> {
        let mut result = Vec::new();

        if !prop.verify_signature::<H>(&witness) {
            if let Some((msg_id, source)) = metadata {
                result.push((msg_id, source, MessageAcceptance::Reject));
            }
            return result;
        }

        if !prop.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            if let Some((msg_id, source)) = metadata {
                result.push((msg_id, source, MessageAcceptance::Reject));
            }
            return result;
        }

        if !self.validator.validate_proposal(
            prop.operations.values(),
            &prop.proposer_pk,
            prop.metadata.as_deref(),
        ) {
            if let Some((msg_id, source)) = metadata {
                result.push((msg_id, source, MessageAcceptance::Reject));
            }
            return result;
        }

        let res = self
            .block_tree
            .update_proposal(prop, witness, metadata.clone());

        let mut ress = Vec::with_capacity(res.validated_msgs.len() + res.invalidated_msgs.len());

        res.validated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Accept));
        });

        res.invalidated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Reject));
        });

        if !res.phantoms.is_empty() {
            if let Some((_, source)) = metadata {
                let bytes = res.phantoms.to_vec();
                self.request_response.send_request(source, bytes).await;
            }
        }

        ress
    }

    async fn on_recv_block(&self, msg: gossipsub::Message) {
        let mut data = msg.data.as_slice();

        let Ok(block) = Block::from_reader(&mut data) else {
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        };

        let Ok(witness) = block::Witness::from_reader(&mut data) else {
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        };

        let res = self.verify_block(block, witness, msg.id, msg.propagation_source);

        for (id, source, acceptance) in res {
            self.gossipsub
                .report_validation_result(&id, &source, acceptance)
                .await;
        }
    }

    fn verify_block(
        &self,
        block: Block,
        witness: block::Witness,
        msg_id: MessageId,
        source: PeerId,
    ) -> Vec<(MessageId, PeerId, MessageAcceptance)> {
        if !block.verify_signature::<H>(&witness) {
            return vec![(msg_id, source, MessageAcceptance::Reject)];
        }

        if !block.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            return vec![(msg_id, source, MessageAcceptance::Reject)];
        }

        let res = self
            .block_tree
            .update_block(block, witness, Some((msg_id, source)));

        let mut ress = Vec::with_capacity(res.validated_msgs.len() + res.invalidated_msgs.len());

        res.validated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Accept));
        });

        res.invalidated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Reject));
        });

        ress
    }

    async fn on_recv_reqeust_response(&self, source: PeerId, msg: Message<Vec<u8>, Vec<u8>>) {
        match msg {
            Message::Request {
                request, channel, ..
            } => {
                let hashes =
                    Vec::<Multihash>::from_reader(&mut request.as_slice()).unwrap_or_default();

                if hashes.is_empty() {
                    return;
                }

                let bytes = self.block_tree.get_proposals(hashes).to_vec();

                if let Err(e) = self.request_response.send_response(channel, bytes).await {
                    log::error!("Failed to send response: {e}");
                }
            }
            Message::Response { response, .. } => {
                let props =
                    Vec::<(Proposal, proposal::Witness)>::from_reader(&mut response.as_slice())
                        .unwrap_or_default();

                if props.is_empty() {
                    if let Err(e) = self.transport.disconnect(source).await {
                        log::error!("Failed to disconnect peer: {e}");
                    }
                    return;
                }

                for (prop, witness) in props {
                    let res = self.verify_proposal(prop, witness, None).await;

                    for (id, source, acceptance) in res {
                        self.gossipsub
                            .report_validation_result(&id, &source, acceptance)
                            .await;
                    }
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
}
