use std::sync::Arc;

use civita_serialize::Serialize;
use derivative::Derivative;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    PeerId,
};
use tokio::{
    sync::{mpsc, RwLock},
    task::JoinHandle,
};
use vdf::{WesolowskiVDF, VDF};

use crate::{
    consensus::{
        block::{self, tree::Tree, Block},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    network::{gossipsub, Gossipsub, Transport},
    utils::trie::Record,
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

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct EngineBuilder<H: Hasher> {
    gossipsub: Option<Arc<Gossipsub>>,

    proposal_topic: Option<u8>,
    block_topic: Option<u8>,

    prop_validation_tx: Option<mpsc::UnboundedSender<Proposal>>,
    prop_validation_rx: Option<mpsc::UnboundedReceiver<(Multihash, bool)>>,

    block_tree: Option<RwLock<Tree<H>>>,

    sk: Option<SecretKey>,

    vdf: Option<WesolowskiVDF>,
    vdf_difficulty: Option<u64>,
}

pub struct Engine<H: Hasher> {
    gossipsub: Arc<Gossipsub>,

    proposal_topic: u8,
    block_topic: u8,

    block_tree: Tree<H>,

    prop_validation_tx: mpsc::UnboundedSender<Proposal>,

    sk: SecretKey,

    vdf: WesolowskiVDF,
    vdf_difficulty: u64,
}

impl<H: Hasher> EngineBuilder<H> {
    pub fn new() -> Self {
        Self {
            gossipsub: None,
            proposal_topic: None,
            block_topic: None,
            prop_validation_tx: None,
            prop_validation_rx: None,
            block_tree: None,
            sk: None,
            vdf: None,
            vdf_difficulty: None,
        }
    }

    pub fn with_transport(mut self, transport: Arc<Transport>) -> Self {
        self.gossipsub = Some(transport.gossipsub());
        self.sk = Some(transport.secret_key().clone());
        self
    }

    pub fn with_topics(mut self, proposal_topic: u8, block_topic: u8) -> Self {
        self.proposal_topic = Some(proposal_topic);
        self.block_topic = Some(block_topic);
        self
    }

    pub fn with_prop_validation_channel(
        mut self,
        tx: mpsc::UnboundedSender<Proposal>,
        rx: mpsc::UnboundedReceiver<(Multihash, bool)>,
    ) -> Self {
        self.prop_validation_tx = Some(tx);
        self.prop_validation_rx = Some(rx);
        self
    }

    pub fn with_block_tree(mut self, tree: Tree<H>) -> Self {
        self.block_tree = Some(RwLock::new(tree));
        self
    }

    pub fn with_sk(mut self, sk: SecretKey) -> Self {
        self.sk = Some(sk);
        self
    }

    pub fn with_vdf(mut self, vdf: WesolowskiVDF, difficulty: u64) -> Self {
        self.vdf = Some(vdf);
        self.vdf_difficulty = Some(difficulty);
        self
    }

    pub fn build(self) -> Arc<Engine<H>> {
        let gossipsub = self.gossipsub.expect("Gossipsub must be set");
        let proposal_topic = self.proposal_topic.expect("Proposal topic must be set");
        let block_topic = self.block_topic.expect("Block topic must be set");
        let prop_validation_tx = self
            .prop_validation_tx
            .expect("Prop validation tx must be set");
        let prop_validation_rx = self
            .prop_validation_rx
            .expect("Prop validation rx must be set");
        let block_tree = self.block_tree.expect("Block tree must be set");
        let sk = self.sk.expect("Secret key must be set");
        let vdf = self.vdf.expect("VDF must be set");
        let vdf_difficulty = self.vdf_difficulty.expect("VDF difficulty must be set");

        let engine = Engine {
            gossipsub,
            proposal_topic,
            block_topic,
            block_tree: block_tree.into_inner(),
            prop_validation_tx,
            sk,
            vdf,
            vdf_difficulty,
        };

        let engine = Arc::new(engine);

        tokio::spawn({
            let engine = Arc::clone(&engine);
            async move {
                if let Err(e) = engine.run(prop_validation_rx).await {
                    panic!("Engine run failed: {e}");
                }
            }
        });

        engine
    }
}

impl<H: Hasher> Engine<H> {
    #[allow(dead_code)]
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

        self.gossipsub.publish(self.proposal_topic, bytes).await?;
        self.block_tree.update_proposal_unchecked(prop);

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn run(
        &self,
        mut prop_validation_rx: mpsc::UnboundedReceiver<(Multihash, bool)>,
    ) -> Result<()> {
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
                Some((hash, accepted)) = prop_validation_rx.recv() => {
                    self.on_recv_validation_result(hash, accepted);
                }
                result = vdf_task.as_mut().unwrap() => {
                    match result {
                        Ok((tip, vdf_proof)) => {
                            let (block, proofs) = self.block_tree.create_and_update_block(
                                tip,
                            );

                            let sig = self.sk.sign(&tip.to_bytes());
                            let witness = block::Witness::new(sig, proofs, vdf_proof);

                            let mut bytes = Vec::new();
                            block.to_writer(&mut bytes);
                            witness.to_writer(&mut bytes);

                            if let Err(e) = self.gossipsub.publish(self.block_topic, bytes).await {
                                log::error!("Failed to publish block: {e}");
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

        let vdf = self.vdf.clone();
        let difficulty = self.vdf_difficulty;
        tokio::spawn(async move {
            (
                tip,
                vdf.solve(&tip.to_bytes(), difficulty)
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

        let this_msg_id = msg.id.clone();
        let res = self.verify_proposal(prop.clone(), witness, msg.id, msg.propagation_source);

        let mut is_invalid = false;
        for (id, source, acceptance) in res {
            if id == this_msg_id && matches!(acceptance, MessageAcceptance::Reject) {
                is_invalid = true;
            }

            self.gossipsub
                .report_validation_result(&id, &source, acceptance)
                .await;
        }

        if is_invalid {
            return;
        }

        self.prop_validation_tx
            .send(prop)
            .expect("Failed to send proposal for validation");
    }

    fn verify_proposal(
        &self,
        prop: Proposal,
        witness: proposal::Witness,
        msg_id: MessageId,
        source: PeerId,
    ) -> Vec<(MessageId, PeerId, MessageAcceptance)> {
        if !prop.verify_signature::<H>(&witness) {
            return vec![(msg_id, source, MessageAcceptance::Reject)];
        }

        if !prop.verify_vdf::<H>(&witness, &self.vdf, self.vdf_difficulty) {
            return vec![(msg_id, source, MessageAcceptance::Reject)];
        }

        let res = self
            .block_tree
            .update_proposal(prop, witness.proofs, msg_id, source);

        let mut ress = Vec::with_capacity(res.validated_msgs.len() + res.invalidated_msgs.len());

        res.validated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Accept));
        });

        res.invalidated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Reject));
        });

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
            .update_block(block, witness.proofs, msg_id, source);

        let mut ress = Vec::with_capacity(res.validated_msgs.len() + res.invalidated_msgs.len());

        res.validated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Accept));
        });

        res.invalidated_msgs.into_iter().for_each(|(id, source)| {
            ress.push((id, source, MessageAcceptance::Reject));
        });

        ress
    }

    fn on_recv_validation_result(&self, hash: Multihash, accepted: bool) {
        self.block_tree
            .update_proposal_client_validation(hash, accepted);
    }

    pub fn get_self_record(&self) -> Record {
        let key = self.sk.public_key().to_hash::<H>().to_bytes();
        self.block_tree.tip_trie().get(&key).unwrap_or_default()
    }

    pub fn tip_hash(&self) -> Multihash {
        self.block_tree.tip_hash()
    }
}
