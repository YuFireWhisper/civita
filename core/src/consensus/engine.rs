use std::{collections::HashMap, sync::Arc};

use civita_serialize::Serialize;
use dashmap::DashMap;
use libp2p::PeerId;
use tokio::sync::{Mutex, RwLock};
use vdf::WesolowskiVDF;

use crate::{
    block::{self, tree::Tree, Block},
    crypto::{Hasher, Multihash, SecretKey},
    network::{
        gossipsub,
        request_response::{self, RequestResponse},
        Gossipsub,
    },
    proposal::{self, Proposal},
    utils::{
        bi_channel::{self, BiChannel},
        trie,
    },
};

type Trie<H> = trie::Trie<H, HashMap<Multihash, Vec<u8>>>;
type Result<T, E = Error> = std::result::Result<T, E>;

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

struct Proposals {
    validated: DashMap<Multihash, Proposal>,
    waiting_parent: DashMap<Multihash, Vec<Proposal>>,
}

pub struct Engine<H: Hasher> {
    gossipsub: Arc<Gossipsub>,
    req_resp: Arc<RequestResponse>,
    props: Proposals,
    waiting_blocks: DashMap<Multihash, Vec<Block>>,
    validate_prop_ch: Mutex<BiChannel<Proposal, Proposal>>,
    block_tree: RwLock<Tree>,
    mpt: Trie<H>,
    sk: SecretKey,
    vdf: WesolowskiVDF,
    vdf_difficulty: u64,
    proposal_topic: u8,
    block_topic: u8,
}

impl Proposals {
    pub fn contains(&self, hash: &Multihash) -> bool {
        self.validated.contains_key(hash) || self.waiting_parent.contains_key(hash)
    }
}

impl<H: Hasher> Engine<H> {
    pub async fn propose(&self, prop: Proposal) -> Result<()> {
        let witness = prop.generate_witness(&self.sk, &self.vdf, self.vdf_difficulty, &self.mpt)?;

        let mut bytes = Vec::new();
        prop.to_writer(&mut bytes);
        witness.to_writer(&mut bytes);

        self.gossipsub.publish(self.proposal_topic, bytes).await?;
        self.props.validated.insert(prop.hash::<H>(), prop);

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let mut prop_rx = self.gossipsub.subscribe(self.proposal_topic).await?;
        let mut block_rx = self.gossipsub.subscribe(self.block_topic).await?;

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

                    if let Err(e) = self.on_recv_block(block, witness).await {
                        log::error!("Failed to handle block: {e}");
                    }
                }
            }
        }
    }

    async fn on_recv_proposal(&self, prop: Proposal, witness: proposal::Witness) -> Result<()> {
        if !prop.verify::<H>(
            &witness,
            &self.checkpoint_hash().await,
            &self.vdf,
            self.vdf_difficulty,
        ) {
            return Ok(());
        }

        let hash = prop.hash::<H>();

        if self.props.contains(&hash) {
            return Ok(());
        }

        let tree = self.block_tree.read().await;
        let Some(parent) = tree.get_block(&prop.parent) else {
            self.props
                .waiting_parent
                .entry(prop.parent)
                .or_default()
                .push(prop);
            return Ok(());
        };

        if parent.height <= self.checkpoint_height().await {
            return Ok(());
        }

        let prop = self
            .validate_prop_ch
            .lock()
            .await
            .send_and_recv(prop)
            .await?;
        self.props.validated.insert(hash, prop);

        Ok(())
    }

    async fn checkpoint_hash(&self) -> Multihash {
        self.block_tree.read().await.checkpoint_hash()
    }

    async fn checkpoint_height(&self) -> u64 {
        self.block_tree.read().await.checkpoint_height()
    }

    async fn on_recv_block(&self, block: Block, witness: block::Witness) -> Result<()> {
        if !block.verify::<H>(
            &witness,
            self.block_tree.read().await.checkpoint(),
            &self.vdf,
            self.vdf_difficulty,
        ) {
            return Ok(());
        }

        let hash = block.hash::<H>();

        if block.height <= self.checkpoint_height().await {
            let _ = self.waiting_blocks.remove(&hash);
            return Ok(());
        }

        if self.contains_block(&hash).await {
            return Ok(());
        }

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
            return Ok(());
        };

        if parent.height != block.height.wrapping_add(1) {
            return Ok(());
        }

        let mut bs = self
            .waiting_blocks
            .remove(&hash)
            .map(|(_, bs)| bs)
            .unwrap_or_default();
        bs.push(block);

        for block in bs.into_iter().rev() {
            if !self.verify_block(block).await {
                return Ok(());
            }
        }

        Ok(())
    }

    async fn contains_block(&self, hash: &Multihash) -> bool {
        self.block_tree.read().await.contains(hash)
    }

    async fn verify_block(&self, block: Block) -> bool {
        let mut props = HashMap::new();
        let peer = PeerId::from_multihash(block.proposer_pk.to_hash::<H>())
            .expect("PeerId should be valid");

        for hash in block.proposals.iter() {
            if let Some((_, p)) = self.props.validated.remove(hash) {
                props.insert(*hash, p);
                continue;
            }

            let Ok(prop) = self
                .req_resp
                .send_reqeust_and_wait(peer, hash.to_bytes(), TIMEOUT)
                .await
            else {
                return false;
            };

            if let Ok(prop) = Proposal::from_slice(&prop) {
                props.insert(*hash, prop);
            } else {
                return false;
            }
        }

        self.block_tree
            .write()
            .await
            .update::<H>(block, &props)
            .unwrap()
    }
}
