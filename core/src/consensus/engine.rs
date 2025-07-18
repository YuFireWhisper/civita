use std::{collections::HashMap, ops::Deref, sync::Arc};

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

type Trie<H> = trie::Trie<H>;
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
    validate_prop_ch: Mutex<BiChannel<Proposal, Option<Proposal>>>,
    block_tree: RwLock<Tree<H>>,
    mpt: RwLock<Trie<H>>,
    sk: SecretKey,
    vdf: WesolowskiVDF,
    vdf_difficulty: u64,
    proposal_topic: u8,
    block_topic: u8,
}

impl<H: Hasher> Engine<H> {
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
                .push(prop);
            return Ok(());
        };

        let parent = &node.block;
        let trie_root = node.trie.root_hash();

        if let Some(prop) = self
            .verify_proposal(prop, &witness, parent, trie_root)
            .await
        {
            self.props.validated.insert(hash, prop);
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

        let mut channel = self.validate_prop_ch.lock().await;
        channel.send_and_recv(prop).await.ok().flatten()
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
            if !self.try_update_block(block).await {
                return Ok(());
            }
        }

        Ok(())
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
            if let Some((_, prop)) = self.props.validated.remove(hash) {
                props.insert(*hash, prop);
                continue;
            }

            let Some((prop, witness)) = self.take_or_fetch_proposal(peer, hash).await else {
                continue;
            };

            let Some(witness) = witness else {
                props.insert(*hash, prop);
                continue;
            };

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
    ) -> Option<(Proposal, Option<proposal::Witness>)> {
        if let Some((_, prop)) = self.props.validated.remove(hash) {
            return Some((prop, None));
        }

        let bytes = self
            .req_resp
            .send_reqeust_and_wait(peer, hash.to_bytes(), TIMEOUT)
            .await
            .ok()?;

        let prop = Proposal::from_slice(&bytes).ok()?;
        let witness = proposal::Witness::from_slice(&bytes).ok()?;

        Some((prop, Some(witness)))
    }
}
