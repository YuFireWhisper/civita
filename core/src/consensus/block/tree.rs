use std::sync::Arc;

use dashmap::DashMap;
use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            self,
            tree::{
                dag::{Dag, Node, ValidationResult},
                node::UnifiedNode,
            },
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::trie::{Trie, Weight},
};

pub mod dag;
mod node;

#[derive(Debug)]
#[derive(Default)]
pub struct ProcessResult {
    pub validated_msgs: Vec<(MessageId, PeerId)>,
    pub invalidated_msgs: Vec<(MessageId, PeerId)>,
}

pub struct Tree<H: Hasher> {
    sk: SecretKey,
    dag: ParkingRwLock<Dag<UnifiedNode<H>>>,
    tip: Arc<ParkingRwLock<(Weight, u64, Multihash)>>,
    checkpoint: Arc<ParkingRwLock<(Weight, Multihash)>>,
    metadatas: DashMap<Multihash, (MessageId, PeerId)>,
}

impl ProcessResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_validated(&mut self, msg_id: MessageId, source: PeerId) {
        self.validated_msgs.push((msg_id, source));
    }

    pub fn add_invalidated(&mut self, msg_id: MessageId, source: PeerId) {
        self.invalidated_msgs.push((msg_id, source));
    }

    pub fn from_validation_result<N: Node>(
        result: &ValidationResult<N>,
        metadatas: &DashMap<N::Id, (MessageId, PeerId)>,
    ) -> Self {
        let mut process_result = Self::new();

        for id in &result.validated {
            if let Some((_, (msg_id, source))) = metadatas.remove(id) {
                process_result.add_validated(msg_id, source);
            }
        }

        for id in &result.invalidated {
            if let Some((_, (msg_id, source))) = metadatas.remove(id) {
                process_result.add_invalidated(msg_id, source);
            }
        }

        process_result
    }
}

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey) -> Self {
        let root_block = block::Builder::new()
            .with_parent_hash(Multihash::default())
            .with_height(0)
            .with_proposer_pk(sk.public_key())
            .with_proposer_weight(0)
            .build();

        let hash = root_block.hash::<H>();

        let tip = Arc::new(ParkingRwLock::new((0, 0, hash)));
        let checkpoint = Arc::new(ParkingRwLock::new((0, hash)));

        let sig = sk.sign(&hash.to_bytes());
        let proofs = root_block.generate_proofs(&Trie::<H>::empty());
        let witness = block::Witness::new(sig, proofs, vec![]);

        let root_node =
            UnifiedNode::new_block(root_block, witness, tip.clone(), checkpoint.clone());

        Self {
            sk,
            dag: ParkingRwLock::new(Dag::with_root(root_node)),
            tip,
            checkpoint,
            metadatas: DashMap::new(),
        }
    }

    pub fn update_block(
        &self,
        block: Block,
        witness: block::Witness,
        metadata: Option<(MessageId, PeerId)>,
    ) -> ProcessResult {
        if block.height <= self.checkpoint_height() {
            let mut result = ProcessResult::new();
            if let Some((msg_id, source)) = metadata {
                result.add_invalidated(msg_id, source);
            }
            return result;
        }

        if let Some((msg_id, source)) = metadata {
            let hash = block.hash::<H>();
            self.metadatas.insert(hash, (msg_id, source));
        }

        let mut parent_ids = Vec::with_capacity(block.proposals.len() + 1);
        parent_ids.push(block.parent);
        parent_ids.extend(block.proposals.iter().cloned());

        let node =
            UnifiedNode::new_block(block, witness, self.tip.clone(), self.checkpoint.clone());

        println!("a");
        let dag_result = {
            let mut dag_write = self.dag.write();

            println!("b");

            dag_write.upsert(node, parent_ids)
        };
        println!("c");

        ProcessResult::from_validation_result(&dag_result, &self.metadatas)
    }

    fn checkpoint_height(&self) -> u64 {
        let checkpoint = self.checkpoint.read();

        self.dag
            .read()
            .get_node(&checkpoint.1)
            .expect("Checkpoint hash should exist in the DAG")
            .as_block()
            .expect("Checkpoint node should be a block")
            .height()
    }

    pub fn update_proposal(
        &self,
        proposal: Proposal,
        witness: proposal::Witness,
        metadata: Option<(MessageId, PeerId)>,
    ) -> ProcessResult {
        if self
            .block_height(&proposal.parent_hash)
            .is_some_and(|height| height < self.checkpoint_height())
        {
            let mut result = ProcessResult::new();
            if let Some((msg_id, source)) = metadata {
                result.add_invalidated(msg_id, source);
            }
            return result;
        }

        if let Some((msg_id, source)) = metadata {
            let hash = proposal.hash::<H>();
            self.metadatas.insert(hash, (msg_id, source));
        }

        let parent_hash = proposal.parent_hash;
        let node = UnifiedNode::new_proposal(proposal, witness);

        let result = self.dag.write().upsert(node, vec![parent_hash]);

        ProcessResult::from_validation_result(&result, &self.metadatas)
    }

    fn block_height(&self, hash: &Multihash) -> Option<u64> {
        self.dag
            .read()
            .get_node(hash)
            .and_then(|n| n.as_block().map(|b| b.height()))
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.dag
            .read()
            .get_node(&self.tip_hash())
            .expect("Tip hash should exist in the DAG")
            .as_block()
            .expect("Tip node should be a block")
            .trie
            .read()
            .clone()
    }

    pub fn tip_hash(&self) -> Multihash {
        self.tip.read().2
    }

    pub fn create_and_update_block(
        &self,
        parent: Multihash,
        vdf_proof: Vec<u8>,
    ) -> Option<(Block, block::Witness)> {
        let ids = self
            .dag
            .read()
            .sorted_levels(&parent)?
            .into_iter()
            .filter_map(|mut ns| ns.pop())
            .collect::<Vec<_>>();

        if ids.is_empty() {
            return None;
        }

        let dag_read = self.dag.read();
        let parent_node = dag_read.get_node(&parent)?.as_block()?;

        let weight = {
            let key = self.sk.public_key().to_hash::<H>().to_bytes();
            parent_node.trie.read().get(&key).map_or(0, |r| r.weight)
        };

        let block = block::Builder::new()
            .with_parent_block::<H>(&parent_node.block)
            .with_proposer_pk(self.sk.public_key())
            .with_proposer_weight(weight)
            .with_proposals(ids.clone())
            .build();

        let block_hash = block.hash::<H>();

        let sig = self.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&parent_node.trie.read());
        let witness = block::Witness::new(sig, proofs, vdf_proof);

        self.update_block(block.clone(), witness.clone(), None);

        Some((block, witness))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{block, proposal},
        crypto::SecretKey,
    };
    use libp2p::{gossipsub::MessageId, PeerId};
    use vdf::VDFParams;

    type TestHasher = sha2::Sha256;

    const VDF_PARAMS: vdf::WesolowskiVDFParams = vdf::WesolowskiVDFParams(1024);
    const VDF_DIFFICULTY: u64 = 1;
    const MESSAGE_ID_BYTES: &[u8] = b"test_message_id";

    #[test]
    fn update_proposal() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let tree = Tree::<TestHasher>::empty(sk.clone());

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(pk)
            .build()
            .expect("Failed to build proposal");

        let hash = prop.hash::<TestHasher>();

        let sig = sk.sign(&hash.to_bytes());
        let proofs = prop.generate_proofs(&tree.tip_trie());
        let vdf_proof = vec![];

        let witness = proposal::Witness::new(sig, proofs, vdf_proof);

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let result = tree.update_proposal(prop, witness, Some((msg_id.clone(), source)));

        assert_eq!(result.validated_msgs.len(), 1);
        assert_eq!(result.validated_msgs[0], (msg_id, source));
        assert!(result.invalidated_msgs.is_empty());
    }

    #[test]
    fn update_block() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let tree = Tree::<TestHasher>::empty(sk);

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(pk.clone())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let hash = prop.hash::<TestHasher>();

        tree.update_proposal(prop.clone(), witness, None);

        let block = block::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_height(1)
            .with_proposals([hash])
            .with_proposer_pk(pk)
            .with_proposer_weight(0)
            .build();

        let block_hash = block.hash::<TestHasher>();

        let sig = tree.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&tree.tip_trie());
        let vdf_proof = vec![];

        let witness = block::Witness::new(sig, proofs, vdf_proof);

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let result = tree.update_block(block, witness, Some((msg_id.clone(), source)));

        assert_eq!(result.validated_msgs.len(), 1);
        assert_eq!(result.validated_msgs[0], (msg_id, source));
        assert!(result.invalidated_msgs.is_empty());
    }
}
