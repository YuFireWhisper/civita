use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::{
    consensus::hot_stuff::utils::{Block, ProofPair, QuorumCertificate, View, ViewNumber},
    crypto::{Hasher, Multihash, PublicKey, Signature},
    network::storage,
};

type ViewPair = (ViewNumber, Multihash);
type QuorumCertificatePair = (ViewNumber, QuorumCertificate);

type Result<T, E = storage::Error> = std::result::Result<T, E>;

pub struct ExecutedViewState {
    number: ViewNumber,
    hash: Multihash,
    parent: Multihash,
}

pub struct ChainState {
    pub views: HashMap<Multihash, View>,
    pub locked_view: ViewPair,
    pub executed_view: ExecutedViewState,
    pub leaf_view: ViewPair,
    pub highest_qc_view: QuorumCertificatePair,
    pub v_height: ViewNumber,
    pub threshold: u64,
}

pub struct Chain {
    views: HashMap<Multihash, View>,

    locked_view: RwLock<ViewPair>,
    executed_view: RwLock<ExecutedViewState>,
    leaf_view: RwLock<ViewPair>,
    highest_qc_view: RwLock<QuorumCertificatePair>,

    v_height: ViewNumber,
    votes: HashMap<Multihash, HashMap<PublicKey, (ProofPair, Signature)>>,

    threshold: u64,
}

impl Chain {
    #[allow(dead_code)]
    pub fn new(threshold: u64) -> Self {
        let view_pair = (0, Multihash::default());
        let executed_view = ExecutedViewState {
            number: 0,
            hash: Multihash::default(),
            parent: Multihash::default(),
        };

        Self {
            views: HashMap::new(),
            locked_view: RwLock::new(view_pair),
            executed_view: RwLock::new(executed_view),
            leaf_view: RwLock::new(view_pair),
            highest_qc_view: RwLock::new((0, QuorumCertificate::default())),
            v_height: 0,
            votes: HashMap::new(),
            threshold,
        }
    }

    pub fn from_state(state: ChainState) -> Self {
        let executed_view = ExecutedViewState {
            number: state.executed_view.number,
            hash: state.executed_view.hash,
            parent: state.executed_view.parent,
        };

        Self {
            views: state.views,
            locked_view: RwLock::new(state.locked_view),
            executed_view: RwLock::new(executed_view),
            leaf_view: RwLock::new(state.leaf_view),
            highest_qc_view: RwLock::new(state.highest_qc_view),
            v_height: state.v_height,
            votes: HashMap::new(),
            threshold: state.threshold,
        }
    }

    pub fn add_view(&mut self, view: View) {
        let hash = view.hash;
        self.views.insert(hash, view);
    }

    pub async fn update(&mut self, b3_hash: &Multihash) -> Option<Vec<Block>> {
        let b3 = self.get_view(b3_hash)?;
        let b2 = self.try_update_highest_qc(&b3.justify).await?;
        let b1 = self.try_update_locked_view(b2).await?;
        self.try_update_executed_view(b2, b1).await
    }

    pub fn get_view(&self, hash: &Multihash) -> Option<&View> {
        self.views.get(hash)
    }

    async fn try_update_highest_qc(&self, qc: &QuorumCertificate) -> Option<&View> {
        let b2 = self.get_view(&qc.view)?;

        if b2.number <= self.highest_qc_view_number().await {
            return None;
        }

        *self.highest_qc_view.write().await = (b2.number, qc.clone());
        *self.leaf_view.write().await = (b2.number, b2.hash);

        Some(b2)
    }

    async fn try_update_locked_view(&self, b2: &View) -> Option<&View> {
        let b1 = self.get_view(&b2.justify.view)?;

        if b1.number <= self.locked_view_number().await {
            return None;
        }

        *self.locked_view.write().await = (b1.number, b1.hash);

        Some(b1)
    }

    async fn try_update_executed_view(&self, b2: &View, b1: &View) -> Option<Vec<Block>> {
        if b2.parent_hash != b1.hash {
            return None;
        }

        let b0 = self.get_view(&b1.justify.view)?;

        if b1.parent_hash != b0.hash {
            return None;
        }

        let b0_number = b0.number;
        let b0_hash = b0.hash;

        let cmds = self.collect_commands(b0).await;

        let mut executed_view = self.executed_view.write().await;
        executed_view.number = b0_number;
        executed_view.parent = executed_view.hash;
        executed_view.hash = b0_hash;

        Some(cmds)
    }

    async fn collect_commands(&self, b0: &View) -> Vec<Block> {
        let exec_height = self.executed_view_number().await;

        let mut cmds = Vec::new();
        let mut cur = b0;

        while exec_height < cur.number {
            cmds.push(cur.block.clone());

            cur = match self.get_view(&cur.parent_hash) {
                Some(view) => view,
                None => break,
            };
        }

        cmds.reverse();

        cmds
    }

    pub async fn locked_view_number(&self) -> ViewNumber {
        self.locked_view.read().await.0
    }

    pub async fn executed_view_number(&self) -> ViewNumber {
        self.executed_view.read().await.number
    }

    pub async fn leaf_view_number(&self) -> ViewNumber {
        self.leaf_view.read().await.0
    }

    pub async fn highest_qc_view_number(&self) -> ViewNumber {
        self.highest_qc_view.read().await.0
    }

    pub async fn executed_view_hash(&self) -> Multihash {
        self.executed_view.read().await.hash
    }

    pub async fn executed_view(&self) -> &View {
        let hash = self.executed_view_hash().await;
        self.get_view(&hash).expect("Executed view not found")
    }

    pub async fn executed_view_parent(&self) -> Multihash {
        self.executed_view.read().await.parent
    }

    pub async fn executed_view_parent_view(&self) -> &View {
        let parent_hash = self.executed_view_parent().await;
        self.get_view(&parent_hash)
            .expect("Executed view parent not found")
    }

    pub async fn is_safe_view(&self, view_hash: &Multihash) -> bool {
        let Some(view) = self.get_view(view_hash) else {
            return false;
        };

        if view.number <= self.v_height {
            return false;
        }

        let (locked_height, locked_hash) = *self.locked_view.read().await;

        let Some(view_qc) = self.get_view(&view.justify.view) else {
            return false;
        };

        if view_qc.number > locked_height {
            return true;
        }

        if self.extends_from_locked_view(view, locked_height, locked_hash) {
            return true;
        }

        false
    }

    fn extends_from_locked_view(
        &self,
        view: &View,
        locked_height: ViewNumber,
        locked_hash: Multihash,
    ) -> bool {
        if view.number == locked_height {
            return view.hash == locked_hash;
        }

        if view.number < locked_height {
            return false;
        }

        let mut cur = view;

        while cur.number > locked_height {
            let Some(parent) = self.get_view(&cur.parent_hash) else {
                return false;
            };

            if parent.number == locked_height {
                return parent.hash == locked_hash;
            }

            if parent.number < locked_height {
                return false;
            }

            cur = parent;
        }

        cur.hash == locked_hash && cur.number == locked_height
    }

    pub async fn on_receive_vote(
        &mut self,
        hash: Multihash,
        pk: PublicKey,
        proof: ProofPair,
        sig: Signature,
    ) -> bool {
        let proofs = self.votes.entry(hash).or_default();

        if proofs.contains_key(&pk) {
            return false; // duplicate vote
        }

        proofs.insert(pk, (proof, sig));

        if proofs.len() as u64 >= self.threshold {
            let proofs = self
                .votes
                .remove(&hash)
                .expect("Votes should exist for the view");
            let qc = QuorumCertificate { view: hash, proofs };

            self.try_update_highest_qc(&qc).await;

            return true;
        }

        false
    }

    pub async fn on_propose<H: Hasher>(&self, block: Block) -> Result<View> {
        let highest_qc = self.highest_qc_view.read().await.1.clone();
        let (leaf_number, leaf_hash) = *self.leaf_view.read().await;
        Ok(View::new::<H>(
            leaf_number + 1,
            leaf_hash,
            block,
            highest_qc,
        ))
    }

    #[allow(dead_code)]
    pub async fn export_state(&self) -> ChainState {
        let executed_view = self.executed_view.read().await;
        let executed_view_number = executed_view.number;

        let relevant_views: HashMap<Multihash, View> = self
            .views
            .iter()
            .filter(|(_, view)| view.number >= executed_view_number)
            .map(|(hash, view)| (*hash, view.clone()))
            .collect();

        ChainState {
            views: relevant_views,
            locked_view: *self.locked_view.read().await,
            executed_view: ExecutedViewState {
                number: executed_view.number,
                hash: executed_view.hash,
                parent: executed_view.parent,
            },
            leaf_view: *self.leaf_view.read().await,
            highest_qc_view: self.highest_qc_view.read().await.clone(),
            v_height: self.v_height,
            threshold: self.threshold,
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::consensus::hot_stuff::utils::{QuorumCertificate, View};
//     use std::{collections::HashMap, sync::Arc};
//
//     type Hasher = sha2::Sha256;
//
//     const QUORUM_SIZE: u64 = 5;
//
//     type TestCommand = u64;
//     type TestPeer = u64;
//     type TestSignature = u64;
//
//     type TestChain = Chain<TestCommand, TestPeer, TestSignature>;
//     type TestQuorumCertificate = QuorumCertificate<Multihash, TestPeer, TestSignature>;
//     type TestView = View<TestCommand, TestPeer, TestSignature>;
//
//     async fn create_test_chain() -> TestChain {
//         let storage = Arc::new(Storage::new_local_one());
//         TestChain::new(storage, QUORUM_SIZE)
//     }
//
//     async fn add_view(chain: &mut TestChain, parent: Multihash, number: u64) -> Multihash {
//         let view = if number == 1 {
//             TestView::new::<Hasher>(
//                 number,
//                 Multihash::default(),
//                 1,
//                 QuorumCertificate::default(),
//             )
//         } else {
//             let qc = create_test_qc(parent, QUORUM_SIZE);
//             TestView::new::<Hasher>(number, parent, number, qc)
//         };
//
//         let hash = view.hash;
//         chain.add_view(view).await;
//
//         hash
//     }
//
//     async fn add_view_cus(
//         chain: &mut TestChain,
//         parent: Multihash,
//         number: u64,
//         cmd: TestCommand,
//     ) -> Multihash {
//         let view = if number == 1 {
//             TestView::new::<Hasher>(
//                 number,
//                 Multihash::default(),
//                 cmd,
//                 QuorumCertificate::default(),
//             )
//         } else {
//             let qc = create_test_qc(parent, QUORUM_SIZE);
//             TestView::new::<Hasher>(number, parent, cmd, qc)
//         };
//
//         let hash = view.hash;
//         chain.add_view(view).await;
//
//         hash
//     }
//
//     fn create_test_qc(view_hash: Multihash, peer_count: u64) -> TestQuorumCertificate {
//         let mut sigs = HashMap::new();
//
//         for i in 0..peer_count {
//             sigs.insert(i, i);
//         }
//
//         QuorumCertificate {
//             view: view_hash,
//             proofs: sigs,
//         }
//     }
//
//     async fn add_view_and_update(
//         chain: &mut TestChain,
//         parent: Multihash,
//         number: u64,
//     ) -> (Multihash, Option<Vec<TestCommand>>) {
//         let hash = add_view(chain, parent, number).await;
//         let result = chain.update(&hash).await.unwrap();
//         (hash, result)
//     }
//
//     #[tokio::test]
//     async fn basic_chain_initialization() {
//         let chain = create_test_chain().await;
//
//         assert_eq!(chain.v_height(), 0);
//         assert_eq!(chain.locked_view_number().await, 0);
//         assert_eq!(chain.executed_view_number().await, 0);
//         assert_eq!(chain.leaf_view_number().await, 0);
//         assert_eq!(chain.highest_qc_view_number().await, 0);
//     }
//
//     #[tokio::test]
//     async fn add_view_basic() {
//         let mut chain = create_test_chain().await;
//
//         let hash = add_view(&mut chain, Multihash::default(), 1).await;
//         let retrieved = chain.get_view(&hash).await.unwrap();
//
//         assert!(retrieved.is_some());
//         assert_eq!(retrieved.unwrap().number, 1);
//     }
//
//     #[tokio::test]
//     async fn single_view_update() {
//         let mut chain = create_test_chain().await;
//
//         let (hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
//         let (_, res) = add_view_and_update(&mut chain, hash, 2).await;
//
//         assert!(res.is_none());
//         assert_eq!(chain.leaf_view_number().await, 1);
//     }
//
//     #[tokio::test]
//     async fn three_chain_execution() {
//         let mut chain = create_test_chain().await;
//
//         let (view1_hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
//         let (view2_hash, _) = add_view_and_update(&mut chain, view1_hash, 2).await;
//         let (view3_hash, _) = add_view_and_update(&mut chain, view2_hash, 3).await;
//         let (_, view4_res) = add_view_and_update(&mut chain, view3_hash, 4).await;
//
//         let leaf_view = chain.leaf_view().await.unwrap();
//         let locked_view = chain.locked_view().await.unwrap();
//         let executed_view = chain.executed_view().await.unwrap();
//
//         // view3 should be leaf
//         // view2 should be locked
//         // view1 should be executed
//         assert_eq!(view4_res.as_ref().map(|r| r.len()), Some(1));
//         assert_eq!(view4_res.unwrap()[0], 1);
//         assert_eq!(leaf_view.number, 3);
//         assert_eq!(leaf_view.hash, view3_hash);
//         assert_eq!(locked_view.number, 2);
//         assert_eq!(locked_view.hash, view2_hash);
//         assert_eq!(executed_view.number, 1);
//         assert_eq!(executed_view.hash, view1_hash);
//     }
//
//     #[tokio::test]
//     async fn duplicate_vote_ignored() {
//         let mut chain = create_test_chain().await;
//
//         let hash = add_view(&mut chain, Multihash::default(), 1).await;
//
//         for _ in 0u64..QUORUM_SIZE {
//             let result = chain.on_receive_vote(hash, 0, 0).await.unwrap();
//             assert!(result.is_none(), "Vote should not trigger a QC yet");
//         }
//     }
//
//     #[tokio::test]
//     async fn safety_check_with_locked_view() {
//         let mut chain = create_test_chain().await;
//
//         let (view1_hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
//         let (view3_hash, _) = add_view_and_update(&mut chain, view1_hash, 3).await; // skip 2
//         let (view4_hash, _) = add_view_and_update(&mut chain, view3_hash, 4).await;
//         let (view5_hash, _) = add_view_and_update(&mut chain, view4_hash, 5).await;
//
//         // Now, lock view should be view 3
//
//         let view2_hash = add_view(&mut chain, view1_hash, 2).await; // add view 2 after locking
//         let view6_hash = add_view(&mut chain, view5_hash, 6).await;
//         let view3_cus = add_view_cus(&mut chain, view2_hash, 3, 100).await;
//
//         let view2_res = chain.is_safe_view(&view2_hash).await.unwrap();
//         let view6_res = chain.is_safe_view(&view6_hash).await.unwrap();
//         let view3_cus_res = chain.is_safe_view(&view3_cus).await.unwrap();
//
//         assert_eq!(chain.locked_view_number().await, 3);
//         assert!(!view2_res, "View 2 should be unsafe");
//         assert!(view6_res, "View 6 should be safe");
//         assert!(
//             !view3_cus_res,
//             "View 3 with custom command should be unsafe"
//         );
//     }
// }
