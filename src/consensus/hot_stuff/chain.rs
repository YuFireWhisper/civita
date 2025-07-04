use std::{collections::HashMap, hash::Hash, sync::Arc};

use dashmap::{mapref::one::Ref, DashMap};
use tokio::sync::RwLock;

use crate::{
    consensus::hot_stuff::utils::{QuorumCertificate, View, ViewNumber},
    crypto::{Hasher, Multihash},
    network::{storage, CacheStorage, Storage},
    traits::Serializable,
};

type ViewPair = (ViewNumber, Multihash);
type QuorumCertificatePair<P, S> = (ViewNumber, QuorumCertificate<Multihash, P, S>);

type Result<T, E = storage::Error> = std::result::Result<T, E>;

pub struct Chain<T, P, S> {
    views: CacheStorage<View<T, P, S>>,

    locked_view: RwLock<Option<ViewPair>>,
    executed_view: RwLock<Option<ViewPair>>,
    leaf_view: RwLock<Option<ViewPair>>,
    highest_qc_view: RwLock<Option<QuorumCertificatePair<P, S>>>,

    v_height: ViewNumber,
    votes: DashMap<Multihash, HashMap<P, S>>,

    total_nodes: u64,
    max_faulty: u64,
}

impl<T, P, S> Chain<T, P, S>
where
    T: Clone + Serializable + Send + Sync + 'static,
    P: Clone + Serializable + Eq + Hash + Send + Sync + 'static,
    S: Clone + Serializable + Send + Sync + 'static,
{
    pub fn new(stroage: Arc<Storage>, total_nodes: u64, max_faulty: u64) -> Self {
        let qc = QuorumCertificate {
            view: Multihash::default(),
            sigs: HashMap::new(),
        };

        Self {
            views: CacheStorage::new(stroage),

            locked_view: RwLock::new(None),
            executed_view: RwLock::new(None),
            leaf_view: RwLock::new(None),
            highest_qc_view: RwLock::new(Some((0, qc))),

            v_height: 0,
            votes: DashMap::new(),

            total_nodes,
            max_faulty,
        }
    }

    pub async fn add_view(&mut self, view: View<T, P, S>) {
        self.views.insert(view.hash, view);
    }

    pub async fn update(&mut self, b3_hash: &Multihash) -> Result<Option<Vec<T>>> {
        let Some(b3) = self.get_view(b3_hash).await? else {
            return Ok(None);
        };

        let b2 = match self.try_update_highest_qc(&b3.justify).await? {
            Some(b2) => {
                log::debug!("Updated highest QC");
                b2
            }
            None => {
                log::debug!("Could not update highest QC");
                return Ok(None);
            }
        };

        let b1 = match self.try_update_locked_view(&b2).await? {
            Some(hash) => {
                log::debug!("Updated locked view");
                hash
            }
            None => {
                log::debug!("Could not update locked view");
                return Ok(None);
            }
        };

        let executed_commands = self.try_update_executed_view(&b2, &b1).await?;

        if let Some(ref cmds) = executed_commands {
            log::info!("Executed {} commands", cmds.len());
        }

        Ok(executed_commands)
    }

    pub async fn get_view(
        &self,
        hash: &Multihash,
    ) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        self.views.get(hash).await
    }

    async fn try_update_highest_qc(
        &self,
        qc: &Option<QuorumCertificate<Multihash, P, S>>,
    ) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        let Some(qc) = qc else {
            return Ok(None);
        };

        let b2 = self.get_view_or_unwrap(&qc.view).await?;

        if !self.is_higher_than_highest_qc(b2.number).await {
            return Ok(None);
        }

        let origin = self
            .highest_qc_view
            .write()
            .await
            .replace((b2.number, qc.clone()));

        self.leaf_view.write().await.replace((b2.number, b2.hash));

        if origin.is_none() {
            Ok(None)
        } else {
            Ok(Some(b2))
        }
    }

    async fn try_update_locked_view<'a>(
        &'a self,
        b2: &Ref<'a, Multihash, View<T, P, S>>,
    ) -> Result<Option<Ref<'a, Multihash, View<T, P, S>>>> {
        let Some(b1) = self.get_justified_view(b2.value()).await? else {
            return Ok(None);
        };

        if !self.is_higher_than_locked_view(b1.number).await {
            return Ok(None);
        }

        let origin = self.locked_view.write().await.replace((b1.number, b1.hash));

        if origin.is_none() {
            Ok(None)
        } else {
            Ok(Some(b1))
        }
    }

    async fn try_update_executed_view<'a>(
        &'a self,
        b2: &Ref<'a, Multihash, View<T, P, S>>,
        b1: &Ref<'a, Multihash, View<T, P, S>>,
    ) -> Result<Option<Vec<T>>> {
        if b2.parent_hash != b1.hash {
            return Ok(None);
        }

        let Some(b0) = self.get_justified_view(b1.value()).await? else {
            return Ok(None);
        };

        if b1.parent_hash != b0.hash {
            return Ok(None);
        }

        let b0_number = b0.number;
        let b0_hash = b0.hash;
        let cmds = self.collect_commands(b0).await?;

        self.executed_view
            .write()
            .await
            .replace((b0_number, b0_hash));

        Ok(Some(cmds))
    }

    async fn get_view_or_unwrap(&self, hash: &Multihash) -> Result<Ref<Multihash, View<T, P, S>>> {
        Ok(self
            .views
            .get(hash)
            .await?
            .unwrap_or_else(|| panic!("View with hash {hash:?} not found in the chain")))
    }

    async fn is_higher_than_highest_qc(&self, number: ViewNumber) -> bool {
        self.highest_qc_view
            .read()
            .await
            .as_ref()
            .is_some_and(|qc| qc.0 < number)
    }

    async fn get_justified_view(
        &self,
        view: &View<T, P, S>,
    ) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        match &view.justify {
            Some(qc) => Ok(Some(self.get_view_or_unwrap(&qc.view).await?)),
            None => Ok(None),
        }
    }

    async fn is_higher_than_locked_view(&self, number: ViewNumber) -> bool {
        self.locked_view
            .read()
            .await
            .as_ref()
            .is_none_or(|lv| lv.0 <= number)
    }

    async fn collect_commands<'a>(&self, b0: Ref<'a, Multihash, View<T, P, S>>) -> Result<Vec<T>> {
        let exec_height = self
            .executed_view
            .read()
            .await
            .as_ref()
            .map_or(0, |ev| ev.0);

        let mut cmds = Vec::new();
        let mut cur = b0;

        while exec_height < cur.number {
            if let Some(cmd) = &cur.cmd {
                cmds.push(cmd.clone());
            }

            cur = self.get_view_or_unwrap(&cur.parent_hash).await?;
        }

        cmds.reverse();

        Ok(cmds)
    }

    pub fn v_height(&self) -> ViewNumber {
        self.v_height
    }

    pub async fn locked_view_number(&self) -> ViewNumber {
        self.locked_view.read().await.as_ref().map_or(0, |lv| lv.0)
    }

    pub async fn executed_view_number(&self) -> ViewNumber {
        self.executed_view
            .read()
            .await
            .as_ref()
            .map_or(0, |ev| ev.0)
    }

    pub async fn leaf_view_number(&self) -> ViewNumber {
        self.leaf_view.read().await.as_ref().map_or(0, |lv| lv.0)
    }

    pub async fn highest_qc_view_number(&self) -> ViewNumber {
        self.highest_qc_view
            .read()
            .await
            .as_ref()
            .map_or(0, |qc| qc.0)
    }

    pub async fn locked_view_hash(&self) -> Option<Multihash> {
        self.locked_view.read().await.as_ref().map(|lv| lv.1)
    }

    pub async fn executed_view_hash(&self) -> Option<Multihash> {
        self.executed_view.read().await.as_ref().map(|ev| ev.1)
    }

    pub async fn leaf_view_hash(&self) -> Option<Multihash> {
        self.leaf_view.read().await.as_ref().map(|lv| lv.1)
    }

    pub async fn highest_qc_view_hash(&self) -> Option<Multihash> {
        self.highest_qc_view
            .read()
            .await
            .as_ref()
            .map(|qc| qc.1.view)
    }

    pub async fn locked_view(&self) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        let Some(hash) = self.locked_view_hash().await else {
            return Ok(None);
        };

        Ok(Some(self.get_view_or_unwrap(&hash).await?))
    }

    pub async fn executed_view(&self) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        let Some(hash) = self.executed_view_hash().await else {
            return Ok(None);
        };

        Ok(Some(self.get_view_or_unwrap(&hash).await?))
    }

    pub async fn leaf_view(&self) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        let Some(hash) = self.leaf_view_hash().await else {
            return Ok(None);
        };

        Ok(Some(self.get_view_or_unwrap(&hash).await?))
    }

    pub async fn highest_qc_view(&self) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        let Some(hash) = self.highest_qc_view_hash().await else {
            return Ok(None);
        };

        Ok(Some(self.get_view_or_unwrap(&hash).await?))
    }

    pub async fn is_safe_view(&self, view_hash: &Multihash) -> Result<bool> {
        let view = match self.get_view(view_hash).await? {
            Some(v) => v,
            None => return Ok(false),
        };

        if view.number <= self.v_height {
            return Ok(false);
        }

        let (locked_height, locked_hash) = match self.locked_view.read().await.as_ref() {
            Some(lv) => (lv.0, lv.1),
            None => return Ok(true),
        };

        let view_qc_height = match self.get_justified_view(view.value()).await? {
            Some(justified_view) => justified_view.number,
            None => return Ok(false),
        };

        if self
            .extends_from_locked_view(view, locked_height, locked_hash)
            .await?
        {
            return Ok(true);
        }

        if view_qc_height > locked_height {
            return Ok(true);
        }

        Ok(false)
    }

    async fn extends_from_locked_view<'a>(
        &'a self,
        view: Ref<'a, Multihash, View<T, P, S>>,
        locked_height: ViewNumber,
        locked_hash: Multihash,
    ) -> Result<bool> {
        if view.number == locked_height {
            return Ok(view.hash == locked_hash);
        }

        if view.number < locked_height {
            return Ok(false);
        }

        let mut cur = view;

        while cur.number > locked_height {
            let Some(parent) = self.get_view(&cur.parent_hash).await? else {
                return Ok(false);
            };

            if parent.number == locked_height {
                return Ok(parent.hash == locked_hash);
            }

            if parent.number < locked_height {
                return Ok(false);
            }

            cur = parent;
        }

        Ok(cur.number == locked_height && cur.hash == locked_hash)
    }

    pub async fn on_receive_vote(
        &mut self,
        hash: Multihash,
        peer: P,
        sign: S,
    ) -> Result<Option<QuorumCertificate<Multihash, P, S>>> {
        let mut signs = self.votes.entry(hash).or_default();

        if signs.contains_key(&peer) {
            return Ok(None); // duplicate vote
        }

        signs.insert(peer, sign);

        if signs.len() as u64 >= self.total_nodes - self.max_faulty {
            drop(signs); // drop the lock on votes

            let votes_for_view = self
                .votes
                .remove(&hash)
                .expect("Votes should exist for the view");

            let qc = QuorumCertificate {
                view: hash,
                sigs: votes_for_view.1,
            };

            self.try_update_highest_qc(&Some(qc.clone())).await?;

            return Ok(Some(qc));
        }

        Ok(None)
    }

    pub async fn exec_hash_at(&self, b4_hash: &Multihash) -> Result<Option<Multihash>> {
        let Some(mut b4) = self.get_view(b4_hash).await? else {
            return Ok(None);
        };

        loop {
            let Some(b3) = self.get_justified_view(b4.value()).await? else {
                return Ok(None);
            };

            if let Some(root) = self.check_three_chain_from(&b3).await? {
                return Ok(Some(root.hash));
            }

            b4 = b3;
        }
    }

    async fn check_three_chain_from<'a>(
        &'a self,
        view: &Ref<'a, Multihash, View<T, P, S>>,
    ) -> Result<Option<Ref<'a, Multihash, View<T, P, S>>>> {
        let Some(b2) = self.get_justified_view(view.value()).await? else {
            return Ok(None);
        };

        let Some(b1) = self.get_justified_view(&b2).await? else {
            return Ok(None);
        };

        if b1.parent_hash != b2.hash || b2.parent_hash != view.hash {
            return Ok(None);
        }

        self.get_justified_view(&b1).await
    }

    pub async fn on_propose<H: Hasher>(&self, cmd: T) -> Result<View<T, P, S>> {
        let highest_qc = self.highest_qc_view.read().await;
        let Some((_, qc)) = highest_qc.as_ref() else {
            return Ok(View::new::<H>(
                self.leaf_view_number().await + 1,
                Multihash::default(),
                Some(cmd),
                None,
            ));
        };

        Ok(View::new::<H>(
            self.leaf_view_number().await + 1,
            qc.view,
            Some(cmd),
            Some(qc.clone()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::hot_stuff::utils::{QuorumCertificate, View};
    use std::{collections::HashMap, sync::Arc};

    type Hasher = sha2::Sha256;

    const TOTAL_NODES: u64 = 4;
    const MAX_FAULTY: u64 = 1;
    const QUORUM_SIZE: u64 = TOTAL_NODES - MAX_FAULTY;

    type TestCommand = u64;
    type TestPeer = u64;
    type TestSignature = u64;

    type TestChain = Chain<TestCommand, TestPeer, TestSignature>;
    type TestQuorumCertificate = QuorumCertificate<Multihash, TestPeer, TestSignature>;
    type TestView = View<TestCommand, TestPeer, TestSignature>;

    fn genesis_hash() -> Multihash {
        let view = TestView::new::<Hasher>(0, Multihash::default(), None, None);
        view.hash
    }

    async fn create_test_chain() -> TestChain {
        let storage = Arc::new(Storage::new_local_one());

        let genesis_view = TestView::new::<Hasher>(0, Multihash::default(), None, None);
        let genesis_hash = genesis_view.hash;

        storage
            .put(genesis_hash, genesis_view)
            .await
            .expect("Failed to store genesis view");

        TestChain::new(storage, TOTAL_NODES, MAX_FAULTY)
    }

    async fn add_view(chain: &mut TestChain, parent: Multihash, number: u64) -> Multihash {
        let view = if number == 1 {
            TestView::new::<Hasher>(number, genesis_hash(), Some(1), None)
        } else {
            let qc = create_test_qc(parent, QUORUM_SIZE);
            TestView::new::<Hasher>(number, parent, Some(number), Some(qc))
        };

        let hash = view.hash;
        chain.add_view(view).await;

        hash
    }

    async fn add_view_cus(
        chain: &mut TestChain,
        parent: Multihash,
        number: u64,
        cmd: TestCommand,
    ) -> Multihash {
        let view = if number == 1 {
            TestView::new::<Hasher>(number, genesis_hash(), Some(cmd), None)
        } else {
            let qc = create_test_qc(parent, QUORUM_SIZE);
            TestView::new::<Hasher>(number, parent, Some(cmd), Some(qc))
        };

        let hash = view.hash;
        chain.add_view(view).await;

        hash
    }

    fn create_test_qc(view_hash: Multihash, peer_count: u64) -> TestQuorumCertificate {
        let mut sigs = HashMap::new();

        for i in 0..peer_count {
            sigs.insert(i, i);
        }

        QuorumCertificate {
            view: view_hash,
            sigs,
        }
    }

    async fn add_view_and_update(
        chain: &mut TestChain,
        parent: Multihash,
        number: u64,
    ) -> (Multihash, Option<Vec<TestCommand>>) {
        let hash = add_view(chain, parent, number).await;
        let result = chain.update(&hash).await.unwrap();
        (hash, result)
    }

    #[tokio::test]
    async fn basic_chain_initialization() {
        let chain = create_test_chain().await;

        assert_eq!(chain.v_height(), 0);
        assert_eq!(chain.locked_view_number().await, 0);
        assert_eq!(chain.executed_view_number().await, 0);
        assert_eq!(chain.leaf_view_number().await, 0);
        assert_eq!(chain.highest_qc_view_number().await, 0);
    }

    #[tokio::test]
    async fn add_view_basic() {
        let mut chain = create_test_chain().await;

        let hash = add_view(&mut chain, Multihash::default(), 1).await;
        let retrieved = chain.get_view(&hash).await.unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().number, 1);
    }

    #[tokio::test]
    async fn single_view_update() {
        let mut chain = create_test_chain().await;

        let (hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
        let (_, res) = add_view_and_update(&mut chain, hash, 2).await;

        assert!(res.is_none());
        assert_eq!(chain.leaf_view_number().await, 1);
    }

    #[tokio::test]
    async fn three_chain_execution() {
        let mut chain = create_test_chain().await;

        let (view1_hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
        let (view2_hash, _) = add_view_and_update(&mut chain, view1_hash, 2).await;
        let (view3_hash, _) = add_view_and_update(&mut chain, view2_hash, 3).await;
        let (_, view4_res) = add_view_and_update(&mut chain, view3_hash, 4).await;

        let leaf_view = chain
            .leaf_view()
            .await
            .unwrap()
            .expect("Leaf view should exist");
        let locked_view = chain
            .locked_view()
            .await
            .unwrap()
            .expect("Locked view should exist");
        let executed_view = chain
            .executed_view()
            .await
            .unwrap()
            .expect("Executed view should exist");

        // view3 should be leaf
        // view2 should be locked
        // view1 should be executed
        assert_eq!(view4_res.as_ref().map(|r| r.len()), Some(1));
        assert_eq!(view4_res.unwrap()[0], 1);
        assert_eq!(leaf_view.number, 3);
        assert_eq!(leaf_view.hash, view3_hash);
        assert_eq!(locked_view.number, 2);
        assert_eq!(locked_view.hash, view2_hash);
        assert_eq!(executed_view.number, 1);
        assert_eq!(executed_view.hash, view1_hash);
    }

    #[tokio::test]
    async fn duplicate_vote_ignored() {
        let mut chain = create_test_chain().await;

        let hash = add_view(&mut chain, Multihash::default(), 1).await;

        for _ in 0u64..QUORUM_SIZE {
            let result = chain.on_receive_vote(hash, 0, 0).await.unwrap();
            assert!(result.is_none(), "Vote should not trigger a QC yet");
        }
    }

    #[tokio::test]
    async fn safety_check_with_locked_view() {
        let mut chain = create_test_chain().await;

        let (view1_hash, _) = add_view_and_update(&mut chain, Multihash::default(), 1).await;
        let (view3_hash, _) = add_view_and_update(&mut chain, view1_hash, 3).await; // skip 2
        let (view4_hash, _) = add_view_and_update(&mut chain, view3_hash, 4).await;
        let (view5_hash, _) = add_view_and_update(&mut chain, view4_hash, 5).await;

        // Now, lock view should be view 3

        let view2_hash = add_view(&mut chain, view1_hash, 2).await; // add view 2 after locking
        let view6_hash = add_view(&mut chain, view5_hash, 6).await;
        let view3_cus = add_view_cus(&mut chain, view2_hash, 3, 100).await;

        let view2_res = chain.is_safe_view(&view2_hash).await.unwrap();
        let view6_res = chain.is_safe_view(&view6_hash).await.unwrap();
        let view3_cus_res = chain.is_safe_view(&view3_cus).await.unwrap();

        assert_eq!(chain.locked_view_number().await, 3);
        assert!(!view2_res, "View 2 should be unsafe");
        assert!(view6_res, "View 6 should be safe");
        assert!(
            !view3_cus_res,
            "View 3 with custom command should be unsafe"
        );
    }
}
