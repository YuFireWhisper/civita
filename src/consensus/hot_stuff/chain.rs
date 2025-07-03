use std::{collections::HashMap, hash::Hash};

use dashmap::{mapref::one::Ref, DashMap};
use tokio::sync::RwLock;

use crate::{
    consensus::hot_stuff::utils::{QuorumCertificate, View, ViewNumber},
    crypto::{Hasher, Multihash},
    network::{
        traits::{storage, Storage},
        CacheStorage,
    },
    traits::Serializable,
};

type ViewPair = (ViewNumber, Multihash);
type QuorumCertificatePair<P, S> = (ViewNumber, QuorumCertificate<Multihash, P, S>);

type Result<T, E = storage::Error> = std::result::Result<T, E>;

pub struct Chain<T, P, S, ST: Storage> {
    views: CacheStorage<View<T, P, S>, ST>,

    locked_view: RwLock<Option<ViewPair>>,
    executed_view: RwLock<Option<ViewPair>>,
    leaf_view: RwLock<Option<ViewPair>>,
    highest_qc_view: RwLock<Option<QuorumCertificatePair<P, S>>>,

    v_height: ViewNumber,
    votes: DashMap<Multihash, HashMap<P, S>>,

    total_nodes: usize,
    max_faulty: usize,
}

impl<T, P, S, ST> Chain<T, P, S, ST>
where
    T: Clone + Serializable + Send + Sync + 'static,
    P: Clone + Serializable + Eq + Hash + Send + Sync + 'static,
    S: Clone + Serializable + Send + Sync + 'static,
    ST: Storage,
{
    pub fn new(stroage: ST, total_nodes: usize, max_faulty: usize) -> Self {
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

    pub fn add_view(&mut self, hash: Multihash, view: View<T, P, S>) {
        self.views.insert(hash, view);
    }

    pub async fn update(&mut self, b3_hash: &Multihash) -> Result<Option<Vec<T>>> {
        let (b3_number, b3_hash_copy, justify) = {
            let b3 = self.get_view_or_unwrap(b3_hash).await?;
            (b3.number, b3.hash, b3.justify.clone())
        };

        let max_view_jump = 10;
        if b3_number > self.v_height + max_view_jump {
            log::warn!(
                "View jump too large: {} > {} + {}",
                b3_number,
                self.v_height,
                max_view_jump
            );
            // Still allow but log for monitoring
        }

        log::debug!("Processing view update: {} -> {}", self.v_height, b3_number);

        let b2_view_hash = match self.try_update_highest_qc(&justify).await? {
            Some(hash) => {
                log::debug!("Updated highest QC");
                hash
            }
            None => {
                log::debug!("Could not update highest QC");
                return Ok(None);
            }
        };

        let b1_view_hash = match self.try_update_locked_view(&b2_view_hash).await? {
            Some(hash) => {
                log::debug!("Updated locked view");
                hash
            }
            None => {
                log::debug!("Could not update locked view");
                return Ok(None);
            }
        };

        let executed_commands = self
            .try_update_executed_view(&b2_view_hash, &b1_view_hash)
            .await?;

        self.leaf_view
            .write()
            .await
            .replace((b3_number, b3_hash_copy));

        let old_height = self.v_height;
        if b3_number > self.v_height {
            self.v_height = b3_number;
            log::info!("Updated chain height: {} -> {}", old_height, self.v_height);
        }

        if let Some(ref cmds) = executed_commands {
            log::info!("Executed {} commands", cmds.len());
        }

        Ok(executed_commands)
    }

    async fn try_update_highest_qc(
        &mut self,
        qc: &Option<QuorumCertificate<Multihash, P, S>>,
    ) -> Result<Option<Multihash>> {
        let Some(qc) = qc else {
            return Ok(None);
        };

        let b2 = self.get_view_or_unwrap(&qc.view).await?;
        let b2_number = b2.number;
        let b2_hash = b2.hash;

        if !self.is_higher_than_highest_qc(b2_number).await {
            return Ok(None);
        }

        let origin = self
            .highest_qc_view
            .write()
            .await
            .replace((b2_number, qc.clone()));

        if origin.is_none() {
            Ok(None)
        } else {
            Ok(Some(b2_hash))
        }
    }

    async fn try_update_locked_view(&mut self, b2_hash: &Multihash) -> Result<Option<Multihash>> {
        let b1_hash = {
            let b2 = self.get_view_or_unwrap(b2_hash).await?;
            self.get_justified_view_hash(&b2).await?
        };

        let Some(b1_hash) = b1_hash else {
            return Ok(None);
        };

        let b1_number = {
            let b1 = self.get_view_or_unwrap(&b1_hash).await?;
            b1.number
        };

        if !self.is_higher_than_locked_view(b1_number).await {
            return Ok(None);
        }

        let origin = self.locked_view.write().await.replace((b1_number, b1_hash));

        if origin.is_none() {
            Ok(None)
        } else {
            Ok(Some(b1_hash))
        }
    }

    async fn try_update_executed_view(
        &mut self,
        b2_hash: &Multihash,
        b1_hash: &Multihash,
    ) -> Result<Option<Vec<T>>> {
        let (b2_parent_hash, b1_parent_hash, b1_justify_view) = {
            let b2 = self.get_view_or_unwrap(b2_hash).await?;
            let b1 = self.get_view_or_unwrap(b1_hash).await?;
            let justify_view = b1.justify.as_ref().map(|qc| qc.view);
            (b2.parent_hash, b1.parent_hash, justify_view)
        };

        if b2_parent_hash != *b1_hash {
            return Ok(None);
        }

        if Some(b1_parent_hash) != b1_justify_view {
            return Ok(None);
        }

        let b0 = self.get_view_or_unwrap(&b1_parent_hash).await?;
        let b0_number = b0.number;
        let b0_hash = b0.hash;

        self.executed_view
            .write()
            .await
            .replace((b0_number, b0_hash));

        let cmds = self.collect_commands(b0).await?;

        Ok(Some(cmds))
    }

    async fn get_justified_view_hash(&self, view: &View<T, P, S>) -> Result<Option<Multihash>> {
        match &view.justify {
            Some(qc) => Ok(Some(qc.view)),
            None => Ok(None),
        }
    }

    async fn get_view_or_unwrap(&self, hash: &Multihash) -> Result<Ref<Multihash, View<T, P, S>>> {
        Ok(self
            .views
            .get(hash)
            .await?
            .expect("View must exist in the cache"))
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
            .is_some_and(|lv| lv.0 < number)
    }

    async fn collect_commands<'a>(
        &self,
        view: Ref<'a, Multihash, View<T, P, S>>,
    ) -> Result<Vec<T>> {
        let exec_height = self
            .executed_view
            .read()
            .await
            .as_ref()
            .expect("Executed view should exist")
            .0;

        let mut cmds = Vec::new();
        let mut cur = view;

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

    pub async fn get_view(
        &self,
        hash: &Multihash,
    ) -> Result<Option<Ref<Multihash, View<T, P, S>>>> {
        self.views.get(hash).await
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

        if signs.len() >= self.total_nodes - self.max_faulty {
            let votes_for_view = self
                .votes
                .remove(&hash)
                .expect("Votes should exist for the view");

            let qc = QuorumCertificate {
                view: hash,
                sigs: votes_for_view.1,
            };

            // Update highest QC if this is higher
            let should_update = {
                let current_qc = self.highest_qc_view.read().await;
                match current_qc.as_ref() {
                    Some((current_height, _)) => {
                        if let Some(view) = self.get_view(&hash).await? {
                            view.number > *current_height
                        } else {
                            false
                        }
                    }
                    None => true,
                }
            };

            if should_update {
                if let Some(view) = self.get_view(&hash).await? {
                    self.highest_qc_view
                        .write()
                        .await
                        .replace((view.number, qc.clone()));
                }
            }

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
        let leaf_view = self.leaf_view.read().await;
        let Some(leaf_view) = *leaf_view else {
            return Ok(View::new::<H>(
                self.v_height + 1,
                Multihash::default(),
                Some(cmd),
                None,
            ));
        };

        let justify = self
            .get_view_or_unwrap(&leaf_view.1)
            .await?
            .justify
            .as_ref()
            .expect("Leaf view should always have a justify")
            .clone();

        Ok(View::new::<H>(
            self.v_height + 1,
            leaf_view.1,
            Some(cmd),
            Some(justify),
        ))
    }
}
