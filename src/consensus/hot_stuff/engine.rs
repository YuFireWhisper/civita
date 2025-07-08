// use std::{collections::BTreeSet, marker::PhantomData, sync::Arc};
//
// use dashmap::mapref::one::Ref;
// use tokio::sync::mpsc;
//
// use crate::{
//     consensus::{
//         hot_stuff::{
//             chain,
//             proposal_pool::{self, ProposalPool},
//             utils::{self, QuorumCertificate, ViewNumber},
//         },
//         randomizer::{self, DrawProof, Randomizer},
//     },
//     crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
//     network::{
//         gossipsub::{self, Gossipsub},
//         storage,
//         transport::Transport,
//         Storage,
//     },
//     proposal::Proposal,
//     resident,
//     traits::serializable::{self, ConstantSize, Serializable},
//     utils::mpt::Mpt,
// };
//
// type Result<T, E = Error> = std::result::Result<T, E>;
//
// type ProofPair = (DrawProof, Signature);
// type Block<P> = utils::Block<P, PublicKey, ProofPair>;
// type View<P> = utils::View<Block<P>, PublicKey, ProofPair>;
// type Chain<P> = chain::Chain<Block<P>, PublicKey, ProofPair>;
//
// #[derive(Debug)]
// #[derive(thiserror::Error)]
// pub enum Error {
//     #[error("{0}")]
//     Gossipsub(#[from] gossipsub::Error),
//
//     #[error("{0}")]
//     Storage(#[from] storage::Error),
//
//     #[error("{0}")]
//     Randomizer(#[from] randomizer::Error),
//
//     #[error("{0}")]
//     Serializable(#[from] serializable::Error),
//
//     #[error("{0}")]
//     ProposalPool(#[from] proposal_pool::Error),
//
//     #[error("{0}")]
//     Proposal(String),
// }
//
// pub struct Config {
//     pub proposal_topic: u8,
//     pub view_topic: u8,
//     pub vote_topic: u8,
//
//     pub proposal_pool_capacity: usize,
//     pub expected_leaders: u16,
//     pub expected_members: u16,
//     pub wait_leader_timeout: tokio::time::Duration,
// }
//
// #[derive(Debug)]
// enum ViewWaitResult {
//     ConsecutiveView(Multihash),
//     NonConsecutiveView(Multihash),
//     Timeout,
// }
//
// struct Vote {
//     hash: Multihash,
//     pk: PublicKey,
//     proof: DrawProof,
//     sig: Signature,
// }
//
// pub struct Engine<P, H>
// where
//     P: Proposal,
//     H: Hasher,
// {
//     gossipsub: Arc<Gossipsub>,
//     storage: Arc<Storage>,
//     sk: SecretKey,
//     proposal_pool: ProposalPool<P>,
//     chain: Chain<P>,
//     records: Mpt<resident::Record>,
//     randomizer: Randomizer,
//     config: Config,
//     _marker: PhantomData<H>,
// }
//
// impl<P, H> Engine<P, H>
// where
//     P: Proposal,
//     H: Hasher,
// {
//     pub async fn spawn(
//         transport: Arc<Transport>,
//         chain: Chain<P>,
//         root_hash: Multihash,
//         config: Config,
//     ) -> Result<()> {
//         let gossipsub = transport.gossipsub();
//         let storage = transport.storage();
//         let sk = transport.secret_key().clone();
//
//         let rx = gossipsub.subscribe(config.proposal_topic).await?;
//         let proposal_pool = ProposalPool::<P>::new(rx, config.proposal_pool_capacity);
//         let randomizer = Randomizer::new(config.expected_leaders, config.expected_members);
//         let records = Mpt::with_root(storage.clone(), root_hash);
//
//         tokio::spawn(async move {
//             let mut engine = Self {
//                 gossipsub,
//                 storage,
//                 sk,
//                 proposal_pool,
//                 chain,
//                 records,
//                 randomizer,
//                 config,
//                 _marker: PhantomData,
//             };
//
//             if let Err(e) = engine.run().await {
//                 log::error!("Engine error: {e}");
//             }
//
//             log::info!("Engine stopped");
//         });
//
//         Ok(())
//     }
//
//     async fn run(&mut self) -> Result<()> {
//         let mut view_rx = self.gossipsub.subscribe(self.config.view_topic).await?;
//         let mut vote_rx = self.gossipsub.subscribe(self.config.vote_topic).await?;
//
//         let mut leader_proof = None;
//         let mut validator_proof = None;
//
//         loop {
//             if let Err(e) = self
//                 .consensus_round(
//                     &mut view_rx,
//                     &mut vote_rx,
//                     &mut leader_proof,
//                     &mut validator_proof,
//                 )
//                 .await
//             {
//                 log::error!("Consensus round error: {e}");
//                 continue;
//             }
//
//             self.update_roles(&mut leader_proof, &mut validator_proof)
//                 .await?;
//         }
//     }
//
//     async fn consensus_round(
//         &mut self,
//         view_rx: &mut mpsc::Receiver<Vec<u8>>,
//         vote_rx: &mut mpsc::Receiver<Vec<u8>>,
//         leader_proof: &mut Option<DrawProof>,
//         validator_proof: &mut Option<DrawProof>,
//     ) -> Result<()> {
//         let expected_view_number = self.chain.leaf_view_number().await + 1;
//
//         let view_result = self
//             .wait_for_next_view(view_rx, vote_rx, expected_view_number)
//             .await?;
//
//         match view_result {
//             ViewWaitResult::ConsecutiveView(view_hash) => {
//                 self.handle_consecutive_view(view_hash, leader_proof, validator_proof)
//                     .await?;
//             }
//             ViewWaitResult::NonConsecutiveView(view_hash) => {
//                 self.handle_non_consecutive_view(view_hash).await?;
//             }
//             ViewWaitResult::Timeout => {
//                 log::debug!("View wait timeout, proceeding to election");
//             }
//         }
//
//         Ok(())
//     }
//
//     async fn wait_for_next_view(
//         &mut self,
//         view_rx: &mut mpsc::Receiver<Vec<u8>>,
//         vote_rx: &mut mpsc::Receiver<Vec<u8>>,
//         expected_view_number: ViewNumber,
//     ) -> Result<ViewWaitResult> {
//         let timeout = tokio::time::sleep(self.config.wait_leader_timeout);
//         tokio::pin!(timeout);
//
//         log::debug!(
//             "Waiting for view {}, timeout: {:?}",
//             expected_view_number,
//             self.config.wait_leader_timeout
//         );
//
//         let mut consecutive_candidates: Vec<(Multihash, Multihash)> = Vec::new();
//
//         loop {
//             tokio::select! {
//                 _ = &mut timeout => {
//                     log::debug!("View wait timeout for view {expected_view_number}");
//
//                     if !consecutive_candidates.is_empty() {
//                         consecutive_candidates.sort_by(|a, b| a.1.cmp(&b.1));
//                         let best_view_hash = consecutive_candidates[0].0;
//                         log::info!("Selected consecutive view with smallest proof hash: {best_view_hash:?}");
//                         return Ok(ViewWaitResult::ConsecutiveView(best_view_hash));
//                     }
//
//                     return Ok(ViewWaitResult::Timeout);
//                 }
//
//                 Some(msg) = view_rx.recv() => {
//                     let hash = Multihash::from_slice(&msg)?;
//
//                     let Some(view_number) = self.get_view_number(&hash).await? else {
//                         log::warn!("Could not determine view number for hash: {hash:?}");
//                         continue;
//                     };
//
//                     log::debug!("Received view {view_number} (expecting {expected_view_number})");
//
//                     if view_number == expected_view_number {
//                         log::debug!("Received consecutive view {view_number}, adding to candidates");
//
//                         if let Some(proof_hash) = self.get_view_proof_hash(&hash).await? {
//                             consecutive_candidates.push((hash, proof_hash));
//                             log::debug!("Added consecutive view candidate with proof hash: {proof_hash:?}");
//                         } else {
//                             log::warn!("Could not get proof hash for consecutive view: {hash:?}");
//                         }
//
//                         continue;
//                     }
//
//                     if view_number > expected_view_number {
//                         log::info!("Received non-consecutive view {view_number} > {expected_view_number}");
//
//                         if self.is_valid_future_view(&hash).await? {
//                             log::info!("Non-consecutive view {view_number} is valid, using immediately");
//                             return Ok(ViewWaitResult::NonConsecutiveView(hash));
//                         }
//
//                         log::warn!("Invalid future view {view_number}");
//                         continue;
//                     }
//
//                     log::debug!("Ignoring old view {view_number} < {expected_view_number}");
//                 }
//
//                 Some(msg) = vote_rx.recv() => {
//                     if let Err(e) = self.handle_vote_message(msg).await {
//                         log::error!("Error handling vote message: {e}");
//                     }
//                 }
//             }
//         }
//     }
//
//     async fn get_view_proof_hash(&self, view_hash: &Multihash) -> Result<Option<Multihash>> {
//         let Some(view) = self.chain.get_view(view_hash).await? else {
//             return Ok(None);
//         };
//
//         let proof_hash = view.cmd.leader.1 .0.proof.to_hash();
//
//         Ok(Some(proof_hash))
//     }
//
//     async fn is_leader_valid(&self, cur_view: &View<P>) -> Result<bool> {
//         let (pk, (proof, sig)) = &cur_view.cmd.leader;
//
//         let Some(exec_view) = self.get_exec_view_at(&cur_view.hash).await? else {
//             return Ok(false);
//         };
//
//         let seed = Self::generate_seed(&exec_view.hash, cur_view.number);
//
//         self.is_role_valid(
//             &cur_view.hash.to_bytes(),
//             seed.digest(),
//             exec_view.cmd.executed_total_stakes,
//             (pk, (proof, sig)),
//             true,
//         )
//         .await
//         .map(|res| res.is_some())
//     }
//
//     async fn get_exec_view_at(
//         &self,
//         view_hash: &Multihash,
//     ) -> Result<Option<Ref<Multihash, View<P>>>> {
//         let Some(exec_hash) = self.chain.exec_hash_at(view_hash).await? else {
//             return Ok(None);
//         };
//
//         let Some(view) = self.chain.get_view(&exec_hash).await? else {
//             return Ok(None);
//         };
//
//         Ok(Some(view))
//     }
//
//     fn generate_seed(exec_hash: &Multihash, view: ViewNumber) -> Multihash {
//         let mut bytes = Vec::with_capacity(exec_hash.serialized_size() + ViewNumber::SIZE);
//
//         exec_hash.to_writer(&mut bytes).unwrap();
//         view.to_writer(&mut bytes).unwrap();
//
//         H::hash(&bytes)
//     }
//
//     async fn is_role_valid(
//         &self,
//         view_hash: &[u8],
//         seed: &[u8],
//         total_stakes: u32,
//         info: (&PublicKey, (&DrawProof, &Signature)),
//         is_leader: bool,
//     ) -> Result<Option<u32>> {
//         let (pk, (proof, sig)) = info;
//
//         if !pk.verify_signature(view_hash, sig) {
//             return Ok(None);
//         }
//
//         let pk_hash = H::hash(&pk.to_vec().expect("PublicKey serialization failed"));
//
//         let Some(stakes) = self
//             .records
//             .get(&pk_hash.to_bytes())
//             .await?
//             .map(|r| r.stakes)
//         else {
//             return Ok(None);
//         };
//
//         if stakes == 0 {
//             return Ok(None);
//         }
//
//         if !self
//             .randomizer
//             .verify::<H>(seed, total_stakes, pk, stakes, proof, is_leader)
//         {
//             return Ok(None);
//         }
//
//         Ok(Some(stakes))
//     }
//
//     async fn is_justify_valid(
//         &self,
//         justify: &QuorumCertificate<Multihash, PublicKey, ProofPair>,
//     ) -> Result<bool> {
//         let Some(jus_view) = self.chain.get_view(&justify.view).await? else {
//             return Ok(false);
//         };
//
//         let Some(exec_view) = self.get_exec_view_at(&justify.view).await? else {
//             return Ok(false);
//         };
//
//         let seed = Self::generate_seed(&exec_view.hash, jus_view.number);
//
//         let jus_view_bytes = jus_view.hash.to_bytes();
//
//         let mut total_votes = 0u32;
//
//         for (pk, (proof, sig)) in justify.sigs.iter() {
//             let Some(stakes) = self
//                 .is_role_valid(
//                     &jus_view_bytes,
//                     seed.digest(),
//                     exec_view.cmd.executed_total_stakes,
//                     (pk, (proof, sig)),
//                     false,
//                 )
//                 .await?
//             else {
//                 return Ok(false);
//             };
//
//             total_votes += stakes;
//         }
//
//         if total_votes < self.config.expected_members as u32 {
//             return Ok(false);
//         }
//
//         Ok(true)
//     }
//
//     async fn apply_proposal(&mut self, proposal: &BTreeSet<P>) -> Result<Option<(Multihash, u32)>> {
//         self.records.rollback();
//
//         let mut total_stakes = 0u32;
//
//         for prop in proposal {
//             if !prop
//                 .verify::<H>(&self.records)
//                 .await
//                 .map_err(|e| Error::Proposal(e.to_string()))?
//             {
//                 return Ok(None);
//             }
//
//             prop.apply::<H>(&mut self.records)
//                 .await
//                 .map_err(|e| Error::Proposal(e.to_string()))?;
//
//             let stakes = prop
//                 .impact_stakes()
//                 .map_err(|e| Error::Proposal(e.to_string()))?;
//
//             total_stakes = total_stakes.wrapping_add_signed(stakes);
//         }
//
//         let Some(hash) = self.records.root_hash() else {
//             return Ok(None);
//         };
//
//         self.records.rollback();
//
//         Ok(Some((hash, total_stakes)))
//     }
//
//     async fn apply_proposal_or_reduce(
//         &mut self,
//         proposal: BTreeSet<P>,
//     ) -> Result<(BTreeSet<P>, Multihash, u32)> {
//         self.records.rollback();
//
//         let mut total_stakes = 0u32;
//
//         let mut finals = BTreeSet::new();
//
//         for prop in proposal.into_iter() {
//             if !prop
//                 .verify::<H>(&self.records)
//                 .await
//                 .map_err(|e| Error::Proposal(e.to_string()))?
//             {
//                 continue;
//             }
//
//             if (prop.apply::<H>(&mut self.records).await).is_err() {
//                 continue;
//             }
//
//             let stakes = prop
//                 .impact_stakes()
//                 .map_err(|e| Error::Proposal(e.to_string()))?;
//
//             total_stakes = total_stakes.wrapping_add_signed(stakes);
//
//             finals.insert(prop);
//         }
//
//         let Some(hash) = self.records.root_hash() else {
//             panic!("Root hash should exist after applying proposals");
//         };
//
//         self.records.rollback();
//
//         Ok((finals, hash, total_stakes))
//     }
//
//     async fn handle_vote_message(&mut self, msg: Vec<u8>) -> Result<()> {
//         let vote = Vote::from_slice(&msg)?;
//
//         let _ = self
//             .chain
//             .on_receive_vote(vote.hash, vote.pk, (vote.proof, vote.sig))
//             .await?;
//
//         Ok(())
//     }
//
//     async fn get_view_number(&self, view_hash: &Multihash) -> Result<Option<ViewNumber>> {
//         let Some(view) = self.chain.get_view(view_hash).await? else {
//             return Ok(None);
//         };
//
//         Ok(Some(view.number))
//     }
//
//     async fn is_valid_future_view(&self, view_hash: &Multihash) -> Result<bool> {
//         if !self.chain.is_safe_view(view_hash).await? {
//             return Ok(false);
//         }
//
//         let Some(view) = self.chain.get_view(view_hash).await? else {
//             return Ok(false);
//         };
//
//         if !self.is_leader_valid(view.value()).await? {
//             return Ok(false);
//         }
//
//         if !self.is_justify_valid(&view.justify).await? {
//             return Ok(false);
//         }
//
//         Ok(true)
//     }
//
//     async fn handle_consecutive_view(
//         &mut self,
//         view_hash: Multihash,
//         leader_proof: &mut Option<DrawProof>,
//         validator_proof: &mut Option<DrawProof>,
//     ) -> Result<()> {
//         let Some(cur_view) = self.chain.get_view(&view_hash).await? else {
//             return Ok(());
//         };
//
//         let cur_view_clone = cur_view.value().clone();
//         drop(cur_view);
//
//         if let Err(e) = self
//             .proposal_pool
//             .remove(cur_view_clone.cmd.proposals.clone())
//             .await
//         {
//             log::warn!("Failed to remove proposals from pool: {e}");
//         }
//
//         let _ = self.chain.update(&view_hash).await?;
//
//         if let Some(proof) = validator_proof.take() {
//             self.cast_vote(&cur_view_clone, proof).await?;
//         }
//
//         if let Some(proof) = leader_proof.take() {
//             self.propose_new_view(&view_hash, proof).await?;
//         }
//
//         Ok(())
//     }
//
//     async fn handle_non_consecutive_view(&mut self, view_hash: Multihash) -> Result<()> {
//         let Some(view) = self.chain.get_view(&view_hash).await? else {
//             return Ok(());
//         };
//
//         if let Err(e) = self.proposal_pool.remove(view.cmd.proposals.clone()).await {
//             log::warn!("Failed to remove proposals from pool: {e}");
//         }
//
//         drop(view);
//
//         let _ = self.chain.update(&view_hash).await?;
//
//         log::info!("Updated chain with non-consecutive view: {view_hash:?}");
//
//         Ok(())
//     }
//
//     async fn cast_vote(&mut self, view: &View<P>, proof: DrawProof) -> Result<()> {
//         if let Some((exec_hash, total_stakes)) = self.apply_proposal(&view.cmd.proposals).await? {
//             if exec_hash != view.cmd.executed_root_hash
//                 || total_stakes != view.cmd.executed_total_stakes
//             {
//                 return Ok(());
//             }
//
//             let pk = self.sk.public_key();
//             let sig = self.sk.sign(&view.hash.to_bytes());
//
//             let vote = Vote {
//                 hash: view.hash,
//                 pk: pk.clone(),
//                 proof: proof.clone(),
//                 sig: sig.clone(),
//             };
//
//             self.gossipsub
//                 .publish(self.config.vote_topic, vote.to_vec()?)
//                 .await?;
//
//             let _ = self
//                 .chain
//                 .on_receive_vote(view.hash, pk, (proof, sig))
//                 .await?;
//         }
//
//         Ok(())
//     }
//
//     async fn propose_new_view(&mut self, parent_hash: &Multihash, proof: DrawProof) -> Result<()> {
//         let proposals = self.proposal_pool.get().await?;
//         let (proposals, exec_hash, total_stakes) = self.apply_proposal_or_reduce(proposals).await?;
//
//         let pk = self.sk.public_key();
//         let sig = self.sk.sign(&parent_hash.to_bytes());
//
//         let block = Block::<P> {
//             leader: (pk, (proof, sig)),
//             proposals,
//             executed_root_hash: exec_hash,
//             executed_total_stakes: total_stakes,
//         };
//
//         let view = self.chain.on_propose::<H>(block).await?;
//         let view_bytes = view.to_vec()?;
//
//         self.storage.put(view.hash, view_bytes).await?;
//
//         self.gossipsub
//             .publish(self.config.view_topic, view.hash.to_bytes())
//             .await?;
//
//         Ok(())
//     }
//
//     async fn update_roles(
//         &mut self,
//         leader_proof: &mut Option<DrawProof>,
//         validator_proof: &mut Option<DrawProof>,
//     ) -> Result<()> {
//         let exec_view = self.chain.executed_view().await?;
//
//         let pk_hash = H::hash(&self.sk.public_key().to_vec()?);
//         let stakes = self
//             .records
//             .get(&pk_hash.to_bytes())
//             .await?
//             .map(|r| r.stakes)
//             .unwrap_or(0);
//
//         let next_view_number = self.chain.leaf_view_number().await + 1;
//         let seed = Self::generate_seed(&exec_view.hash, next_view_number);
//
//         *leader_proof = self.randomizer.draw::<H>(
//             seed.digest(),
//             exec_view.cmd.executed_total_stakes,
//             &self.sk,
//             stakes,
//             true,
//         )?;
//
//         *validator_proof = self.randomizer.draw::<H>(
//             seed.digest(),
//             exec_view.cmd.executed_total_stakes,
//             &self.sk,
//             stakes,
//             false,
//         )?;
//
//         Ok(())
//     }
// }
//
// impl Serializable for Vote {
//     fn serialized_size(&self) -> usize {
//         self.hash.serialized_size()
//             + self.pk.serialized_size()
//             + self.proof.serialized_size()
//             + self.sig.serialized_size()
//     }
//
//     fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
//         Ok(Self {
//             hash: Multihash::from_reader(reader)?,
//             pk: PublicKey::from_reader(reader)?,
//             proof: DrawProof::from_reader(reader)?,
//             sig: Signature::from_reader(reader)?,
//         })
//     }
//
//     fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
//         self.hash.to_writer(writer)?;
//         self.pk.to_writer(writer)?;
//         self.proof.to_writer(writer)?;
//         self.sig.to_writer(writer)?;
//
//         Ok(())
//     }
// }
