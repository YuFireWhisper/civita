use std::sync::Arc;

use libp2p::{Multiaddr, PeerId};
use tokio::time;

use crate::{
    consensus::randomizer::{self, DrawProof, Drawer, VerifyDrawProof},
    constants::{U16_LENGTH, U64_LENGTH},
    crypto::traits::{hasher::HashArray, vrf::Proof, Hasher, PublicKey, SecretKey, Suite},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, Node},
    },
    resident,
};

type Result<T> = std::result::Result<T, Error>;

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    MerkleDag(#[from] merkle_dag::Error),

    #[error("{0}")]
    Randomizer(#[from] randomizer::Error),
}

pub struct Config {
    pub expected_leaders: u16,
    pub expected_members: u16,
    pub topic: String,
    pub wait_leader_timeout: tokio::time::Duration,
}

pub struct Elector<S: Suite> {
    transport: Arc<Transport>,
    sk: S::SecretKey,
    config: Config,
}

impl<S> Elector<S>
where
    S: Suite,
    S::SecretKey: Drawer<S::Hasher>,
    S::PublicKey: VerifyDrawProof<S::Hasher>,
    S::Hasher: merkle_dag::HasherConfig,
{
    pub async fn elect(
        &self,
        number: u64,
        total_stakes: u32,
        root_hash: HashArray<S::Hasher>,
    ) -> Result<(PeerId, Multiaddr)> {
        let mut counter = 0u16;

        let mut base_seed = Vec::with_capacity(U64_LENGTH + root_hash.len() + U16_LENGTH);
        base_seed.extend(number.to_be_bytes());
        base_seed.extend_from_slice(&root_hash);

        loop {
            let seed = self.generate_seed(&mut base_seed, counter);

            let ctx = randomizer::Context::<S::Hasher>::new(
                seed.clone(),
                total_stakes,
                self.config.expected_leaders,
                self.config.expected_members,
            );

            let own_stake = self.get_stakes(&self.sk.public_key(), &root_hash).await?;
            let proof = self.sk.draw(&ctx, own_stake, true)?;

            if let Some(proof) = &proof {
                let payload = gossipsub::Payload::ConsensusCandidate {
                    seed: seed.to_vec(),
                    proof: proof.to_bytes(),
                    pk: self.sk.public_key().to_bytes(),
                    addr: self.transport.self_address().await,
                };
                self.transport.publish(&self.config.topic, payload).await?;
            }

            if let Some(leader) = self.wait_for_leader(&ctx, seed, proof).await? {
                return Ok(leader);
            }

            counter += 1;
        }
    }

    fn generate_seed(&self, base_seed: &mut Vec<u8>, counter: u16) -> HashArray<S::Hasher> {
        base_seed.extend(counter.to_be_bytes());
        let seed = S::Hasher::hash(base_seed);
        base_seed.truncate(base_seed.len() - U16_LENGTH);
        seed
    }

    async fn get_stakes(&self, pk: &S::PublicKey, root_hash: &HashArray<S::Hasher>) -> Result<u32> {
        let peer_hash = S::Hasher::hash(&pk.to_bytes());

        let root = self
            .transport
            .get::<Node<S::Hasher>, S::Hasher>(root_hash)
            .await?
            .expect("Root node should always exist");

        match root.get(peer_hash, &self.transport).await? {
            Some(hash) => Ok(self
                .transport
                .get::<resident::Record, S::Hasher>(&hash)
                .await?
                .expect("Record should exist")
                .stakes),
            None => Ok(0),
        }
    }

    async fn wait_for_leader(
        &self,
        ctx: &randomizer::Context<S::Hasher>,
        seed: HashArray<S::Hasher>,
        init: Option<DrawProof<S::Proof>>,
    ) -> Result<Option<(PeerId, Multiaddr)>> {
        let mut trigger = time::interval(self.config.wait_leader_timeout);
        let mut rx = self.transport.listen_on_topic(&self.config.topic).await?;

        let mut leader_output = init.as_ref().map(|proof| proof.proof.proof_to_hash());
        let mut leader: Option<(PeerId, Multiaddr)> = if init.is_some() {
            Some((
                self.transport.self_peer(),
                self.transport.self_address().await,
            ))
        } else {
            None
        };

        loop {
            tokio::select! {
                _ = trigger.tick() => {
                    return Ok(leader);
                }

                Some(msg) = rx.recv() => {
                    if let gossipsub::Payload::ConsensusCandidate { seed: received_seed, proof, pk, addr } = msg.payload {
                        if received_seed != seed.as_slice() {
                            continue;
                        }

                        if PeerId::from_bytes(&pk).map_or(true, |peer_id| msg.source != peer_id) {
                            continue;
                        }

                        let Ok(proof) = DrawProof::from_slice(&proof) else { continue };
                        let Ok(pk) = S::PublicKey::from_slice(&pk) else { continue };

                        let stakes = self.get_stakes(&pk, &seed).await?;
                        if stakes == 0 {
                            continue;
                        }

                        if !pk.verify_draw_proof(ctx, stakes, &proof, true)? {
                            continue;
                        }

                        let new_hash = proof.proof.proof_to_hash();
                        if leader_output.as_ref().is_some_and(|hash| hash < &new_hash) {
                            continue;
                        }

                        leader_output = Some(new_hash);
                        leader = Some((msg.source, addr));
                    }
                }
            }
        }
    }
}
