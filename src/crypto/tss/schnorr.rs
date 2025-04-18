use std::{collections::HashSet, sync::Arc};

use sha2::{Digest, Sha256};

use crate::{
    crypto::{
        dkg::{Dkg_, GenerateResult},
        index_map::IndexedMap,
        primitives::{
            algebra::{self, Point, Scalar},
            threshold,
        },
        tss::schnorr::collector::CollectionResult,
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

mod collector;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Algebra(#[from] algebra::Error),

    #[error("{0}")]
    Dkg(String),

    #[error("{0}")]
    Collector(#[from] collector::Error),

    #[error("Transport error: {0}")]
    Transport(String),
}

pub enum SignResult {
    Success(Scalar),
    Failure(HashSet<libp2p::PeerId>),
}

enum RandomGenerateResult {
    Success(Scalar),
    Failure(HashSet<libp2p::PeerId>),
}

#[derive(Debug)]
pub struct Config {
    pub threshold_counter: threshold::Counter,
    pub topic: String,
    pub timeout: tokio::time::Duration,
    pub random_generate_id_suffix: Vec<u8>,
    pub gossipusb_topic: String,
}

pub struct Schnorr<D: Dkg_, T: Transport + 'static> {
    transport: Arc<T>,
    dkg: D,
    secret: Option<Scalar>,
    golobal_pk: Option<Point>,
    collector: collector::Collector<T>,
    peer_index: Option<IndexedMap<libp2p::PeerId, ()>>,
    config: Config,
}

impl<D: Dkg_, T: Transport> Schnorr<D, T> {
    pub fn new(dkg: D, transport: Arc<T>, config: Config) -> Result<Self> {
        let collector_config = collector::Config {
            threshold_counter: config.threshold_counter,
            topic: config.topic.clone(),
            timeout: config.timeout,
        };

        let collector = collector::Collector::new(transport.clone(), collector_config);

        Ok(Self {
            transport,
            dkg,
            secret: None,
            golobal_pk: None,
            collector,
            peer_index: None,
            config,
        })
    }

    pub async fn start(
        &mut self,
        secret: Scalar,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let global_pk = Point::sum(
            partial_pks
                .values()
                .map(|ps| ps.first().expect("Partial PKs not empty")),
        )?;

        self.secret = Some(secret);
        self.golobal_pk = Some(global_pk);
        self.peer_index = Some(self.convert_to_peer_index(&partial_pks));
        self.collector.stop().await;
        self.collector.start(partial_pks).await?;

        Ok(())
    }

    fn convert_to_peer_index(
        &self,
        peer_pks: &IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> IndexedMap<libp2p::PeerId, ()> {
        let mut peer_index = IndexedMap::new();
        for peer_id in peer_pks.keys() {
            peer_index.insert(*peer_id, ());
        }
        peer_index
    }

    pub async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Result<SignResult> {
        let own_random_share = match self.generate_random(id.clone()).await? {
            RandomGenerateResult::Success(secret) => secret,
            RandomGenerateResult::Failure(invalid_peers) => {
                return Ok(SignResult::Failure(invalid_peers));
            }
        };

        self.publish_random(id.clone(), own_random_share.clone())
            .await?;
        let mut random_shares = match self.collect_random(id.clone()).await? {
            CollectionResult::Success(shares) => shares,
            CollectionResult::Failure(invalid_peers) => {
                return Ok(SignResult::Failure(invalid_peers));
            }
        };

        random_shares.insert(self.transport.self_peer(), own_random_share.clone());

        let indices = self.get_indices(random_shares.keys());
        let shares = random_shares.into_values().collect::<Vec<_>>();
        let random = Scalar::lagrange_interpolation(&indices, &shares)?;
        let challenge = self.compute_challenge(msg, &random)?;
        let own_sig = self.calaulate_signature(&challenge, &own_random_share)?;
        self.publish_signature(id.clone(), own_sig.clone()).await?;
        let result = self.collector.query_signature_share(id.clone()).await?;

        match result {
            CollectionResult::Success(mut shares) => {
                shares.insert(self.transport.self_peer(), own_sig);
                let indices = self.get_indices(shares.keys());
                let sig_shares = shares.into_values().collect::<Vec<_>>();
                let sig = Scalar::lagrange_interpolation(&indices, &sig_shares)?;
                Ok(SignResult::Success(sig))
            }
            collector::CollectionResult::Failure(invalid_peers) => {
                Ok(SignResult::Failure(invalid_peers))
            }
        }
    }

    fn get_indices<'a>(&self, iter: impl Iterator<Item = &'a libp2p::PeerId>) -> Vec<u16> {
        let peer_index = self.peer_index.as_ref().expect("Peer index is not set");
        let mut indices = Vec::new();

        for peer_id in iter {
            let index = peer_index
                .get_index(peer_id)
                .expect("Peer ID not found in peer index");
            indices.push(index);
        }

        indices
    }

    async fn generate_random(&self, id: Vec<u8>) -> Result<RandomGenerateResult> {
        let id = self.combine_id(id);

        let result = self
            .dkg
            .generate(id)
            .await
            .map_err(|e| Error::Dkg(e.to_string()))?;

        match result {
            GenerateResult::Success { secret, .. } => Ok(RandomGenerateResult::Success(secret)),
            GenerateResult::Failure { invalid_peers } => {
                Ok(RandomGenerateResult::Failure(invalid_peers))
            }
        }
    }

    fn combine_id(&self, id: Vec<u8>) -> Vec<u8> {
        id.iter()
            .chain(self.config.random_generate_id_suffix.iter())
            .copied()
            .collect()
    }

    async fn publish_random(&self, id: Vec<u8>, random: Scalar) -> Result<()> {
        let payload = gossipsub::Payload::TssNonceShare {
            id: id.clone(),
            share: random,
        };

        self.transport
            .publish(&self.config.gossipusb_topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }

    async fn collect_random(&self, id: Vec<u8>) -> Result<CollectionResult> {
        let id = self.combine_id(id);
        self.collector
            .query_nonce_shares(id)
            .await
            .map_err(Error::from)
    }

    fn compute_challenge(&self, msg: &[u8], random: &Scalar) -> Result<Scalar> {
        const DOMAIN_SEPARATOR: &[u8] = b"SCHNORR_SIGNATURE";

        let global_random = Point::generator(&random.scheme()).mul(random)?;
        let random_bytes = global_random.to_vec()?;
        let global_pk_bytes = self
            .golobal_pk
            .as_ref()
            .expect("Global public key is not set")
            .to_vec()?;

        let input = [DOMAIN_SEPARATOR, msg, &random_bytes, &global_pk_bytes].concat();

        let hash = Sha256::new().chain(&input).finalize();
        Ok(Scalar::from_bytes(hash.as_slice(), &random.scheme()))
    }

    fn calaulate_signature(&self, challenge: &Scalar, own_random_share: &Scalar) -> Result<Scalar> {
        let secret = self.secret.as_ref().expect("Secret key is not set");
        own_random_share
            .add(&challenge.mul(secret)?)
            .map_err(Error::from)
    }

    async fn publish_signature(&self, id: Vec<u8>, signature: Scalar) -> Result<()> {
        let payload = gossipsub::Payload::TssSignatureShare {
            id,
            share: signature,
        };

        self.transport
            .publish(&self.config.gossipusb_topic, payload)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashMap;
//
//     use crate::crypto::{
//         dkg::{Dkg_, MockDkg_},
//         primitives::algebra::{Point, Scalar, Scheme},
//         tss::schnorr::Schnorr,
//     };
//
//     const SCHEME: Scheme = Scheme::Secp256k1;
//     const NUM_PARTIAL_PKS: usize = 3;
//
//     fn generate_partial_pks(num: usize) -> HashMap<libp2p::PeerId, Point> {
//         let mut partial_pks = HashMap::new();
//         for _ in 0..num {
//             let peer_id = libp2p::PeerId::random();
//             let point = Point::random(&SCHEME);
//             partial_pks.insert(peer_id, point);
//         }
//         partial_pks
//     }
//
//     #[test]
//     fn global_pk_generate_from_correct_partial_pks() {
//         let dkg = MockDkg_::new();
//         let secret = Scalar::random(&SCHEME);
//         let partial_pks = generate_partial_pks(NUM_PARTIAL_PKS);
//         let expected_global_pk = Point::sum(partial_pks.values()).unwrap();
//
//         let schnorr = Schnorr::new(dkg, secret.clone(), partial_pks.clone()).unwrap();
//
//         assert_eq!(schnorr.golobal_pk, expected_global_pk);
//     }
// }
