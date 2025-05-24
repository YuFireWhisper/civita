use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;

use crate::{
    consensus::vrf_elector::{self, VrfElector},
    crypto::keypair::{PublicKey, VrfProof},
    network::transport::{
        self,
        store::merkle_dag::{self, KeyArray, Node},
    },
    resident::Record,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    VrfElector(#[from] vrf_elector::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),
}

struct MemberInfo {
    public_key: PublicKey,
    proof: VrfProof,
}

pub struct MemberManager {
    members: HashMap<PeerId, MemberInfo>,
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    input: Vec<u8>,
    total_stakes: u32,
    root: Node,
}

impl MemberManager {
    pub fn new(
        transport: Arc<Transport>,
        elector: Arc<VrfElector>,
        input: Vec<u8>,
        total_stakes: u32,
        root: Node,
    ) -> Self {
        Self {
            members: HashMap::new(),
            transport,
            elector,
            input,
            total_stakes,
            root,
        }
    }

    pub async fn add_member(
        &mut self,
        peer_id: PeerId,
        public_key: PublicKey,
        proof: VrfProof,
    ) -> Result<Option<u32>> {
        if !public_key.verify_proof(&self.input, &proof) {
            return Ok(None);
        }

        if self.members.contains_key(&peer_id) {
            return Ok(None);
        }

        let stakes = match self.get_stakes(&peer_id, &self.root).await? {
            Some(stakes) => stakes,
            None => return Ok(None),
        };

        let times = self
            .elector
            .calc_elected_times(stakes, self.total_stakes, &proof.output());

        if times == 0 {
            return Ok(None);
        }

        let info = MemberInfo { public_key, proof };

        self.members.insert(peer_id, info);
        Ok(Some(times))
    }

    async fn get_stakes(&self, peer: &PeerId, root: &Node) -> Result<Option<u32>> {
        let peer_key = Self::peer_to_key_array(peer);
        let hash = root.get(peer_key, &self.transport).await?;

        match hash {
            Some(hash) => {
                let record = self.transport.get::<Record>(&hash).await?;
                Ok(record.map(|r| r.stakes))
            }
            None => Ok(None),
        }
    }

    fn peer_to_key_array(peer: &PeerId) -> KeyArray {
        let bytes = peer.to_bytes();
        let mut result = KeyArray::default();

        for (i, chunk) in result.iter_mut().enumerate() {
            if i * 2 + 1 < bytes.len() {
                let high = bytes[i * 2] as u16;
                let low = bytes[i * 2 + 1] as u16;
                *chunk = (high << 8) | low;
            }
        }

        result
    }

    pub fn get_member_proofs(&self) -> HashMap<PeerId, (PublicKey, VrfProof)> {
        self.members
            .iter()
            .map(|(peer_id, info)| {
                let public_key = info.public_key.clone();
                let proof = info.proof.clone();
                (*peer_id, (public_key, proof))
            })
            .collect()
    }
}
