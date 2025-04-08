use std::collections::HashMap;

use crate::{
    crypto::{
        core::element::{Public, Secret},
        dkg::vss::Vss,
    },
    network::transport::libp2p_transport::protocols::{
        gossipsub,
        request_response::{self, payload::Request},
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Collection timed out")]
    Timeout,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Validation failed, peer_id: {0}")]
    ValidationFailed(libp2p::PeerId),
}

struct Pair<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    share: Option<SK>,
    commitments: Option<Vec<PK>>,
}

impl<SK, PK> Pair<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub fn set_share(&mut self, secret: SK) -> bool {
        self.share = Some(secret);
        self.is_complete()
    }

    pub fn set_commitments(&mut self, commitments: Vec<PK>) -> bool {
        self.commitments = Some(commitments);
        self.is_complete()
    }

    fn is_complete(&self) -> bool {
        self.commitments.is_some() && self.share.is_some()
    }

    pub fn into_components(self) -> Option<(SK, Vec<PK>)> {
        match (self.share, self.commitments) {
            (Some(share), Some(commitments)) => Some((share, commitments)),
            _ => None,
        }
    }
}

pub struct VerifiedPair<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub share: SK,
    pub commitments: Vec<PK>,
}

impl<SK, PK> VerifiedPair<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    pub fn new<VSS: Vss<SK, PK>>(index: &u16, share: SK, commitments: Vec<PK>) -> Option<Self> {
        match VSS::verify(index, &share, &commitments) {
            true => Some(Self { share, commitments }),
            false => None,
        }
    }

    pub fn into_components(self) -> (SK, Vec<PK>) {
        (self.share, self.commitments)
    }
}

pub struct Collector<SK, PK, VSS>
where
    SK: Secret,
    PK: Public,
    VSS: Vss<SK, PK>,
{
    timeout: tokio::time::Duration,
    own_id: libp2p::PeerId,
    _marker: std::marker::PhantomData<(SK, PK, VSS)>,
}

impl<SK, PK, VSS> Collector<SK, PK, VSS>
where
    SK: Secret,
    PK: Public,
    VSS: Vss<SK, PK>,
{
    pub fn new(timeout: tokio::time::Duration, own_id: libp2p::PeerId) -> Self {
        Self {
            timeout,
            own_id,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn collect(
        &self,
        topic_rx: tokio::sync::mpsc::Receiver<gossipsub::Message>,
        peer_rx: tokio::sync::mpsc::Receiver<request_response::Message>,
        ids: &HashMap<libp2p::PeerId, u16>,
    ) -> Result<Vec<VerifiedPair<SK, PK>>>
    where
        SK: Secret,
        PK: Public,
        VSS: Vss<SK, PK>,
    {
        tokio::time::timeout(self.timeout, self.collect_internal(topic_rx, peer_rx, ids))
            .await
            .map_err(|_| Error::Timeout)
            .and_then(|result| result)
    }

    async fn collect_internal(
        &self,
        mut topic_rx: tokio::sync::mpsc::Receiver<gossipsub::Message>,
        mut peer_rx: tokio::sync::mpsc::Receiver<request_response::Message>,
        ids: &HashMap<libp2p::PeerId, u16>,
    ) -> Result<Vec<VerifiedPair<SK, PK>>>
    where
        SK: Secret,
        PK: Public,
        VSS: Vss<SK, PK>,
    {
        let mut collecting: HashMap<u16, Pair<SK, PK>> = HashMap::new();
        let mut collected: Vec<VerifiedPair<SK, PK>> = Vec::new();
        let mut completed_peer: Vec<libp2p::PeerId> = Vec::new();

        let own_index = ids.get(&self.own_id).expect("Own ID not found in IDs");

        while completed_peer.len() < ids.len() {
            tokio::select! {
                Some(msg) = topic_rx.recv() => {
                    if let gossipsub::Payload::DkgVSS_(commitments) = msg.payload {
                        if completed_peer.contains(&msg.source) {
                            continue;
                        }

                        let index = match ids.get(&msg.source) {
                            Some(&i) => i,
                            None => continue,
                        };

                        let commitments = commitments
                            .iter()
                            .map(|commitment| PK::from_bytes(commitment))
                            .collect::<Vec<PK>>();

                        let pair = collecting.entry(index).or_default();
                        if pair.set_commitments(commitments) {
                            completed_peer.push(msg.source);
                            let pair = collecting.remove(&index).expect("Pair not found, this should never happen");
                            Self::update_collected(pair, &mut collected, own_index);
                        }
                    }
                }
                Some(msg) = peer_rx.recv() => {
                    if let request_response::Payload::Request(Request::DkgShare(share_bytes)) = msg.payload {
                        if completed_peer.contains(&msg.peer) {
                            continue;
                        }

                        let index = match ids.get(&msg.peer) {
                            Some(&i) => i,
                            None => continue,
                        };

                        let share = SK::from_bytes(&share_bytes);

                        let pair = collecting.entry(index).or_default();
                        if pair.set_share(share) {
                            completed_peer.push(msg.peer);
                            let pair = collecting.remove(&index).expect("Pair not found, this should never happen");
                            Self::update_collected(pair, &mut collected, own_index);
                        }
                    }
                }
                else => {
                    return Err(Error::ChannelClosed);
                }
            }
        }

        Ok(collected)
    }

    fn update_collected(
        pair: Pair<SK, PK>,
        validated_map: &mut Vec<VerifiedPair<SK, PK>>,
        own_index: &u16,
    ) where
        SK: Secret,
        PK: Public,
        VSS: Vss<SK, PK>,
    {
        if let Some((share, commitments)) = pair.into_components() {
            let validated_pair = VerifiedPair::new::<VSS>(own_index, share, commitments);
            if let Some(validated_pair) = validated_pair {
                validated_map.push(validated_pair);
            }
        }
    }
}

impl<SK: Secret, PK: Public> Default for Pair<SK, PK> {
    fn default() -> Self {
        Self {
            share: None,
            commitments: None,
        }
    }
}
