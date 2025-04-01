use std::{collections::HashSet, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use curv::elliptic::curves::Curve;
use libp2p::PeerId;

use crate::{
    crypto::dkg::{
        classic::{config::Config, Classic, Error},
        DkgFactory,
    },
    network::transport::Transport,
};

pub struct Factory<T: Transport + 'static, E: Curve> {
    transport: Arc<T>,
    self_peer: PeerId,
    other_peers: HashSet<PeerId>,
    config: Option<Config>,
    _marker: PhantomData<E>,
}

impl<T: Transport + 'static, E: Curve> Factory<T, E> {
    pub fn new(transport: Arc<T>, self_peer: PeerId) -> Self {
        let other_peers = HashSet::new();
        let config = None;
        let _marker = PhantomData;

        Self {
            transport,
            self_peer,
            other_peers,
            config,
            _marker,
        }
    }

    pub fn with_other_peers(mut self, other_peers: HashSet<PeerId>) -> Self {
        self.other_peers = other_peers;
        self
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }
}

#[async_trait]
impl<T: Transport + 'static, E: Curve> DkgFactory for Factory<T, E> {
    type Error = Error;
    type Dkg = Classic<E>;

    async fn create(&self) -> Result<Self::Dkg, Self::Error> {
        let transport = Arc::clone(&self.transport);
        let self_peer = self.self_peer;
        let other_peers = self.other_peers.clone();
        let config = self.config.clone().unwrap_or_default();

        Classic::new(transport, self_peer, other_peers, config).await
    }
}
