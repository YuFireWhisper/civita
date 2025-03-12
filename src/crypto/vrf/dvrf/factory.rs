use std::sync::Arc;

use libp2p::PeerId;

use crate::{crypto::vrf::Error, network::transport::Transport};

use super::{
    config::Config,
    consensus_process::{process::ProcessFactory, ConsensusProcessFactory},
    crypto::Crypto,
    DVrf,
};

pub struct DVrfFactory {
    transport: Arc<Transport>,
    config: Option<Config>,
    process_factory: Option<Arc<dyn ConsensusProcessFactory>>,
    crypto: Option<Arc<dyn Crypto>>,
    peer_id: PeerId,
}

impl DVrfFactory {
    const DEFAULT_FACTORY: ProcessFactory = ProcessFactory;

    pub fn new(transport: Arc<Transport>, peer_id: PeerId) -> Self {
        Self {
            transport,
            config: None,
            process_factory: None,
            crypto: None,
            peer_id,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_process_factory(
        mut self,
        process_factory: Arc<dyn ConsensusProcessFactory>,
    ) -> Self {
        self.process_factory = Some(process_factory);
        self
    }

    pub fn with_crypto(mut self, crypto: Arc<dyn Crypto>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    pub async fn create_service(&mut self) -> Result<Arc<DVrf>, Error> {
        let transport = Arc::clone(&self.transport);
        let config = self.get_config();
        let process_factory = self.get_process_factory();
        DVrf::new(transport, config, self.peer_id, process_factory).await
    }

    fn get_config(&mut self) -> Config {
        if self.config.is_none() {
            self.config = Some(Config::default());
        }
        self.config.clone().unwrap() // Safe to unwrap, and clone is cheap
    }

    fn get_process_factory(&mut self) -> Arc<dyn ConsensusProcessFactory> {
        if self.process_factory.is_none() {
            self.process_factory = Some(Arc::new(Self::DEFAULT_FACTORY));
        }
        self.process_factory.clone().unwrap()
    }
}
