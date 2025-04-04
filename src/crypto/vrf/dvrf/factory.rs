use std::sync::Arc;

use libp2p::PeerId;

use crate::{
    crypto::vrf::{Error, VrfFactory},
    network::transport::Transport,
};

use super::{
    config::Config,
    consensus_process::{process::ProcessFactory, ConsensusProcessFactory},
    crypto::{Crypto, EcvrfCrypto},
    Components, DVrf,
};

pub struct Factory<T: Transport + 'static> {
    transport: Arc<T>,
    config: Option<Config>,
    process_factory: Option<Arc<dyn ConsensusProcessFactory>>,
    crypto: Option<Arc<dyn Crypto>>,
    peer_id: PeerId,
}

impl<T: Transport + 'static> Factory<T> {
    const DEFAULT_FACTORY: ProcessFactory = ProcessFactory;

    pub fn new(transport: Arc<T>, peer_id: PeerId) -> Self {
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

    pub async fn create_service(&mut self) -> Result<Arc<DVrf<T>>, Error> {
        let transport = Arc::clone(&self.transport);
        let config = self.get_config();
        let peer_id = self.peer_id;
        let process_factory = self.get_process_factory();
        let crypto = self.get_crypto()?;
        let components = Components {
            transport,
            peer_id,
            config,
            process_factory,
            crypto,
        };
        DVrf::new_with_components(components).await
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

    fn get_crypto(&mut self) -> Result<Arc<dyn Crypto>, Error> {
        if self.crypto.is_none() {
            self.crypto = Some(Arc::new(self.get_default_crypto()?));
        }
        Ok(self.crypto.clone().unwrap()) // Safe to unwrap, and clone is cheap
    }

    fn get_default_crypto(&mut self) -> Result<EcvrfCrypto, Error> {
        Ok(EcvrfCrypto::new()?)
    }
}

impl<T: Transport + 'static> VrfFactory for Factory<T> {
    type E = Error;
    type V = DVrf<T>;

    async fn create(&mut self) -> Result<Arc<Self::V>, Self::E> {
        let service = self.create_service().await?;
        Ok(service)
    }
}
