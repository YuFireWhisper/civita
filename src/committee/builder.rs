use std::sync::Arc;

use thiserror::Error;

use crate::{
    committee::{self, Committee, Config},
    crypto::dkg::{Dkg, DkgFactory},
    network::transport::Transport,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("Missing transport")]
    TransportMissing,
    #[error("Missing DKG factory")]
    DkgFactoryMissing,
    #[error("Failed to create VRF: {0}")]
    Vrf(String),
    #[error("Failed to create DKG: {0}")]
    Dkg(String),
    #[error("Failed to create committee: {0}")]
    CommitteeCreation(#[from] committee::Error),
}

#[derive(Debug)]
pub(super) struct Component<T, D>
where
    T: Transport + Send + Sync + 'static,
    D: Dkg + Send + Sync + 'static,
{
    pub transport: Arc<T>,
    pub dkg: D,
    pub config: Config,
}

#[derive(Debug)]
pub struct Builder<T, DF>
where
    T: Transport + Send + Sync + 'static,
    DF: DkgFactory + Send + Sync + 'static,
{
    transport: Option<Arc<T>>,
    dkg_factory: Option<DF>,
    config: Option<Config>,
}

impl<T, DF> Builder<T, DF>
where
    T: Transport + Send + Sync + 'static,
    DF: DkgFactory + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_transport(mut self, transport: Arc<T>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn with_dkg_factory(mut self, dkg_factory: DF) -> Self {
        self.dkg_factory = Some(dkg_factory);
        self
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn build(self) -> Result<Arc<Committee<T, DF::Dkg>>> {
        let transport = self.transport()?;
        let dkg = self.dkg().await?;
        let config = self.config();

        let component = Component {
            transport,
            dkg,
            config,
        };

        Committee::from_component(component)
            .await
            .map_err(Error::from)
    }

    fn transport(&self) -> Result<Arc<T>> {
        self.transport
            .as_ref()
            .ok_or(Error::TransportMissing)
            .cloned()
    }

    async fn dkg(&self) -> Result<DF::Dkg> {
        self.dkg_factory
            .as_ref()
            .ok_or(Error::DkgFactoryMissing)?
            .create()
            .await
            .map_err(|e| Error::Dkg(e.to_string()))
    }

    fn config(&self) -> Config {
        self.config.clone().unwrap_or_default()
    }
}

impl<T, DF> Default for Builder<T, DF>
where
    T: Transport + Send + Sync + 'static,
    DF: DkgFactory + Send + Sync + 'static,
{
    fn default() -> Self {
        let transport = None;
        let dkg_factory = None;
        let config = None;

        Self {
            transport,
            dkg_factory,
            config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::dkg::{MockDkg, MockDkgFactory},
        network::transport::MockTransport,
    };

    #[tokio::test]
    async fn create() {
        let builder: Builder<MockTransport, MockDkgFactory> = Builder::new();

        assert!(builder.transport.is_none());
        assert!(builder.dkg_factory.is_none());
        assert!(builder.config.is_none());
    }

    #[tokio::test]
    async fn same_items() {
        let transport = Arc::new(MockTransport::new());
        let dkg_factory = MockDkgFactory::new();
        let config = Config::default();

        let builder = Builder::<MockTransport, MockDkgFactory>::new()
            .with_transport(transport.clone())
            .with_dkg_factory(dkg_factory)
            .with_config(config.clone());

        assert!(builder.transport.is_some());
        assert!(builder.dkg_factory.is_some());
        assert!(builder.config.is_some());
    }

    #[tokio::test]
    // Because we don't set up expectations for the mock
    #[should_panic(expected = "No matching expectation found")]
    async fn success_build() {
        let transport = MockTransport::new();
        let transport = Arc::new(transport);
        let mut dkg_factory = MockDkgFactory::new();
        dkg_factory.expect_create().returning(|| Ok(MockDkg::new()));
        let config = Config::default();

        let builder: Builder<MockTransport, MockDkgFactory> = Builder::new()
            .with_transport(transport.clone())
            .with_dkg_factory(dkg_factory)
            .with_config(config);

        let _ = builder.build().await;
    }

    #[tokio::test]
    async fn return_error_missing_transport() {
        let dkg_factory = MockDkgFactory::new();
        let config = Config::default();

        let builder: Builder<MockTransport, MockDkgFactory> = Builder::new()
            .with_dkg_factory(dkg_factory)
            .with_config(config);

        let result = builder.build().await;

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TransportMissing)));
    }

    #[tokio::test]
    async fn return_error_missing_dkg_factory() {
        let transport = Arc::new(MockTransport::new());
        let config = Config::default();

        let builder: Builder<MockTransport, MockDkgFactory> = Builder::new()
            .with_transport(transport.clone())
            .with_config(config);

        let result = builder.build().await;

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::DkgFactoryMissing)));
    }
}
