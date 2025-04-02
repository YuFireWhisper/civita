use std::{marker::PhantomData, sync::Arc};

use thiserror::Error;

use crate::{
    crypto::{
        dkg::{Dkg, DkgFactory},
        vrf::{Vrf, VrfFactory},
    },
    network::transport::Transport,
};

pub mod timer;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("Failed to create VRF: {0}")]
    Vrf(String),
    #[error("Failed to create DKG: {0}")]
    Dkg(String),
}

pub struct Committee<T: Transport + 'static, V: Vrf, D: Dkg> {
    pub vrf: Arc<V>,
    pub dkg: Arc<D>,
    _marker: PhantomData<T>,
}

impl<T: Transport + 'static, V: Vrf, D: Dkg> Committee<T, V, D> {
    pub async fn new(
        mut vrf_factory: impl VrfFactory<V = V>,
        dkg_factory: impl DkgFactory<Dkg = D>,
    ) -> Result<Self> {
        let vrf = vrf_factory
            .create()
            .await
            .map_err(|e| Error::Vrf(e.to_string()))?;
        let dkg = Arc::new(
            dkg_factory
                .create()
                .await
                .map_err(|e| Error::Dkg(e.to_string()))?,
        );
        let _marker = PhantomData;

        Ok(Self { vrf, dkg, _marker })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        committee::Committee,
        crypto::{
            dkg::{MockDkg, MockDkgFactory},
            vrf::{MockVrf, MockVrfFactory},
        },
        network::transport::MockTransport,
    };

    #[tokio::test]
    async fn create() {
        let mut vrf_factory = MockVrfFactory::new();
        vrf_factory.expect_create().returning(|| {
            let mock_vrf = MockVrf::new();
            Box::pin(async move { Ok(Arc::new(mock_vrf)) })
        });

        let mut dkg_factory = MockDkgFactory::new();
        dkg_factory.expect_create().returning(|| Ok(MockDkg::new()));

        let result = Committee::<MockTransport, _, _>::new(vrf_factory, dkg_factory).await;

        assert!(result.is_ok());
    }
}
