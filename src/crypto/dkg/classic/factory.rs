use std::{marker::PhantomData, sync::Arc};

use curv::elliptic::curves::Curve;

use crate::{
    crypto::dkg::{
        classic::{config::Config, Classic},
        DkgFactory,
    },
    network::transport::Transport,
};

pub struct Factory<T: Transport + 'static, E: Curve> {
    transport: Arc<T>,
    config: Option<Config>,
    _marker: PhantomData<E>,
}

impl<T: Transport + 'static, E: Curve> Factory<T, E> {
    pub fn new(transport: Arc<T>) -> Self {
        let config = None;
        let _marker = PhantomData;

        Self {
            transport,
            config,
            _marker,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }
}

impl<T: Transport + 'static, E: Curve> DkgFactory for Factory<T, E> {
    type T = T;
    type D = Classic<T, E>;

    fn create(&self) -> Self::D {
        let transport = Arc::clone(&self.transport);
        let config = self.config.clone().unwrap_or_default();

        Classic::new(transport, config)
    }
}
