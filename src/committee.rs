use std::{collections::HashMap, sync::Arc};

use tokio::sync::{mpsc::Receiver as TokioReceiver, RwLock as TokioRwLock};

use crate::{
    behaviour::Behaviour,
    committee::elector::{ElectionResult, Elector},
    crypto::{dkg::Dkg, keypair::SecretKey, tss::Tss},
    network::transport::{self, protocols::kad},
    traits::{byteable, Byteable},
    utils::Timer,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

pub mod config;
pub mod info;

mod elector;
mod vrf_elector;

pub use config::Config;
pub use info::Info;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Byteable(#[from] byteable::Error),

    #[error("{0}")]
    Payload(#[from] kad::payload::Error),

    #[error("{0}")]
    Elector(#[from] elector::Error),

    #[error("{0}")]
    Tss(String),
}

#[derive(Debug)]
enum Action {
    CollectionStart(Vec<u8>, u64),
}

pub struct Committee<D, T>
where
    D: Dkg + 'static,
    T: Tss + 'static,
{
    infos: TokioRwLock<HashMap<u64, Info>>,
    elector: TokioRwLock<Elector<D>>,
    tss: Arc<TokioRwLock<T>>,
}

impl<D, T> Committee<D, T>
where
    D: Dkg + 'static,
    T: Tss + 'static,
{
    pub async fn new<B: Behaviour>(
        transport: Arc<Transport>,
        dkg: Arc<D>,
        tss: Arc<TokioRwLock<T>>,
        secret_key: SecretKey,
        config: Config,
    ) -> Result<Arc<Self>> {
        let committee_info = Self::get_committee_info(transport.clone()).await?;

        let (timer, timer_rx) = Timer::new().await;
        let input = committee_info.public_key.to_vec()?;
        Self::set_timer(&timer, input, committee_info.epoch, config.committee_term).await;

        let elector = Elector::new(
            transport.clone(),
            dkg.clone(),
            secret_key.clone(),
            config.into(),
        );

        let committee = Arc::new(Self {
            infos: TokioRwLock::new(HashMap::new()),
            elector: TokioRwLock::new(elector),
            tss,
        });

        committee.clone().start::<B>(timer_rx).await?;

        Ok(committee)
    }

    async fn get_committee_info(transport: Arc<Transport>) -> Result<Info> {
        let hash = transport
            .get_or_error(kad::Key::LatestCommittee)
            .await?
            .extract(kad::payload::Variant::CommitteeKey)?;

        let info = transport
            .get_or_error(kad::Key::ByHash(hash))
            .await?
            .extract(kad::payload::Variant::Committee)?;

        Ok(info)
    }

    async fn set_timer(
        timer: &Timer<Action>,
        input: Vec<u8>,
        epoch: u64,
        remaining_time: tokio::time::Duration,
    ) {
        timer
            .schedule(Action::CollectionStart(input, epoch), remaining_time)
            .await;
    }

    async fn start<B: Behaviour>(self: Arc<Self>, timer_rx: TokioReceiver<Action>) -> Result<()> {
        tokio::spawn(async move {
            self.event_loop::<B>(timer_rx).await;
        });

        Ok(())
    }

    async fn event_loop<B: Behaviour>(&self, mut timer_rx: TokioReceiver<Action>) {
        loop {
            tokio::select! {
                Some(action) = timer_rx.recv() => {
                    match action {
                        Action::CollectionStart(input, epoch) => {
                            self.handle_collection_start::<B>(input, epoch).await.unwrap_or_else(|e| {
                                log::error!("Failed to handle collection start: {:?}", e);
                            });
                        }
                    }
                }

                else => {
                    log::warn!("No more messages or actions to process");
                    break;
                }
            }
        }
    }

    async fn handle_collection_start<B: Behaviour>(
        &self,
        input: Vec<u8>,
        epoch: u64,
    ) -> Result<()> {
        let result = self.elector.write().await.start::<B>(input, epoch).await?;

        match result {
            ElectionResult::OwnIsMember {
                info,
                secret,
                global_commitments,
                ..
            } => {
                self.tss
                    .write()
                    .await
                    .set_keypair(
                        secret,
                        info.public_key.clone(),
                        global_commitments,
                        info.members.clone(),
                    )
                    .await
                    .map_err(|e| Error::Tss(e.to_string()))?;

                self.infos.write().await.insert(epoch, info);
            }
            ElectionResult::OwnIsNotMember { info } => {
                self.infos.write().await.insert(epoch, info);
            }
        }

        Ok(())
    }
}
