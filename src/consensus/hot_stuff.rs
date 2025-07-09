use std::sync::Arc;

use tokio::sync::mpsc;

use crate::{
    consensus::hot_stuff::{chain::Chain, engine::Engine},
    crypto::{Hasher, Multihash},
    network::{gossipsub, Gossipsub, Transport},
    proposal::MultiProposal,
    resident,
    traits::Serializable,
    utils::mpt,
};

mod chain;
mod engine;
mod proposal_pool;
mod utils;

pub use chain::ChainState;
pub use engine::Config;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),
}

pub struct HotStuff {
    gossipsub: Arc<Gossipsub>,
    resp_prop_result_tx: mpsc::Sender<(Multihash, bool)>,
    prop_topic: u8,
}

impl HotStuff {
    pub async fn new<H: Hasher>(
        transport: Arc<Transport>,
        chain_state: ChainState,
        mpt_root: mpt::Node,
        record: Option<resident::Record>,
        config: Config,
    ) -> (Self, mpsc::Receiver<MultiProposal>) {
        let gossipsub = transport.gossipsub();
        let chain = Chain::from_state(chain_state);
        let prop_topic = config.prop_topic;

        let (resp_tx, req_rx) = Engine::<H>::spawn(transport, chain, mpt_root, record, config)
            .await
            .expect("Failed to spawn engine");

        let hot_stuff = Self {
            gossipsub,
            resp_prop_result_tx: resp_tx,
            prop_topic,
        };

        (hot_stuff, req_rx)
    }

    pub async fn report_proposal_result(
        &self,
        proposal_id: Multihash,
        result: bool,
    ) -> Result<(), mpsc::error::SendError<(Multihash, bool)>> {
        self.resp_prop_result_tx.send((proposal_id, result)).await
    }

    pub async fn proposal(&self, prop: MultiProposal) -> Result<()> {
        let bytes = prop.to_vec().expect("Failed to serialize proposal");
        self.gossipsub.publish(self.prop_topic, bytes).await?;
        Ok(())
    }
}
