use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
};

use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    crypto::{Hasher, Multihash},
    proposal::MultiProposal,
    traits::{serializable, Serializable},
};

type Result<T> = std::result::Result<T, Error>;
type ValidationPair = (
    mpsc::Sender<(Multihash, bool)>,
    mpsc::Receiver<MultiProposal>,
);

const CHANNEL_CAPACITY: usize = 100;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Send(String),

    #[error(transparent)]
    Serializable(#[from] serializable::Error),

    #[error("Invalid proof")]
    InvalidProof,
}

enum InboundAction {
    Get,
    Remove(HashSet<Multihash>),
    ChangeRoot(Multihash),
}

struct ProposalPoolInner<H> {
    inbound_rx: mpsc::Receiver<InboundAction>,
    result_tx: mpsc::Sender<BTreeMap<Multihash, MultiProposal>>,
    req_validation_tx: mpsc::Sender<MultiProposal>,
    resp_validation_rx: mpsc::Receiver<(Multihash, bool)>,
    prop_rx: mpsc::Receiver<Vec<u8>>,
    root_hash: Multihash,
    capacity: usize,
    pending_props: BTreeMap<Multihash, MultiProposal>,
    validated_props: BTreeMap<Multihash, MultiProposal>,
    _marker: PhantomData<H>,
}

pub struct ProposalPool<H> {
    handle: JoinHandle<()>,
    inbound_tx: mpsc::Sender<InboundAction>,
    result_rx: mpsc::Receiver<BTreeMap<Multihash, MultiProposal>>,
    _marker: PhantomData<H>,
}

impl<H: Hasher> ProposalPoolInner<H> {
    pub fn spawn(
        inbound_rx: mpsc::Receiver<InboundAction>,
        result_tx: mpsc::Sender<BTreeMap<Multihash, MultiProposal>>,
        req_validation_tx: mpsc::Sender<MultiProposal>,
        resp_validation_rx: mpsc::Receiver<(Multihash, bool)>,
        prop_rx: mpsc::Receiver<Vec<u8>>,
        root_hash: Multihash,
        capacity: usize,
    ) -> JoinHandle<()> {
        let mut inner = Self {
            inbound_rx,
            result_tx,
            req_validation_tx,
            resp_validation_rx,
            prop_rx,
            root_hash,
            capacity,
            pending_props: BTreeMap::new(),
            validated_props: BTreeMap::new(),
            _marker: PhantomData,
        };

        tokio::spawn(async move {
            inner.run().await;
        })
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(action) = self.inbound_rx.recv() => {
                    if let Err(e) = self.handle_inbound_action(action).await {
                        log::error!("{e}");
                    }
                },

                Some(prop) = self.prop_rx.recv() => {
                    if let Err(e) = self.handle_proposal(prop).await {
                        log::error!("Failed to handle proposal: {e}");
                    }
                },

                Some((id, valid)) = self.resp_validation_rx.recv() => {
                    if let Some(prop) = self.pending_props.remove(&id) {
                        if valid {
                            self.validated_props.insert(id, prop);
                        } else {
                            log::warn!("Proposal with ID {id:?} was invalidated");
                        }
                    } else {
                        log::warn!("Proposal with ID {id:?} not found in pending props");
                    }
                },

                else => {
                    log::info!("Proposal pool task completed");
                    break;
                },
            }
        }
    }

    async fn handle_inbound_action(&mut self, action: InboundAction) -> Result<()> {
        match action {
            InboundAction::Get => {
                let result = std::mem::take(&mut self.validated_props);
                self.result_tx.send(result).await?;
            }
            InboundAction::Remove(to_remove) => {
                self.pending_props.retain(|k, _| !to_remove.contains(k));
                self.validated_props.retain(|k, _| !to_remove.contains(k));
            }
            InboundAction::ChangeRoot(new_hash) => {
                self.root_hash = new_hash;
                self.pending_props.clear();
                self.validated_props.clear();
            }
        }

        Ok(())
    }

    async fn handle_proposal(&mut self, prop: Vec<u8>) -> Result<()> {
        let prop = MultiProposal::from_slice(&prop)?;

        if !prop.base_verify::<H>(&self.root_hash) {
            return Err(Error::InvalidProof);
        }

        if self.pending_props.len() >= self.capacity {
            self.pending_props.pop_last();
        }

        let id = prop.generate_id::<H>();
        self.pending_props.insert(id, prop.clone());
        self.req_validation_tx.send(prop).await?;
        Ok(())
    }
}

impl<H: Hasher> ProposalPool<H> {
    pub fn new(
        prop_rx: mpsc::Receiver<Vec<u8>>,
        root_hash: Multihash,
        capacity: usize,
    ) -> (Self, ValidationPair) {
        let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (req_validation_tx, req_validation_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (resp_validation_tx, resp_validation_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let handle = ProposalPoolInner::<H>::spawn(
            inbound_rx,
            result_tx,
            req_validation_tx,
            resp_validation_rx,
            prop_rx,
            root_hash,
            capacity,
        );

        (
            Self {
                handle,
                inbound_tx,
                result_rx,
                _marker: PhantomData,
            },
            (resp_validation_tx, req_validation_rx),
        )
    }

    pub async fn get(&mut self) -> Result<BTreeMap<Multihash, MultiProposal>> {
        while self.result_rx.try_recv().is_ok() {}
        self.inbound_tx.send(InboundAction::Get).await?;
        match self.result_rx.recv().await {
            Some(result) => Ok(result),
            _ => Err(Error::Send("Failed to get proposals".to_string())),
        }
    }

    pub async fn remove(&self, ids: HashSet<Multihash>) -> Result<()> {
        self.inbound_tx.send(InboundAction::Remove(ids)).await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn change_root(&self, new_hash: Multihash) -> Result<()> {
        self.inbound_tx
            .send(InboundAction::ChangeRoot(new_hash))
            .await?;
        Ok(())
    }
}

impl From<mpsc::error::SendError<InboundAction>> for Error {
    fn from(e: mpsc::error::SendError<InboundAction>) -> Self {
        Error::Send(e.to_string())
    }
}

impl From<mpsc::error::SendError<BTreeMap<Multihash, MultiProposal>>> for Error {
    fn from(e: mpsc::error::SendError<BTreeMap<Multihash, MultiProposal>>) -> Self {
        Error::Send(e.to_string())
    }
}

impl From<mpsc::error::SendError<MultiProposal>> for Error {
    fn from(e: mpsc::error::SendError<MultiProposal>) -> Self {
        Error::Send(e.to_string())
    }
}

impl<H> Drop for ProposalPool<H> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
