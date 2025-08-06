use std::{marker::PhantomData, sync::Arc};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use libp2p::PeerId;

use crate::{
    consensus::{
        block::{self, Block},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    network::{request_response, Transport},
    utils::Record,
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RequestResponse(#[from] request_response::Error),
}

pub trait Tree {
    fn get_block(&self, checkpoint: Multihash, block: Multihash)
        -> Option<(Block, block::Witness)>;
    fn get_blocks(
        &self,
        checkpoint: Multihash,
        block: Multihash,
        up_to: u64,
    ) -> Option<Vec<(Block, block::Witness)>>;
    fn get_proposals<T: Record>(
        &self,
        checkpoint: Multihash,
        block: Multihash,
        proposal_hashes: Vec<Multihash>,
    ) -> Option<Vec<(Proposal<T>, proposal::Witness)>>;
}

#[derive(Serialize)]
enum Request {
    Blocks {
        checkpoint: Multihash,
        block: Multihash,
        times: u64,
    },
    Proposals {
        checkpoint: Multihash,
        block: Multihash,
        proposal_hashes: Vec<Multihash>,
    },
    Snapshot,
    FullHistory,
}

#[derive(Serialize)]
enum Response<T: Record> {
    Blocks(Vec<(Block, block::Witness)>),
    Proposals(Vec<(Proposal<impl Record>, proposal::Witness)>),
}

#[derive(Serialize)]
enum Response<T: Record> {
    Block(Box<(Block, block::Witness)>),
    Blocks(Vec<(Block, block::Witness)>),
    Proposals(Vec<(Proposal<T>, proposal::Witness)>),
}

pub struct Synchronizer<R: Record, T: Tree> {
    transport: Arc<Transport>,
    tree: T,
    request_topic: u8,
    response_topic: u8,
    _marker: PhantomData<R>,
}

impl<R: Record, T: Tree> Synchronizer<R, T> {
    pub fn new(transport: Arc<Transport>, tree: T, request_topic: u8, response_topic: u8) -> Self {
        Synchronizer {
            transport,
            tree,
            request_topic,
            response_topic,
            _marker: PhantomData,
        }
    }

    pub async fn reqeust_block(
        &self,
        peer: PeerId,
        checkpoint: Multihash,
        block: Multihash,
    ) -> Result<Option<(Block, block::Witness)>> {
        debug_assert!(self.tree.get_block(checkpoint, block).is_none());

        let request = Request::Block(checkpoint, block).to_vec();
        self.transport
            .request_response()
            .send_request(peer, request, self.request_topic)
            .await;

        todo!("Request block from network or local storage");
    }

    pub async fn request_blocks(
        &self,
        checkpoint: Multihash,
        block: Multihash,
        up_to: u64,
    ) -> Option<Vec<(Block, block::Witness)>> {
        todo!("Request blocks from network or local storage");
    }

    pub async fn request_proposals(
        &self,
        checkpoint: Multihash,
        block: Multihash,
        proposal_hashes: Vec<Multihash>,
    ) -> Option<Vec<(Proposal<R>, proposal::Witness)>> {
        todo!("Request proposals from network or local storage");
    }
}
