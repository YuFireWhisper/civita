use std::collections::HashMap;

use libp2p::{gossipsub::MessageId, request_response::ResponseChannel, PeerId};
use tokio::sync::oneshot;

use crate::{
    consensus::tree::Status,
    crypto::Multihash,
    network::transport::{Request, Response},
    traits,
    ty::{Atom, Token},
};

pub struct Proposal<T: traits::Config> {
    pub code: u8,
    pub on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
    pub off_chain_inputs: Vec<T::OffChainInput>,
    pub outputs: Vec<Token<T>>,
}

pub enum Event<T: traits::Config> {
    Gossipsub(MessageId, PeerId, Box<Atom<T>>),
    Request(Request, PeerId, ResponseChannel<Response<T>>),
    Response(Response<T>, PeerId),
    Propose(Proposal<T>),
    Tokens(oneshot::Sender<HashMap<Multihash, Token<T>>>),
    Status(oneshot::Sender<Status>),
    Stop(oneshot::Sender<()>),
    AtomReady(Box<Atom<T>>),
}
