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

type OnChainInputs<T> = Vec<(Multihash, <T as traits::Config>::ScriptSig)>;

pub enum Event<T: traits::Config> {
    Gossipsub(MessageId, PeerId, Box<Atom<T>>),
    Request(Request, PeerId, ResponseChannel<Response<T>>),
    Response(Response<T>, PeerId),
    Propose(u8, OnChainInputs<T>, Vec<T::OffChainInput>, Vec<Token<T>>),
    Tokens(oneshot::Sender<HashMap<Multihash, Token<T>>>),
    Status(oneshot::Sender<Status>),
    Stop(oneshot::Sender<()>),
}
