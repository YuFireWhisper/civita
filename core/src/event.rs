use std::collections::HashMap;

use libp2p::{gossipsub::MessageId, request_response::ResponseChannel, PeerId};
use tokio::sync::oneshot;

use crate::{
    consensus::tree::Status,
    crypto::Multihash,
    network::transport::{Request, Response},
    ty::{Atom, ScriptPk, ScriptSig, Token, Value},
};

pub struct Proposal {
    pub code: u8,
    pub inputs: Vec<(Multihash, ScriptSig)>,
    pub outputs: Vec<(Value, ScriptPk)>,
}

pub enum Event {
    Gossipsub(MessageId, PeerId, Box<Atom>),
    Request(Request, PeerId, ResponseChannel<Response>),
    Response(Response, PeerId),
    Propose(Proposal),
    Tokens(oneshot::Sender<HashMap<Multihash, Token>>),
    Status(oneshot::Sender<Status>),
    Stop(oneshot::Sender<()>),
    AtomReady(Box<Atom>),
}

impl Proposal {
    pub fn new(
        code: u8,
        inputs: Vec<(Multihash, ScriptSig)>,
        outputs: Vec<(Value, ScriptPk)>,
    ) -> Self {
        Self {
            code,
            inputs,
            outputs,
        }
    }
}
