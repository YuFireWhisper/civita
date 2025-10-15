use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identity::Keypair,
    kad::{self, store::MemoryStore},
    request_response::{self, cbor::codec::Codec, ProtocolSupport},
    swarm::NetworkBehaviour,
    StreamProtocol,
};

use crate::network::transport::{Request, Response};

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kad: kad::Behaviour<MemoryStore>,
    pub request_response: request_response::Behaviour<Codec<Request, Response>>,
}

impl Behaviour {
    pub fn new(key: Keypair) -> Self {
        let peer_id = key.public().to_peer_id();

        Self {
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key),
                Default::default(),
            )
            .expect("Correct configuration"),
            request_response: request_response::Behaviour::new(
                [(
                    StreamProtocol::new(concat!("/", env!("CARGO_PKG_NAME"))),
                    ProtocolSupport::Full,
                )],
                Default::default(),
            ),
            kad: kad::Behaviour::new(peer_id, MemoryStore::new(peer_id)),
        }
    }
}
