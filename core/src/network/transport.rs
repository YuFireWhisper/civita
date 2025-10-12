use std::collections::HashSet;

use derivative::Derivative;
use futures::StreamExt;
use libp2p::{
    gossipsub::{IdentTopic, MessageAcceptance, MessageId},
    identity::Keypair,
    noise,
    request_response::ResponseChannel,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, time::Duration};

use crate::{
    consensus::tree::Proofs,
    crypto::Multihash,
    event::Event,
    network::{behaviour::Behaviour, transport::inner::Inner},
    traits,
    ty::{atom::Height, Atom},
};

mod inner;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Config {
    #[derivative(Default(value = "100"))]
    pub channel_capacity: usize,

    #[derivative(Default(value = "Duration::from_secs(10)"))]
    pub listen_timeout: Duration,

    #[derivative(Default(value = "Duration::from_secs(10)"))]
    pub dial_timeout: Duration,
}

enum Command<T: traits::Config> {
    Disconnect(PeerId),
    Publish(Vec<u8>),
    Report(MessageId, PeerId, MessageAcceptance),
    SendRequest(Request, PeerId),
    SendResponse(Response<T>, ResponseChannel<Response<T>>),
    Stop,
}

#[derive(Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub enum Request {
    AtomByHash(Multihash),
    AtomByHeight(Height),
    Headers(Height, Height), // (start, count)
    CurrentHeight,
    Proofs,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "T: traits::Config")]
pub enum Response<T: traits::Config> {
    Atom(Box<Atom<T>>),
    Headers(Vec<Multihash>),
    CurrentHeight(Height),
    Proofs(Height, Proofs<T>),
}

pub struct Transport<T: traits::Config> {
    pub peer_id: PeerId,
    pub addr: Multiaddr,
    tx: mpsc::Sender<Command<T>>,
}

impl Request {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)
    }
}

impl<T: traits::Config> Response<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)
    }
}

impl<T: traits::Config> Transport<T> {
    pub async fn new(
        keypair: Keypair,
        listen_addr: Multiaddr,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
        tx: mpsc::Sender<Event<T>>,
        config: Config,
    ) -> Self {
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("Failed to create transport")
            .with_behaviour(|key| Behaviour::new(key.clone()))
            .expect("Failed to create swarm")
            .build();

        let addr = Self::listen_on(&mut swarm, listen_addr, config.listen_timeout).await;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(0u8.to_string()))
            .unwrap();
        Self::dial_peers(&mut swarm, bootstrap_peers, config.dial_timeout).await;

        let peer_id = *swarm.local_peer_id();
        let (cmd_tx, cmd_rx) = mpsc::channel(config.channel_capacity);

        Inner::spawn(swarm, cmd_rx, tx);

        Self {
            peer_id,
            addr,
            tx: cmd_tx,
        }
    }

    async fn listen_on(
        swarm: &mut Swarm<Behaviour<T>>,
        addr: Multiaddr,
        timeout: Duration,
    ) -> Multiaddr {
        swarm.listen_on(addr).expect("Failed to listen on address");

        tokio::time::timeout(timeout, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => return address,
                    SwarmEvent::ListenerError { error, .. } => panic!("Listener error: {error}"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("Timeout waiting for listen address")
    }

    async fn dial_peers(
        swarm: &mut Swarm<Behaviour<T>>,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
        timeout: Duration,
    ) -> bool {
        if bootstrap_peers.is_empty() {
            return true;
        }

        let mut peers = HashSet::new();

        for (peer, addr) in bootstrap_peers {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            swarm.dial(addr).expect("Failed to dial bootstrap peer");
            peers.insert(peer);
        }

        let mut counter = 0;
        let _ = tokio::time::timeout(timeout, async {
            while !peers.is_empty() {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        if peers.remove(&peer_id) {
                            counter += 1;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        if let Some(peer) = peer_id {
                            if peers.remove(&peer) {
                                log::error!("Failed to connect to bootstrap peer {peer}: {error}");
                            }
                        }
                    }
                    _ => continue,
                }
            }
        })
        .await;

        counter > 0
    }

    pub async fn disconnect(&self, peer_id: PeerId) {
        let _ = self.tx.send(Command::Disconnect(peer_id)).await;
    }

    pub async fn publish(&self, atom: Atom<T>) {
        let _ = self.tx.send(Command::Publish(atom.to_bytes())).await;
    }

    pub async fn report(&self, msg_id: MessageId, peer_id: PeerId, acceptance: MessageAcceptance) {
        let _ = self
            .tx
            .send(Command::Report(msg_id, peer_id, acceptance))
            .await;
    }

    pub async fn send_request(&self, req: Request, peer: PeerId) {
        let _ = self.tx.send(Command::SendRequest(req, peer)).await;
    }

    pub async fn send_response(&self, resp: Response<T>, channel: ResponseChannel<Response<T>>) {
        let _ = self.tx.send(Command::SendResponse(resp, channel)).await;
    }

    pub async fn stop(&self) {
        let _ = self.tx.send(Command::Stop).await;
    }
}
