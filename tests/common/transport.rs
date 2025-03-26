use std::sync::Arc;

use civita::network::transport::Transport;
use libp2p::Multiaddr;
use libp2p::{identity::Keypair, PeerId};

use civita::network::transport::libp2p_transport::{config::Config, Libp2pTransport};

const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";

pub struct TransportInfo {
    pub transport: Arc<Libp2pTransport>,
    pub peer_id: PeerId,
    pub addr: Multiaddr,
}

impl TransportInfo {
    fn new(transport: Arc<Libp2pTransport>, peer_id: PeerId, addr: Multiaddr) -> Self {
        Self {
            transport,
            peer_id,
            addr,
        }
    }
}

pub async fn generate_connected_transports(n: u16) -> Vec<TransportInfo> {
    let mut infos: Vec<TransportInfo> = Vec::new();

    for _ in 0..n {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(&keypair.public());
        let transport = Libp2pTransport::new(
            keypair.clone(),
            LISTEN_ADDR.parse().unwrap(),
            Config::default(),
        )
        .await
        .expect("failed to create transport");
        let addr = listen_addr(&transport)
            .await
            .into_iter()
            .next()
            .expect("no listen addr");

        infos.push(TransportInfo::new(Arc::new(transport), peer_id, addr));
    }

    dial_peers(&infos).await;

    infos
}

async fn listen_addr(transport: &Libp2pTransport) -> Vec<Multiaddr> {
    let swarm = transport.swarm().await.expect("swarm not initialized");
    swarm.listeners().cloned().collect()
}

async fn dial_peers(infos: &Vec<TransportInfo>) {
    for info in infos {
        for other in infos.iter().filter(|o| o.peer_id != info.peer_id) {
            info.transport
                .dial(other.peer_id, other.addr.clone())
                .await
                .expect("dial failed");
        }
    }
}
