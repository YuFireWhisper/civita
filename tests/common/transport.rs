use std::sync::Arc;

use civita::network::transport::Transport;
use libp2p::identity::Keypair;
use libp2p::Multiaddr;

use civita::network::transport::libp2p_transport::{config::Config, Libp2pTransport};

const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";

pub async fn create_connected_transports(n: u16) -> Vec<Arc<Libp2pTransport>> {
    let mut transports: Vec<Arc<Libp2pTransport>> = Vec::new();
    let mut addrs: Vec<Multiaddr> = Vec::new();

    for _ in 0..n {
        let keypair = Keypair::generate_ed25519();
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
        transports.push(Arc::new(transport));
        addrs.push(addr);
    }

    dial_peers(&transports, addrs).await;

    transports
}

async fn dial_peers(transports: &[Arc<Libp2pTransport>], addrs: Vec<Multiaddr>) {
    for (i, transport) in transports.iter().enumerate() {
        for (j, other) in transports.iter().enumerate() {
            if i != j {
                transport
                    .dial(other.self_peer(), addrs[j].to_owned())
                    .await
                    .expect("dial failed");
            }
        }
    }
}

async fn listen_addr(transport: &Libp2pTransport) -> Vec<Multiaddr> {
    let swarm = transport.swarm().await.expect("swarm not initialized");
    swarm.listeners().cloned().collect()
}
