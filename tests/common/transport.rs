use std::sync::Arc;

use libp2p::identity::Keypair;
use libp2p::Multiaddr;

use civita::network::transport::{config::Config, Transport};

const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";

pub async fn create_connected_transports(n: u16) -> Vec<Arc<Transport>> {
    let mut transports: Vec<Arc<Transport>> = Vec::new();
    let mut addrs: Vec<Multiaddr> = Vec::new();

    for _ in 0..n {
        let keypair = Keypair::generate_ed25519();
        let transport = Transport::new(
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

async fn dial_peers(transports: &[Arc<Transport>], addrs: Vec<Multiaddr>) {
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

async fn listen_addr(transport: &Transport) -> Vec<Multiaddr> {
    let swarm = transport.swarm().await.expect("swarm not initialized");
    swarm.listeners().cloned().collect()
}
