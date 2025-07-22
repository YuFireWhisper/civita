use civita_core::{
    crypto::SecretKey,
    network::{transport::NetworkConfig, Transport},
};
use libp2p::Multiaddr;

const LISTEN_ADDRESS: &str = "/ip4/0.0.0.0/tcp/0";

pub async fn create_transports(n: usize) -> Vec<Transport> {
    let mut transports = Vec::with_capacity(n);

    for _ in 0..n {
        let sk = SecretKey::random();
        let listen_addr: Multiaddr = LISTEN_ADDRESS.parse().unwrap();
        let config = NetworkConfig::default();
        if let Ok(transport) = Transport::new_network(sk, listen_addr, config).await {
            transports.push(transport);
        }
    }

    dial_transports(&transports).await;

    transports
}

async fn dial_transports(transports: &[Transport]) {
    for (i, cur) in transports.iter().enumerate() {
        for target_transport in transports.iter().skip(i + 1) {
            let target_addr = target_transport.listen_addr();
            let target_peer_id = target_transport.local_peer_id();
            cur.dial(target_peer_id, target_addr).await.unwrap();
        }
    }
}
