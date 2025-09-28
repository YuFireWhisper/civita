use civita_core::network::{transport::Config, Transport};
use libp2p::{identity::Keypair, Multiaddr};

use crate::common::constants::*;

const LISTEN_ADDRESS: &str = "/ip4/0.0.0.0/tcp/0";

pub async fn create_transports() -> Vec<Transport> {
    let mut txs = Vec::with_capacity(5);

    let sk1 = Keypair::from_protobuf_encoding(&SK_1).unwrap();
    let sk2 = Keypair::from_protobuf_encoding(&SK_2).unwrap();
    let sk3 = Keypair::from_protobuf_encoding(&SK_3).unwrap();
    let sk4 = Keypair::from_protobuf_encoding(&SK_4).unwrap();
    let sk5 = Keypair::from_protobuf_encoding(&SK_5).unwrap();

    let addr: Multiaddr = LISTEN_ADDRESS.parse().unwrap();
    let config = Config::default();
    txs.push(Transport::new(sk1, addr.clone(), config).await.unwrap());
    txs.push(Transport::new(sk2, addr.clone(), config).await.unwrap());
    txs.push(Transport::new(sk3, addr.clone(), config).await.unwrap());
    txs.push(Transport::new(sk4, addr.clone(), config).await.unwrap());
    txs.push(Transport::new(sk5, addr, config).await.unwrap());

    txs
}
