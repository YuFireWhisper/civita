use std::{io, sync::Arc};

use crossbeam_channel::{unbounded, Receiver, Sender};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    gossipsub::{self, IdentTopic},
    identity::Keypair,
    noise,
    swarm::{self},
    tcp::tokio,
    yamux, Multiaddr, PeerId, Swarm, Transport,
};
use thiserror::Error;

use super::p2p_behaviour::P2PBehaviour;

#[derive(Debug, Error)]
pub enum P2PCommunicationError {
    #[error("Transport Error: {0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("Dial Error: {0}")]
    Dial(#[from] swarm::DialError),
    #[error("Gossipsub Error: {0}")]
    Gossipsub(String),
    #[error("Subscribe Error: {0}")]
    Subscribe(#[from] gossipsub::SubscriptionError),
    #[error("Publish Error: {0}")]
    Publish(#[from] gossipsub::PublishError),
}

type P2PCommunicationResult<T> = Result<T, P2PCommunicationError>;

pub struct P2PCommunication {
    swarm: Swarm<P2PBehaviour>,
    message_sender: Sender<P2PMessage>,
    message_receiver: Arc<Receiver<P2PMessage>>,
}

impl P2PCommunication {
    pub fn new(keypair: Keypair, listen_addr: Multiaddr) -> P2PCommunicationResult<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = P2PBehaviour::new(keypair.clone());

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            PeerId::from_public_key(&keypair.public()),
            swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(listen_addr)?;

        let (message_sender, message_receiver) = unbounded();

        Ok(Self {
            swarm,
            message_sender,
            message_receiver: Arc::new(message_receiver),
        })
    }

    fn create_transport(keypair: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed()
    }

    pub async fn dial(&mut self, peer_id: PeerId, addr: Multiaddr) -> P2PCommunicationResult<()> {
        self.swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        self.swarm.dial(addr)?;

        Ok(())
    }

    pub fn subscribe(&mut self, topic: &str) -> P2PCommunicationResult<()> {
        let topic = IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub_mut()
            .subscribe(&topic)?;
        Ok(())
    }

    pub fn publish(&mut self, topic: &str, data: impl Into<Vec<u8>>) -> P2PCommunicationResult<()> {
        let topic = IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, data)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct P2PMessage {
    pub source: PeerId,
    pub topic: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use libp2p::{
        futures::StreamExt, gossipsub, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId,
        Swarm,
    };
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::network::{
        p2p_behaviour::{P2PBehaviour, P2PEvent},
        p2p_communication::P2PCommunication,
    };

    const TIMEOUT_DURATION: Duration = Duration::from_secs(5);
    const TEST_TOPIC: &str = "test_topic";

    struct TestCommunication {
        peer_id: PeerId,
        listen_addr: Multiaddr,
        p2p: P2PCommunication,
    }

    impl TestCommunication {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;

            let mut p2p = P2PCommunication::new(keypair.clone(), listen_addr.clone())?;
            Self::wait_for_listen_addr(&mut p2p.swarm).await?;

            let peer_id = PeerId::from_public_key(&keypair.public());

            Ok(Self {
                peer_id,
                listen_addr: Self::get_actual_listen_addr(&p2p.swarm),
                p2p,
            })
        }

        fn get_actual_listen_addr(swarm: &Swarm<P2PBehaviour>) -> Multiaddr {
            swarm.listeners().next().cloned().unwrap_or_else(|| {
                panic!("No listen address available");
            })
        }

        async fn wait_for_listen_addr(swarm: &mut Swarm<P2PBehaviour>) -> Result<(), &'static str> {
            timeout(TIMEOUT_DURATION, async {
                while let Some(event) = swarm.next().await {
                    if let SwarmEvent::NewListenAddr { .. } = event {
                        return Ok(());
                    }
                }
                Err("Timeout waiting for listen address")
            })
            .await
            .map_err(|_| "Timeout waiting for listen address")?
        }

        pub fn has_peer_in_routing_table(&mut self, peer_id: &PeerId) -> bool {
            self.p2p
                .swarm
                .behaviour_mut()
                .kad_mut()
                .kbucket(*peer_id)
                .is_some()
        }

        pub async fn process_events(&mut self, duration: Duration) {
            let start = std::time::Instant::now();
            while start.elapsed() < duration {
                tokio::select! {
                    _ = self.p2p.swarm.select_next_some() => {
                    },
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
        }

        pub async fn establish_gossipsub_connection(
            &mut self,
            other: &mut Self,
        ) -> Result<(), &'static str> {
            self.p2p
                .dial(other.peer_id, other.listen_addr.clone())
                .await
                .map_err(|_| "Failed to dial")?;

            self.p2p
                .subscribe(TEST_TOPIC)
                .map_err(|_| "Failed to subscribe self")?;
            other
                .p2p
                .subscribe(TEST_TOPIC)
                .map_err(|_| "Failed to subscribe other")?;

            self.process_events(Duration::from_secs(3)).await;
            other.process_events(Duration::from_secs(3)).await;

            let connection_established = self.check_gossipsub_connection(other);

            if !connection_established {
                self.process_events(Duration::from_secs(3)).await;
                other.process_events(Duration::from_secs(3)).await;

                if !self.check_gossipsub_connection(other) {
                    return Err("Failed to establish Gossipsub connection");
                }
            }

            Ok(())
        }

        fn check_gossipsub_connection(&mut self, other: &mut Self) -> bool {
            let peers_in_mesh1 = self
                .p2p
                .swarm
                .behaviour_mut()
                .gossipsub_mut()
                .all_peers()
                .count();

            let peers_in_mesh2 = other
                .p2p
                .swarm
                .behaviour_mut()
                .gossipsub_mut()
                .all_peers()
                .count();

            peers_in_mesh1 > 0 && peers_in_mesh2 > 0
        }

        pub async fn wait_for_gossipsub_message(&mut self) -> Option<Vec<u8>> {
            timeout(TIMEOUT_DURATION, async {
                while let Some(event) = self.p2p.swarm.next().await {
                    if let SwarmEvent::Behaviour(P2PEvent::Gossipsub(gossipsub_event)) = event {
                        if let gossipsub::Event::Message { message, .. } = *gossipsub_event {
                            return Some(message.data);
                        }
                    }
                }
                None
            })
            .await
            .unwrap_or(None)
        }

        pub async fn wait_for_kad_event(&mut self) -> bool {
            timeout(TIMEOUT_DURATION, async {
                while let Some(event) = self.p2p.swarm.next().await {
                    if let SwarmEvent::Behaviour(_) = event {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false)
        }
    }

    #[tokio::test]
    async fn test_new() {
        let result = TestCommunication::new().await;
        assert!(
            result.is_ok(),
            "Failed to create P2PCommunication: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dial() {
        let target = TestCommunication::new().await.unwrap();
        let mut source = TestCommunication::new().await.unwrap();

        let result = source
            .p2p
            .dial(target.peer_id, target.listen_addr.clone())
            .await;
        let received_kad_event = source.wait_for_kad_event().await;

        assert!(result.is_ok(), "Dial operation should succeed");
        assert!(
            received_kad_event,
            "Should receive Kademlia event after dialing"
        );
        assert!(
            source.has_peer_in_routing_table(&target.peer_id),
            "Target peer should be in the routing table after dialing"
        );
    }

    #[tokio::test]
    async fn test_subscribe() {
        let mut comm = TestCommunication::new()
            .await
            .expect("Failed to create P2PCommunication");

        let subscribe_result = comm.p2p.subscribe(TEST_TOPIC);
        assert!(
            subscribe_result.is_ok(),
            "Failed to subscribe to topic: {:?}",
            subscribe_result.err()
        );

        let gossipsub = comm.p2p.swarm.behaviour_mut().gossipsub_mut();
        let subscriptions: Vec<String> =
            gossipsub.topics().map(|t| t.as_str().to_string()).collect();
        assert!(
            subscriptions.contains(&TEST_TOPIC.to_string()),
            "Should be subscribed to topic"
        );
    }

    #[tokio::test]
    async fn test_publish() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        let connection_result = node1.establish_gossipsub_connection(&mut node2).await;
        assert!(
            connection_result.is_ok(),
            "Gossipsub connection should be established: {:?}",
            connection_result.err()
        );

        let test_message = b"hello world";
        let publish_result = node1.p2p.publish(TEST_TOPIC, test_message);

        assert!(
            publish_result.is_ok(),
            "Should publish message successfully, got error: {:?}",
            publish_result.err()
        );

        let received_message = node2.wait_for_gossipsub_message().await;

        assert!(
            received_message.is_some(),
            "Should receive the published message"
        );

        assert_eq!(
            received_message.unwrap(),
            test_message.to_vec(),
            "Received message should match published message"
        );
    }
}
