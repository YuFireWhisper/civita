use std::{io, sync::Arc};

use futures::StreamExt;
use libp2p::{
    core::upgrade,
    identity::Keypair,
    noise,
    swarm::{self, SwarmEvent},
    Multiaddr, PeerId, Swarm, Transport as _,
};
use tokio::{
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use crate::network::{
    behaviour::{self, Behaviour},
    gossipsub,
    request_response::{self},
    Gossipsub,
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Dial(#[from] libp2p::swarm::DialError),

    #[error(transparent)]
    TransportIo(#[from] libp2p::TransportError<io::Error>),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Lock contention")]
    LockContention,

    #[error(transparent)]
    Behaviour(#[from] behaviour::Error),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct Config {
    pub check_listen_timeout: Duration,
    pub channel_capacity: usize,
    pub get_swarm_lock_timeout: Duration,
    pub wait_for_gossipsub_peer_timeout: Duration,
    pub wait_for_gossipsub_peer_interval: Duration,
    pub wait_next_event_timeout: Duration,
    pub receive_interval: Duration,
}

pub struct Transport {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    gossipsub: Arc<Gossipsub>,
    req_resp: Arc<request_response::RequestResponse>,
    local_peer_id: PeerId,
    keypair: Keypair,
    listen_addr: Multiaddr,
    config: Config,
}

impl Transport {
    pub async fn new(keypair: Keypair, listen_addr: Multiaddr, config: Config) -> Result<Self> {
        let transport = libp2p::tcp::tokio::Transport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).expect("Failed to create Noise config"))
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

        let peer_id = keypair.public().to_peer_id();
        let behaviour = Behaviour::new(keypair.clone(), peer_id)?;

        let swarm_config = swarm::Config::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        let listen_addr =
            Self::listen_on(&mut swarm, listen_addr, config.check_listen_timeout).await?;

        let swarm = Arc::new(Mutex::new(swarm));

        let gossipsub_config = gossipsub::Config {
            timeout: config.wait_for_gossipsub_peer_timeout,
            channel_size: config.channel_capacity,
        };
        let gossipsub = Gossipsub::new(swarm.clone(), peer_id, gossipsub_config).await;
        let gossipsub = Arc::new(gossipsub);

        let req_resp = request_response::RequestResponse::new(swarm.clone());
        let req_resp = Arc::new(req_resp);

        let transport = Self {
            swarm,
            gossipsub,
            req_resp,
            local_peer_id: peer_id,
            keypair,
            listen_addr,
            config,
        };

        transport.receive().await;

        Ok(transport)
    }

    async fn listen_on(
        swarm: &mut Swarm<Behaviour>,
        addr: Multiaddr,
        check_timeout: Duration,
    ) -> Result<Multiaddr> {
        swarm.listen_on(addr)?;

        tokio::time::timeout(check_timeout, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => return Ok(address),
                    SwarmEvent::ListenerError { error, .. } => {
                        return Err(Error::from(error));
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(Error::from)
        .and_then(|result| result)
    }

    async fn receive(&self) {
        let swarm = self.swarm.clone();
        let gossipsub = self.gossipsub.clone();
        let req_resp = self.req_resp.clone();
        let receive_interval = self.config.receive_interval;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = Self::next_behaviour_event(&swarm) => {
                        match event {
                            behaviour::Event::Gossipsub(event) => {
                                if let Err(e) = gossipsub.handle_event(*event).await {
                                    log::error!("Error handling gossipsub event: {e:?}");
                                }
                            },
                            behaviour::Event::RequestResponse(event) => {
                                if let Err(e) = req_resp.handle_event(*event).await {
                                    log::error!("Error handling request response event: {e:?}");
                                }
                            },
                            behaviour::Event::Kad(_) => {
                                // Do nothing
                            },
                        }
                    },
                    _ = async { tokio::time::sleep(receive_interval).await } => {},
                }
            }
        });
    }

    async fn next_behaviour_event(swarm: &Arc<Mutex<Swarm<Behaviour>>>) -> behaviour::Event {
        loop {
            if let SwarmEvent::Behaviour(event) = swarm.lock().await.select_next_some().await {
                return event;
            }
        }
    }

    pub async fn swarm<'a>(&'a self) -> Result<MutexGuard<'a, Swarm<Behaviour>>> {
        match tokio::time::timeout(self.config.get_swarm_lock_timeout, self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockContention),
        }
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        let mut swarm = self.swarm().await?;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.add_peer_address(peer_id, addr.clone());
        swarm.dial(addr)?;
        Ok(())
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn listen_addr(&self) -> Multiaddr {
        self.listen_addr.clone()
    }

    pub fn gossipsub(&self) -> Arc<Gossipsub> {
        self.gossipsub.clone()
    }

    pub fn request_response(&self) -> Arc<request_response::RequestResponse> {
        self.req_resp.clone()
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        let mut swarm = self.swarm().await?;
        swarm.behaviour_mut().kad_mut().remove_peer(&peer_id);
        let _ = swarm.disconnect_peer_id(peer_id);
        Ok(())
    }

    pub fn keypair(&self) -> Keypair {
        self.keypair.clone()
    }
}

impl Default for Config {
    fn default() -> Self {
        const DEFAULT_CHECK_LISTEN_TIMEOUT: Duration = Duration::from_millis(100);
        const DEFAULT_CHANNEL_SIZE: usize = 1000;
        const DEFAULT_GET_SWARM_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
        const DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_TIMEOUT: Duration = Duration::from_secs(10);
        const DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_INTERVAL: Duration = Duration::from_millis(100);
        const DEFAULT_WAIT_NEXT_EVENT_TIMEOUT: Duration = Duration::from_millis(10);
        const DEFAULT_RECEIVE_INTERVAL: Duration = Duration::from_millis(100);

        let check_listen_timeout = DEFAULT_CHECK_LISTEN_TIMEOUT;
        let channel_capacity = DEFAULT_CHANNEL_SIZE;
        let get_swarm_lock_timeout = DEFAULT_GET_SWARM_LOCK_TIMEOUT;
        let wait_for_gossipsub_peer_timeout = DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_TIMEOUT;
        let wait_for_gossipsub_peer_interval = DEFAULT_WAIT_FOR_GOSSIPSUB_PEER_INTERVAL;
        let wait_next_event_timeout = DEFAULT_WAIT_NEXT_EVENT_TIMEOUT;
        let receive_interval = DEFAULT_RECEIVE_INTERVAL;

        Self {
            check_listen_timeout,
            channel_capacity,
            get_swarm_lock_timeout,
            wait_for_gossipsub_peer_timeout,
            wait_for_gossipsub_peer_interval,
            wait_next_event_timeout,
            receive_interval,
        }
    }
}
