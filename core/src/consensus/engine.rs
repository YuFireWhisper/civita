use std::{collections::HashMap, sync::Arc};

use civita_serialize::Serialize;
use dashmap::DashMap;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    PeerId,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    RwLock,
};

use crate::{
    consensus::{
        graph::{CreationError, Graph},
        validator::Validator,
    },
    crypto::{hasher::Hasher, Multihash},
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        Gossipsub, Transport,
    },
    ty::atom::{Atom, Command},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),
}

#[derive(Clone, Copy)]
pub struct Config {
    pub gossip_topic: u8,
    pub request_response_topic: u8,
}

pub struct Engine<V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,

    gossip_topic: u8,
    req_resp_topic: u8,

    graph: RwLock<Graph<V>>,

    pending_atoms: DashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    atom_result_tx: Sender<Atom>,
}

impl<V: Validator> Engine<V> {
    pub async fn new(
        transport: Arc<Transport>,
        graph: Graph<V>,
        config: Config,
    ) -> Result<Arc<Self>> {
        let gossipsub = transport.gossipsub();
        let request_response = transport.request_response();
        let (atom_result_tx, atom_result_rx) = tokio::sync::mpsc::channel(100);
        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;

        let engine = Arc::new(Self {
            transport,
            gossipsub,
            request_response,
            gossip_topic: config.gossip_topic,
            req_resp_topic: config.request_response_topic,
            graph: RwLock::new(graph),
            pending_atoms: DashMap::new(),
            atom_result_tx,
        });

        let engine_clone = engine.clone();
        tokio::spawn(async move {
            engine_clone.run(gossip_rx, atom_result_rx).await;
        });

        Ok(engine)
    }

    pub async fn propose(
        &self,
        cmd: Command,
        script_sigs: HashMap<Multihash, Vec<u8>>,
    ) -> Result<(), CreationError> {
        let handle = self
            .graph
            .read()
            .await
            .create_atom(Some((cmd, script_sigs)))?;
        let tx = self.atom_result_tx.clone();

        tokio::spawn(async move {
            let atom = handle.await.expect("Atom creation failed");
            if let Err(e) = tx.send(atom).await {
                log::error!("Failed to send VDF result: {e}");
            }
        });

        Ok(())
    }

    async fn run(
        &self,
        mut gossip_rx: Receiver<gossipsub::Message>,
        mut atom_result_rx: Receiver<Atom>,
    ) {
        let mut request_response_rx = self.request_response.subscribe(self.req_resp_topic);

        loop {
            tokio::select! {
                Some(msg) = gossip_rx.recv() => {
                    let Ok(atom) = Atom::from_slice(msg.data.as_slice()) else {
                        self.gossipsub.report_validation_result(&msg.id, &msg.propagation_source, MessageAcceptance::Reject).await;
                        continue;
                    };

                    if !Hasher::validate(&atom.hash, &atom.header.to_vec()) {
                        log::warn!("Invalid atom hash from peer {}", msg.propagation_source);
                        self.gossipsub
                            .report_validation_result(&msg.id, &msg.propagation_source, MessageAcceptance::Reject)
                            .await;
                        continue;
                    }

                    self.pending_atoms
                        .entry(atom.hash)
                        .or_default()
                        .push((Some(msg.id), msg.propagation_source));

                    self.on_recv_atom(atom).await;
                }
                Some(msg) = request_response_rx.recv() => {
                    self.on_recv_reqeust_response(msg).await;
                }
                Some(atom) = atom_result_rx.recv() => {
                    self.on_atom_ready(atom).await;
                }
            }
        }
    }

    async fn on_recv_atom(&self, atom: Atom) {
        let hash = atom.hash;

        let Some(result) = self.graph.write().await.upsert(atom) else {
            log::info!("Atom {hash:?} is already existing");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                return;
            };

            for (msg_id, peer) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                self.gossipsub
                    .report_validation_result(&msg_id, &peer, MessageAcceptance::Ignore)
                    .await;
            }

            return;
        };

        for hash in result.accepted {
            log::info!("Atom {hash:?} accepted");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer_id) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                self.gossipsub
                    .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Ignore)
                    .await;
            }
        }

        for (hash, reason) in result.rejected {
            log::info!("Atom {hash:?} rejected: {reason:?}");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer_id) in infos {
                if let Some(msg_id) = msg_id {
                    self.gossipsub
                        .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Reject)
                        .await;
                } else {
                    self.disconnect_peer(peer_id).await;
                }
            }
        }
    }

    async fn disconnect_peer(&self, source: PeerId) {
        if let Err(e) = self.transport.disconnect(source).await {
            log::error!("Failed to disconnect peer: {e}");
        }
    }

    async fn on_recv_reqeust_response(&self, msg: Message) {
        match msg {
            Message::Request {
                peer,
                request,
                channel,
            } => {
                let hashes = Vec::from_slice(request.as_slice()).unwrap_or_default();
                if hashes.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                let atoms = {
                    let graph = self.graph.read().await;
                    let Some(atoms) = hashes.iter().try_fold(Vec::new(), |mut acc, h| {
                        acc.push(graph.get(h)?.to_vec());
                        Some(acc)
                    }) else {
                        self.disconnect_peer(peer).await;
                        return;
                    };
                    atoms
                };

                if let Err(e) = self
                    .request_response
                    .send_response(channel, atoms.to_vec(), self.req_resp_topic)
                    .await
                {
                    log::error!("Failed to send response: {e}");
                }
            }
            Message::Response { peer, response } => {
                let atoms: Vec<Atom> = Vec::from_slice(response.as_slice()).unwrap_or_default();
                if atoms.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                for atom in atoms {
                    if !Hasher::validate(&atom.hash, &atom.header.to_vec()) {
                        log::warn!("Invalid atom hash from peer {peer}");
                        self.disconnect_peer(peer).await;
                        return;
                    }

                    self.pending_atoms
                        .entry(atom.hash)
                        .or_default()
                        .push((None, peer));

                    self.on_recv_atom(atom).await;
                }
            }
        }
    }

    async fn on_atom_ready(&self, atom: Atom) {
        let hash = atom.hash;
        let bytes = atom.to_vec();
        let result = self.graph.write().await.upsert(atom).unwrap();

        if !result.rejected.is_empty() {
            debug_assert!(result.rejected.len() == 1);
            log::error!("Created atom was rejected: {:?}", result.rejected[&hash]);
            return;
        }

        debug_assert!(result.accepted.contains(&hash));

        if let Err(e) = self.gossipsub.publish(self.gossip_topic, bytes).await {
            log::error!("Failed to publish created atom: {e}");
        }
    }
}
