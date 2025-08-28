use std::{collections::HashMap, sync::Arc};

use civita_serialize::Serialize;
use dashmap::DashMap;
use libp2p::PeerId;
use tokio::sync::mpsc::{Receiver, Sender};
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF};

use crate::{
    consensus::{
        graph::{Graph, UpdateResult},
        validator::Validator,
    },
    crypto::Multihash,
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        Gossipsub, Transport,
    },
    ty::atom::{Atom, Command, Witness},
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
    pub vdf_params: u16,
    pub vdf_difficulty: u64,
}

pub struct Engine<V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,

    gossip_topic: u8,
    req_resp_topic: u8,

    graph: Graph<V>,
    pending_tasks: DashMap<Multihash, (Atom, HashMap<Multihash, Vec<u8>>)>,
    vdf_result_tx: Sender<(Multihash, u64, Vec<u8>)>,

    vdf: WesolowskiVDF,
}

impl<V: Validator> Engine<V> {
    pub async fn new(
        transport: Arc<Transport>,
        graph: Graph<V>,
        config: Config,
    ) -> Result<Arc<Self>> {
        let gossipsub = transport.gossipsub();
        let request_response = transport.request_response();
        let vdf = WesolowskiVDFParams(config.vdf_params).new();
        let (vdf_result_tx, vdf_result_rx) = tokio::sync::mpsc::channel(100);

        let engine = Arc::new(Self {
            transport: transport.clone(),
            gossipsub: gossipsub.clone(),
            request_response: request_response.clone(),

            gossip_topic: config.gossip_topic,
            req_resp_topic: config.request_response_topic,

            graph,
            pending_tasks: DashMap::new(),

            vdf,
            vdf_result_tx,
        });

        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;

        let engine_clone = engine.clone();

        tokio::spawn(async move {
            engine_clone.run(gossip_rx, vdf_result_rx).await;
        });

        Ok(engine)
    }

    pub async fn propose(
        &self,
        cmd: Command,
        script_sigs: HashMap<Multihash, Vec<u8>>,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let atom = Atom::new(self.transport.local_peer_id(), Some(cmd), now);

        let hash = atom.hash();
        self.pending_tasks.insert(hash, (atom, script_sigs));
        self.start_vdf_task(hash);

        Ok(())
    }

    async fn run(
        &self,
        mut gossip_rx: Receiver<gossipsub::Message>,
        mut vdf_result_rx: Receiver<(Multihash, u64, Vec<u8>)>,
    ) {
        let mut request_response_rx = self.request_response.subscribe(self.req_resp_topic);

        loop {
            tokio::select! {
                Some(msg) = gossip_rx.recv() => {
                    type Pair = (Atom, Witness);

                    let Ok((atom, witness)) = Pair::from_slice(msg.data.as_slice()) else {
                        self.disconnect_peer(msg.propagation_source).await;
                        continue;
                    };

                    self.on_recv_atom(atom, witness, msg.propagation_source).await;
                }
                Some(msg) = request_response_rx.recv() => {
                    self.on_recv_reqeust_response(msg).await;
                }
                Some((hash, difficulty, result)) = vdf_result_rx.recv() => {
                    self.on_vdf_complete(hash, difficulty, result).await;
                }
            }
        }
    }

    fn start_vdf_task(&self, hash: Multihash) {
        let vdf = self.vdf.clone();
        let difficulty = self.graph.difficulty();
        let tx = self.vdf_result_tx.clone();

        tokio::spawn(async move {
            let vdf_proof = vdf
                .solve(&hash.to_bytes(), difficulty)
                .expect("VDF solve failed");
            if let Err(e) = tx.send((hash, difficulty, vdf_proof)).await {
                log::error!("Failed to send VDF result: {e}");
            }
        });
    }

    async fn on_recv_atom(&self, atom: Atom, witness: Witness, source: PeerId) -> bool {
        if self
            .vdf
            .verify(
                &atom.hash().to_bytes(),
                self.graph.difficulty(),
                &witness.vdf_proof,
            )
            .is_err()
        {
            self.disconnect_peer(source).await;
            return true;
        }

        match self.graph.upsert(atom, witness) {
            UpdateResult::Missing(hashes) => {
                let bytes = hashes.to_vec();
                self.request_response
                    .send_request(source, bytes, self.req_resp_topic)
                    .await;
                true
            }
            UpdateResult::Invalidated(peers) => {
                for peer in peers {
                    self.disconnect_peer(peer).await;
                }
                false
            }
            UpdateResult::Noop => true,
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
                let hashes: Vec<Multihash> =
                    Vec::from_slice(request.as_slice()).unwrap_or_default();

                if hashes.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                let atoms = hashes.into_iter().try_fold(Vec::new(), |mut acc, hash| {
                    if let Some((atom, witness)) = self.graph.get(&hash) {
                        acc.push((atom, witness));
                        Some(acc)
                    } else {
                        None
                    }
                });

                let Some(atoms) = atoms else {
                    self.disconnect_peer(peer).await;
                    return;
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
                let atoms: Vec<(Atom, Witness)> =
                    Vec::from_slice(response.as_slice()).unwrap_or_default();

                if atoms.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                for (atom, witness) in atoms {
                    if !self.on_recv_atom(atom, witness, peer).await {
                        break;
                    }
                }
            }
        }
    }

    async fn on_vdf_complete(&self, hash: Multihash, difficulty: u64, result: Vec<u8>) {
        let Some((atom, sigs)) = self.pending_tasks.remove(&hash).map(|e| e.1) else {
            return;
        };

        if difficulty != self.graph.difficulty() {
            self.start_vdf_task(hash);
            return;
        }

        let head = self.graph.head();
        let trie_proofs = atom
            .cmd
            .as_ref()
            .map(|cmd| self.graph.generate_proofs(cmd.input.iter(), &head))
            .unwrap_or_default();
        let atoms = self.graph.get_children(&head);

        let witness = Witness {
            vdf_proof: result,
            trie_proofs,
            script_sigs: sigs,
            atoms,
        };

        let mut bytes = Vec::new();
        atom.to_writer(&mut bytes);
        witness.to_writer(&mut bytes);

        if !self.graph.upsert(atom, witness).is_noop() {
            log::error!("Inconsistent state after VDF completion");
            return;
        }

        if let Err(e) = self.gossipsub.publish(self.gossip_topic, bytes).await {
            log::error!("Failed to publish atom after VDF completion: {e}");
        }
    }
}
