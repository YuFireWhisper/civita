use std::path::PathBuf;

use libp2p::PeerId;

use crate::{
    consensus::tree::Tree,
    network::{transport::Request, Transport},
    traits,
};

const MAX_HEADERS_PER_REQUEST: u32 = 1000;

pub struct Bootstraper<T: traits::Config> {
    pub transport: Transport<T>,
    pub bootstrap_peer: PeerId,
    pub tree: Option<Tree<T>>,
    pub dir: PathBuf,
    pub is_archival: bool,
}

impl<T: traits::Config> Bootstraper<T> {
    pub fn new<P>(
        transport: Transport<T>,
        bootstrap_peer: PeerId,
        dir: P,
        is_archival: bool,
    ) -> Self
    where
        P: AsRef<std::path::Path>,
    {
        let tree = is_archival
            .then(|| Tree::load_or_genesis(&dir).expect("Failed to load or create genesis"));

        Self {
            transport,
            bootstrap_peer,
            tree,
            dir: dir.as_ref().to_path_buf(),
            is_archival,
        }
    }

    pub async fn bootstrap(&mut self) {
        loop {
            let req = Request::CurrentHeight;
            self.transport.send_request(req, self.bootstrap_peer).await;
            let remote_height = self.transport.recv_current_height().await;
            let local_height = self
                .tree
                .as_ref()
                .map(|tree| tree.head_height())
                .unwrap_or_default();

            if remote_height < local_height {
                break;
            }

            if remote_height == local_height {
                let tree = self
                    .tree
                    .get_or_insert_with(|| Tree::genesis(&self.dir, Some(self.transport.peer_id)));

                if !self.is_archival {
                    let req = Request::Proofs;
                    self.transport.send_request(req, self.bootstrap_peer).await;
                    let (height, proofs) = self.transport.recv_proofs().await;

                    if height != local_height {
                        continue;
                    }

                    assert!(tree.fill(proofs));
                }

                break;
            }

            let start = if self.is_archival {
                local_height + 1
            } else {
                remote_height
                    .saturating_sub(T::MAINTENANCE_WINDOW)
                    .max(T::GENESIS_HEIGHT)
            };
            let end = remote_height.min(start + MAX_HEADERS_PER_REQUEST - 1);

            let req = Request::Headers(start, end);
            self.transport.send_request(req, self.bootstrap_peer).await;

            let headers = self.transport.recv_headers().await;
            let mut atoms = vec![None; headers.len()];
            let mut count = 0;

            for header in &headers {
                let req = Request::AtomByHash(*header);
                self.transport.send_request(req, self.bootstrap_peer).await;
            }

            while count < atoms.len() {
                let atom = self.transport.recv_atom().await;

                if atom.height < start || atom.height > end {
                    continue;
                }

                let idx = (atom.height - start) as usize;

                if headers[idx] != atom.parent {
                    continue;
                }

                if atoms[idx].is_none() {
                    atoms[idx] = Some(atom);
                    count += 1;
                }
            }

            let tree = self.tree.get_or_insert_with(|| {
                Tree::with_atom(atoms[0].take().unwrap(), &self.dir, self.transport.peer_id)
            });

            if !tree.execute_chain(atoms.into_iter().flatten()) {
                // TODO: handle error
                panic!("Failed to execute chain");
            }
        }
    }

    pub fn take(self) -> (Transport<T>, Tree<T>) {
        (self.transport, self.tree.unwrap())
    }
}
