use civita_benches::{init_contants, BenchConfig, Response, SimpleScriptPubKey, ADDRS, DIRS, KEYS};
use civita_core::{
    consensus::engine::NodeType,
    resident::{self, Resident},
    ty::Token,
};
use clap::Parser;
use log::LevelFilter;
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Root},
    filter::threshold::ThresholdFilter,
    Config,
};
use std::{io::BufRead, path::PathBuf};
use tokio::sync::oneshot;

#[derive(Debug)]
#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    id: usize,
}

struct NodeRunner {
    idx: usize,
    resident: Option<Resident<BenchConfig>>,
}

impl NodeRunner {
    async fn new(idx: usize) -> Self {
        let config = resident::Config {
            storage_dir: DIRS.get().unwrap()[idx].clone(),
            node_type: if idx == 0 {
                NodeType::Archive
            } else {
                NodeType::Regular
            },
            listen_addr: ADDRS.get().unwrap()[idx].clone(),
            bootstrap_peers: if idx == 0 {
                vec![]
            } else {
                vec![(
                    KEYS.get().unwrap()[0].public().to_peer_id(),
                    ADDRS.get().unwrap()[0].clone(),
                )]
            },
            ..Default::default()
        };

        let key = KEYS.get().unwrap()[idx].clone();
        let resident = Resident::<BenchConfig>::new(key, config)
            .await
            .expect("Failed to create node");

        Self {
            idx,
            resident: Some(resident),
        }
    }

    async fn start(&mut self, mut rx: oneshot::Receiver<oneshot::Sender<Response>>) {
        let key = KEYS.get().unwrap()[self.idx].clone();
        let pk = key.public();
        let peer_id = pk.to_peer_id();
        let resident = self.resident.take().unwrap();
        let idx = self.idx;

        let off_chain = vec![peer_id];
        let script_pk = SimpleScriptPubKey::new(&key);
        let created = vec![Token::new(1, script_pk)];
        let mut counter = 0u64;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(tx) = &mut rx => {
                        let status = resident.status().await.expect("Failed to get status");
                        resident.stop().await;
                        let _ = tx.send(Response::new(idx, counter, status));
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        match resident.propose(0, vec![], off_chain.clone(), created.clone()).await {
                            Ok(_) => {
                                counter += 1;
                            }
                            Err(e) => {
                                log::error!("Node {} proposal error: {:?}", idx, e);
                            }
                        }
                    }
                }

                tokio::task::yield_now().await;
            }
        });
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    init_contants();
    setup_logger(args.id).expect("Failed to set up logger");

    log::info!("Node {} starting up", args.id);

    let mut node = NodeRunner::new(args.id).await;

    let stdin = std::io::stdin();
    let reader = stdin.lock();
    let mut lines = reader.lines();
    let _ = lines.next();

    let (tx, rx) = oneshot::channel();
    node.start(rx).await;

    let _ = lines.next();
    let (resp_tx, resp_rx) = oneshot::channel();
    let _ = tx.send(resp_tx);

    log::info!("{}", resp_rx.await.unwrap());
}

fn setup_logger(node_id: usize) -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = PathBuf::from("log");
    std::fs::create_dir_all(&log_dir)?;

    let log_file = log_dir.join(format!("node_{:02}.log", node_id));
    let file_appender = FileAppender::builder().build(log_file)?;
    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
                .build("file", Box::new(file_appender)),
        )
        .logger(
            log4rs::config::Logger::builder()
                .appender("file")
                .additive(false)
                .build("civita_core", LevelFilter::Debug),
        )
        .build(Root::builder().appender("file").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;

    Ok(())
}
