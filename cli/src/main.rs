use std::sync::OnceLock;

use base64::Engine;
use civita_core::{
    identity::{Keypair, PeerId, PublicKey},
    resident, Multiaddr,
};
use clap::{Arg, Command};

mod validator;

// SK 1 (base64): CAISIBhIYZWrCsH+bGF2auXH5UyFQZV3OGi0YhaH9tukAIjk
// PK 1 (base64): CAISIQMl55Ld5OhSnQKYJoz3zwXJT2K5d/SpxF64Ve7q/ogGUQ==
// SK 2 (base64): CAISIIvA84VpzqjAq6WdqlrS+k2k3l0+DzU3/gDk2AZhZE5O
// PK 2 (base64): CAISIQPXCjOmn4ZK+Klf5vUMdHpEX53ps3JUyDnjiuZY/rmiKg==

static INIT_TOKENS: OnceLock<Vec<u64>> = OnceLock::new();
static GENESIS_PEER_PK: OnceLock<PublicKey> = OnceLock::new();

#[tokio::main]
async fn main() {
    let matches = Command::new("civita-cli")
        .about("Civita blockchain CLI")
        .arg(
            Arg::new("secret_key")
                .required(true)
                .index(1)
                .value_name("SECRET_KEY")
                .help("Secret key of the local peer in protobuf format (base64 encoded)"),
        )
        .arg(
            Arg::new("init tokens")
                .short('t')
                .long("tokens")
                .value_name("TOKEN1,TOKEN2,...")
                .help("Comma-separated list of initial token values for the genesis block"),
        )
        .arg(
            Arg::new("genesis pk")
                .short('k')
                .long("genesis-pk")
                .value_name("PUBLIC_KEY")
                .help("Public key of the genesis peer in protobuf format (base64 encoded)"),
        )
        .arg(
            Arg::new("listen addr")
                .short('l')
                .long("listen-addr")
                .value_name("MULTIADDR")
                .help("Multiaddr for the local peer to listen on")
                .default_value("/ip4/0.0.0.0/tcp/0"),
        )
        .arg(
            Arg::new("bootstrap peers")
                .short('b')
                .long("bootstrap-peers")
                .value_name("PEER1_ID,PEER1_ADDR,PEER2_ID,PEER2_ADDR,...")
                .help(
                    "Comma-separated list of bootstrap peers in the format PEER_ID,MULTIADDR,...",
                ),
        )
        .arg(
            Arg::new("storage dir")
                .short('d')
                .long("storage-dir")
                .value_name("DIR")
                .help("Directory for storing persistent data")
                .default_value("./data"),
        )
        .arg(
            Arg::new("block threshold")
                .long("block-threshold")
                .value_name("NUM")
                .help("Block threshold for graph config")
                .default_value("1"),
        )
        .arg(
            Arg::new("checkpoint distance")
                .long("checkpoint-distance")
                .value_name("NUM")
                .help("Checkpoint distance")
                .default_value("100"),
        )
        .arg(
            Arg::new("target block time")
                .long("target-block-time")
                .value_name("SECS")
                .help("Target block time in seconds")
                .default_value("15"),
        )
        .arg(
            Arg::new("init vdf difficulty")
                .long("init-vdf-difficulty")
                .value_name("NUM")
                .help("Initial VDF difficulty")
                .default_value("10"),
        )
        .arg(
            Arg::new("max difficulty adjustment")
                .long("max-difficulty-adjustment")
                .value_name("RATIO")
                .help("Maximum difficulty adjustment ratio")
                .default_value("5.0"),
        )
        .arg(
            Arg::new("vdf params")
                .long("vdf-params")
                .value_name("NUM")
                .help("VDF parameters")
                .default_value("1024"),
        )
        .arg(
            Arg::new("heartbeat interval")
                .long("heartbeat-interval")
                .value_name("SECS")
                .help("Heartbeat interval in seconds (0 to disable)")
                .default_value("5"),
        )
        .get_matches();

    // Parse secret key (required positional argument)
    let sk_str = matches
        .get_one::<String>("secret_key")
        .expect("Secret key argument is required");
    let sk_bytes = base64::engine::general_purpose::STANDARD
        .decode(sk_str)
        .expect("Invalid base64 secret key");
    let keypair = Keypair::from_protobuf_encoding(&sk_bytes).expect("Failed to parse secret key");

    let local_public_key = keypair.public();
    let local_pk_bytes = local_public_key.encode_protobuf();

    // Parse optional init tokens
    if let Some(tokens_str) = matches.get_one::<String>("init tokens") {
        let tokens = tokens_str
            .split(',')
            .map(|s| s.parse::<u64>().expect("Invalid token value"))
            .collect::<Vec<_>>();
        INIT_TOKENS
            .set(tokens)
            .expect("Failed to set initial tokens");
    }

    // Parse optional genesis public key
    if let Some(pk_str) = matches.get_one::<String>("genesis pk") {
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(pk_str)
            .expect("Invalid base64 public key");
        let pk = PublicKey::try_decode_protobuf(&pk_bytes).expect("Failed to parse public key");
        GENESIS_PEER_PK
            .set(pk)
            .expect("Failed to set genesis public key");
    }

    // Parse listen address
    let listen_addr = matches
        .get_one::<String>("listen addr")
        .expect("Listen address argument is required")
        .parse::<Multiaddr>()
        .expect("Invalid listen multiaddr");

    // Parse bootstrap peers
    let bootstrap_peers =
        if let Some(bootstrap_peers_str) = matches.get_one::<String>("bootstrap peers") {
            if bootstrap_peers_str.is_empty() {
                Vec::new()
            } else {
                let parts = bootstrap_peers_str.split(',').collect::<Vec<_>>();
                if parts.len() % 2 != 0 {
                    panic!("Bootstrap peers must be in pairs of PEER_ID and MULTIADDR");
                }
                parts
                    .chunks(2)
                    .map(|chunk| {
                        let peer_id = chunk[0].parse::<PeerId>().expect("Invalid peer ID");
                        let addr = chunk[1].parse::<Multiaddr>().expect("Invalid multiaddr");
                        (peer_id, addr)
                    })
                    .collect::<Vec<_>>()
            }
        } else {
            Vec::new()
        };

    // Parse storage directory
    let storage_dir = matches
        .get_one::<String>("storage dir")
        .expect("Storage directory argument is required")
        .clone();

    // Parse other config values
    let block_threshold = matches
        .get_one::<String>("block threshold")
        .unwrap()
        .parse::<u32>()
        .expect("Invalid block threshold");

    let checkpoint_distance = matches
        .get_one::<String>("checkpoint distance")
        .unwrap()
        .parse::<u32>()
        .expect("Invalid checkpoint distance");

    let target_block_time = matches
        .get_one::<String>("target block time")
        .unwrap()
        .parse::<u64>()
        .expect("Invalid target block time");

    let init_vdf_difficulty = matches
        .get_one::<String>("init vdf difficulty")
        .unwrap()
        .parse::<u64>()
        .expect("Invalid init vdf difficulty");

    let max_difficulty_adjustment = matches
        .get_one::<String>("max difficulty adjustment")
        .unwrap()
        .parse::<f32>()
        .expect("Invalid max difficulty adjustment");

    let vdf_params = matches
        .get_one::<String>("vdf params")
        .unwrap()
        .parse::<u16>()
        .expect("Invalid vdf params");

    let heartbeat_secs = matches
        .get_one::<String>("heartbeat interval")
        .unwrap()
        .parse::<u64>()
        .expect("Invalid heartbeat interval");

    let heartbeat_interval = if heartbeat_secs == 0 {
        None
    } else {
        Some(tokio::time::Duration::from_secs(heartbeat_secs))
    };

    // Build config
    let resident_config = resident::Config {
        block_threshold,
        checkpoint_distance,
        target_block_time,
        init_vdf_difficulty,
        max_difficulty_adjustment,
        vdf_params,
        heartbeat_interval,
        listen_addr,
        storage_dir,
        bootstrap_peers,
        bootstrap_timeout: tokio::time::Duration::from_secs(5),
        ..Default::default()
    };

    // Create resident
    let resident =
        resident::Resident::<validator::Validator>::new(keypair.clone(), resident_config)
            .await
            .expect("Failed to create resident");

    println!("Civita CLI started successfully!");
    println!(
        "Your public key: {}",
        base64::engine::general_purpose::STANDARD.encode(&local_pk_bytes)
    );
    println!("Your listening address: {}", resident.listen_addr());
    println!("\nAvailable commands:");
    println!("  balance    - Check your token balance");
    println!("  transfer   - Transfer tokens to another user");
    println!("  status     - Check blockchain status");
    println!("  help       - Show this help message");
    println!("  quit       - Exit the CLI");

    loop {
        print!("\ncivita> ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        let input = input.trim();

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "balance" => {
                handle_balance(&resident, &local_pk_bytes).await;
            }
            "transfer" => {
                if parts.len() != 3 {
                    println!("Usage: transfer <amount> <recipient_public_key_base64>");
                    continue;
                }
                let amount = match parts[1].parse::<u64>() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Error: Invalid amount");
                        continue;
                    }
                };
                handle_transfer(&resident, &keypair, &local_pk_bytes, amount, parts[2]).await;
            }
            "status" => {
                handle_status(&resident).await;
            }
            "help" => {
                println!("Available commands:");
                println!("  balance    - Check your token balance");
                println!("  transfer   - Transfer tokens to another user");
                println!("  status     - Check blockchain status");
                println!("  help       - Show this help message");
                println!("  quit       - Exit the CLI");
            }
            "quit" | "exit" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!(
                    "Unknown command: {}. Type 'help' for available commands.",
                    parts[0]
                );
            }
        }
    }
}

async fn handle_balance(resident: &resident::Resident<validator::Validator>, local_pk: &[u8]) {
    let tokens = resident.tokens().await;
    let mut total_balance = 0u64;
    let mut token_count = 0;

    for token in &tokens {
        if token.script_pk == local_pk {
            let value = u64::from_be_bytes(token.value.as_slice().try_into().unwrap_or([0u8; 8]));
            total_balance += value;
            token_count += 1;

            println!(
                "  Token ID: {}",
                base64::engine::general_purpose::STANDARD.encode(token.id.to_bytes())
            );
            println!("  Value: {}", value);
            println!("  ---");
        }
    }

    println!(
        "Total balance: {} (from {} tokens)",
        total_balance, token_count
    );
}

async fn handle_transfer(
    resident: &resident::Resident<validator::Validator>,
    keypair: &Keypair,
    local_pk: &[u8],
    amount: u64,
    recipient_pk_str: &str,
) {
    let recipient_pk = match base64::engine::general_purpose::STANDARD.decode(recipient_pk_str) {
        Ok(pk) => pk,
        Err(_) => {
            println!("Error: Invalid recipient public key (must be base64 encoded)");
            return;
        }
    };

    let tokens = resident.tokens().await;
    let mut my_tokens = Vec::new();
    let mut total_balance = 0u64;

    for token in tokens {
        if token.script_pk == local_pk {
            let value = u64::from_be_bytes(token.value.as_slice().try_into().unwrap_or([0u8; 8]));
            total_balance += value;
            my_tokens.push((token.id, value));
        }
    }

    if total_balance < amount {
        println!(
            "Error: Insufficient balance. You have {} but trying to transfer {}",
            total_balance, amount
        );
        return;
    }

    println!("Transferring {} tokens...", amount);
    println!("Your current balance: {}", total_balance);

    let mut inputs = Vec::new();
    let mut consumed_value = 0u64;

    for (token_id, value) in &my_tokens {
        inputs.push((
            *token_id,
            keypair
                .sign(&token_id.to_bytes())
                .expect("Failed to sign token ID"),
        ));
        consumed_value += value;

        if consumed_value >= amount {
            break;
        }
    }

    let mut created = Vec::new();

    created.push((amount.to_be_bytes().to_vec(), recipient_pk.clone()));

    let change = consumed_value - amount;
    if change > 0 {
        created.push((change.to_be_bytes().to_vec(), local_pk.to_vec()));
    }

    match resident.propose(0, inputs, created).await {
        Ok(_) => {
            println!("Transfer successful!");
            println!("Amount transferred: {}", amount);
            if change > 0 {
                println!("Change returned: {}", change);
            }
            println!("New balance: {}", total_balance - amount);
        }
        Err(e) => {
            println!("Transfer failed: {:?}", e);
        }
    }
}

async fn handle_status(resident: &resident::Resident<validator::Validator>) {
    let status = resident.status().await;

    println!("Blockchain Status:");
    println!("==================");
    println!(
        "Main chain head: {}",
        base64::engine::general_purpose::STANDARD.encode(status.main_head.to_bytes())
    );
    println!("Main chain height: {}", status.main_height);
    println!(
        "Checkpoint: {}",
        base64::engine::general_purpose::STANDARD.encode(status.checkpoint.to_bytes())
    );
    println!("Checkpoint height: {}", status.checkpoint_height);
    println!("Current difficulty: {}", status.difficulty);
}
