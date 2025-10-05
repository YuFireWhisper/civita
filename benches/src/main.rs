use std::{
    io::Write,
    process::{Child, Command, Stdio},
    thread,
};

use civita_benches::init_contants;
use clap::Parser;

#[derive(Debug)]
#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value_t = 5)]
    nodes: usize,

    #[arg(short, long, default_value_t = 5)]
    warmup: u64,

    #[arg(short, long, default_value_t = 720)]
    duration: u64,
}

struct NodeProcess(Child);

impl NodeProcess {
    fn new(id: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cmd = Command::new("cargo");
        cmd.args(["run", "--bin", "node_runner", "--", "--id", &id.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        Ok(Self(cmd.spawn()?))
    }

    fn send_signal(&mut self) {
        let stdin = self.0.stdin.as_mut().expect("Failed to open stdin");
        writeln!(stdin).expect("Failed to write to stdin");
        stdin.flush().expect("Failed to flush stdin");
    }
}

fn main() {
    init_contants();

    let args = Args::parse();

    let mut processes = Vec::new();
    for i in 0..args.nodes {
        print!("  Starting node {}... ", i);
        match NodeProcess::new(i) {
            Ok(process) => {
                println!("✓");
                processes.push(process);
            }
            Err(e) => {
                eprintln!("✗");
                eprintln!("Failed to start node {}: {:?}", i, e);
                processes.iter_mut().for_each(|p| {
                    let _ = p.0.kill();
                });
                return;
            }
        }
    }

    println!(
        "\nAll {} nodes started. Warming up for {} seconds...",
        args.nodes, args.warmup
    );
    thread::sleep(std::time::Duration::from_secs(args.warmup));

    processes.iter_mut().for_each(|p| p.send_signal());

    thread::sleep(std::time::Duration::from_secs(args.duration));

    println!("\nStopping nodes and collecting results...");

    processes.iter_mut().for_each(|p| p.send_signal());

    std::thread::sleep(std::time::Duration::from_secs(5));
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
