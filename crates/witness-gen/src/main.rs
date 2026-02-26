#[allow(dead_code)]
mod attestation_collector;
#[allow(dead_code)]
mod beacon_api;
#[allow(dead_code)]
mod db;
#[allow(dead_code)]
mod poseidon_tree;
#[allow(dead_code)]
mod state_diff;
#[allow(dead_code)]
mod witness_bootstrap;
#[allow(dead_code)]
mod witness_epoch_diff;
#[allow(dead_code)]
mod witness_finality;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zkasper-witness-gen")]
#[command(about = "Witness generator for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Database path for persistent state (Poseidon tree, cursor)
    #[arg(long, default_value = "zkasper_data")]
    db_path: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build initial Poseidon tree from the full validator set
    Bootstrap {
        /// Slot to bootstrap from
        slot: u64,
    },
    /// Generate epoch diff witness between two consecutive epochs
    EpochDiff {
        /// Last slot of the previous epoch
        slot1: u64,
        /// Last slot of the current epoch
        slot2: u64,
    },
    /// Generate finality proof witness for a given epoch
    Finality {
        /// The epoch whose checkpoint to prove finalized
        epoch: u64,
    },
    /// Continuous mode: watch for new finalized checkpoints and generate proofs
    Run,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Bootstrap { slot } => {
            eprintln!("bootstrap from slot {slot}");
            todo!("bootstrap")
        }
        Command::EpochDiff { slot1, slot2 } => {
            eprintln!("epoch diff: {slot1} -> {slot2}");
            todo!("epoch-diff")
        }
        Command::Finality { epoch } => {
            eprintln!("finality proof for epoch {epoch}");
            todo!("finality")
        }
        Command::Run => {
            eprintln!("continuous mode");
            todo!("run")
        }
    }
}
