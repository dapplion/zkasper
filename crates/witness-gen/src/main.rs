mod attestation_collector;
mod beacon_api;
mod db;
mod poseidon_tree;
mod state_diff;
mod witness_bootstrap;
mod witness_epoch_diff;
mod witness_finality;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use zkasper_common::constants::VALIDATORS_TREE_DEPTH;

use beacon_api::BeaconApiClient;
use db::Db;

#[derive(Parser)]
#[command(name = "zkasper-witness-gen")]
#[command(about = "Witness generator for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Path for persistent state (Poseidon tree, cursor)
    #[arg(long, default_value = "zkasper.db")]
    db_path: String,

    /// Output directory for witness files
    #[arg(long, default_value = ".")]
    output_dir: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build initial Poseidon tree from the full validator set
    Bootstrap {
        /// Slot to bootstrap from (must be an epoch boundary)
        slot: u64,
    },
    /// Generate epoch diff witness between two epoch-boundary slots
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
        /// Target block root (hex, 0x-prefixed)
        #[arg(long)]
        target_root: String,
        /// Signing domain (hex, 0x-prefixed). Precomputed from fork version + genesis validators root.
        #[arg(long)]
        signing_domain: String,
    },
    /// Continuous mode: watch for new finalized checkpoints and generate proofs
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = BeaconApiClient::new(&cli.beacon_url);
    let db = Db::new(&cli.db_path);

    match cli.command {
        Command::Bootstrap { slot } => {
            eprintln!("bootstrapping from slot {slot}...");

            let (witness, tree, total_active_balance, num_validators) =
                witness_bootstrap::build(&api, slot, VALIDATORS_TREE_DEPTH).await?;

            let epoch = witness.epoch;

            // Save tree state to DB
            db.save(&tree, epoch, total_active_balance, num_validators)?;
            eprintln!("saved tree state: epoch={epoch}, validators={num_validators}, total_active_balance={total_active_balance}");

            // Serialize witness
            let output_path = format!("{}/bootstrap_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize bootstrap witness")?;
            std::fs::write(&output_path, bytes).context("write bootstrap witness")?;
            eprintln!("wrote {output_path} ({} bytes)", std::fs::metadata(&output_path)?.len());
        }

        Command::EpochDiff { slot1, slot2 } => {
            eprintln!("epoch diff: slot {slot1} -> {slot2}...");

            let (mut tree, cursor_epoch, total_active_balance, _num_validators) = db
                .load()?
                .context("no saved state — run bootstrap first")?;

            eprintln!("loaded tree state: cursor_epoch={cursor_epoch}, total_active_balance={total_active_balance}");

            let (witness, new_total_active_balance, new_num_validators) =
                witness_epoch_diff::build(&api, &mut tree, slot1, slot2, total_active_balance, VALIDATORS_TREE_DEPTH)
                    .await?;

            let new_epoch = witness.epoch_2;

            // Save updated tree
            db.save(&tree, new_epoch, new_total_active_balance, new_num_validators)?;
            eprintln!("saved tree state: epoch={new_epoch}, validators={new_num_validators}, total_active_balance={new_total_active_balance}");

            // Serialize witness
            let output_path = format!("{}/epoch_diff_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize epoch diff witness")?;
            std::fs::write(&output_path, bytes).context("write epoch diff witness")?;
            eprintln!("wrote {output_path} ({} bytes)", std::fs::metadata(&output_path)?.len());
        }

        Command::Finality {
            epoch,
            target_root,
            signing_domain,
        } => {
            eprintln!("finality proof for epoch {epoch}...");

            let (tree, _cursor_epoch, total_active_balance, _num_validators) = db
                .load()?
                .context("no saved state — run bootstrap + epoch-diff first")?;

            let target_root = parse_hex_bytes32(&target_root)?;
            let signing_domain = parse_hex_bytes32(&signing_domain)?;

            let witness = witness_finality::build(
                &api,
                &tree,
                epoch,
                target_root,
                total_active_balance,
                signing_domain,
            )
            .await?;

            // Serialize witness
            let output_path = format!("{}/finality_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize finality witness")?;
            std::fs::write(&output_path, bytes).context("write finality witness")?;
            eprintln!("wrote {output_path} ({} bytes)", std::fs::metadata(&output_path)?.len());
        }

        Command::Run => {
            eprintln!("continuous mode not yet implemented");
            todo!("run")
        }
    }

    Ok(())
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}
