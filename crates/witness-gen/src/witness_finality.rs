//! Assemble a FinalityWitness for Proof 2.

use anyhow::{Context, Result};

use zkasper_common::constants::SLOTS_PER_EPOCH;
use zkasper_common::poseidon::accumulator_commitment;
use zkasper_common::types::FinalityWitness;

use crate::beacon_api::BeaconApi;
use crate::poseidon_tree::PoseidonTree;

/// Build a FinalityWitness proving that a target checkpoint was finalized.
///
/// Parameters:
/// - `target_epoch`: the epoch of the checkpoint to prove finalized
/// - `target_root`: the block root of the checkpoint
/// - `poseidon_tree`: current Poseidon tree (must match the accumulator state)
/// - `total_active_balance`: current total active balance
/// - `signing_domain`: `compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_validators_root)`
pub async fn build(
    api: &impl BeaconApi,
    poseidon_tree: &PoseidonTree,
    target_epoch: u64,
    target_root: [u8; 32],
    total_active_balance: u64,
    signing_domain: [u8; 32],
) -> Result<FinalityWitness> {
    // Fetch validators at the epoch boundary (needed for pubkeys + balances)
    let slot_str = (target_epoch * SLOTS_PER_EPOCH).to_string();
    let validators = api
        .get_validators(&slot_str)
        .await
        .context("fetch validators for finality")?;

    let poseidon_root = poseidon_tree.root();
    let commitment = accumulator_commitment(&poseidon_root, total_active_balance);

    // Collect attestations targeting this checkpoint
    let attestations = crate::attestation_collector::collect_for_checkpoint(
        api,
        target_epoch,
        &target_root,
        &validators,
        poseidon_tree,
        target_epoch,
    )
    .await
    .context("collect attestations")?;

    Ok(FinalityWitness {
        accumulator_commitment: commitment,
        finalized_block_root: target_root,
        poseidon_root,
        total_active_balance,
        signing_domain,
        attestations,
    })
}
