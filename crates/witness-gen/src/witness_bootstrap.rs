//! Assemble a BootstrapWitness for one-time Poseidon tree construction.

use anyhow::{Context, Result};

use zkasper_common::constants::SLOTS_PER_EPOCH;
use zkasper_common::types::BootstrapWitness;

use crate::beacon_api::BeaconApi;
use crate::poseidon_tree::PoseidonTree;
use crate::state_diff::{
    build_validator_roots, make_state_proof, validator_response_to_data,
    validator_response_to_field_leaves, validator_response_to_pubkey_chunks,
};

/// Build a BootstrapWitness and PoseidonTree from a beacon state at `slot`.
///
/// `depth` controls the Merkle tree depth (40 for mainnet, smaller for tests).
/// Returns `(witness, tree, total_active_balance, num_validators)`.
pub async fn build(
    api: &impl BeaconApi,
    slot: u64,
    depth: u32,
) -> Result<(BootstrapWitness, PoseidonTree, u64, u64)> {
    let slot_str = slot.to_string();

    // Fetch header to get the state_root
    let header = api
        .get_header(&slot_str)
        .await
        .context("fetch block header")?;
    let state_root = header.state_root;
    let epoch = header.slot / SLOTS_PER_EPOCH;

    // Fetch all validators at this state
    let validators = api
        .get_validators(&slot_str)
        .await
        .context("fetch validators")?;
    let num_validators = validators.len() as u64;

    // Convert to common types + SSZ chunks
    let validator_data: Vec<_> = validators.iter().map(validator_response_to_data).collect();
    let field_chunks: Vec<_> = validators
        .iter()
        .map(validator_response_to_field_leaves)
        .collect();
    let pubkey_chunks: Vec<_> = validators
        .iter()
        .map(validator_response_to_pubkey_chunks)
        .collect();

    // Build SSZ data tree root and state proof
    let validator_roots = build_validator_roots(&validators);
    let (ssz_data_root, _) =
        crate::state_diff::build_validators_ssz_tree(&validator_roots, depth, &[]);
    let (computed_state_root, state_siblings) = make_state_proof(&ssz_data_root, num_validators);

    // Sanity check: our computed state root should match the header's state root.
    // In production with real state proofs this would always hold.
    // With synthetic proofs, the caller needs to have used our make_state_proof.
    anyhow::ensure!(
        computed_state_root == state_root,
        "computed state root does not match header state root — \
         real state proofs are not yet supported"
    );

    // Build Poseidon tree
    let tree = PoseidonTree::build(&validator_data, epoch, depth);

    // Compute total active balance
    let total_active_balance: u64 = validator_data
        .iter()
        .map(|v| v.active_effective_balance(epoch))
        .sum();

    let witness = BootstrapWitness {
        state_root,
        epoch,
        validators: validator_data,
        state_to_validators_siblings: state_siblings,
        validators_list_length: num_validators,
        validator_field_chunks: field_chunks,
        validator_pubkey_chunks: pubkey_chunks,
    };

    Ok((witness, tree, total_active_balance, num_validators))
}
