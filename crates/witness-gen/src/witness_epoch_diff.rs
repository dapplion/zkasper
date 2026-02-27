//! Assemble an EpochDiffWitness between two beacon states.

use anyhow::{Context, Result};

use zkasper_common::constants::SLOTS_PER_EPOCH;
use zkasper_common::poseidon::poseidon_leaf;
use zkasper_common::types::{BlsPubkey, EpochDiffWitness, ValidatorData, ValidatorMutation};

use crate::beacon_api::BeaconApi;
use crate::poseidon_tree::PoseidonTree;
use crate::ssz_state;
use crate::state_diff::{
    build_validator_roots, build_validators_ssz_tree, find_mutations, make_state_proof,
    validator_response_to_data, validator_response_to_field_leaves,
    validator_response_to_pubkey_chunks,
};

/// Build an EpochDiffWitness and update the PoseidonTree in place.
///
/// `total_active_balance_1` is the total active balance at slot_1 (from DB).
/// `depth` controls the Merkle tree depth (40 for mainnet, smaller for tests).
///
/// Returns `(witness, new_total_active_balance, new_num_validators)`.
pub async fn build(
    api: &impl BeaconApi,
    poseidon_tree: &mut PoseidonTree,
    slot_1: u64,
    slot_2: u64,
    total_active_balance_1: u64,
    depth: u32,
) -> Result<(EpochDiffWitness, u64, u64)> {
    let slot_1_str = slot_1.to_string();
    let slot_2_str = slot_2.to_string();
    let epoch_1 = slot_1 / SLOTS_PER_EPOCH;
    let epoch_2 = slot_2 / SLOTS_PER_EPOCH;

    // Fetch validators at both states
    let validators_1 = api
        .get_validators(&slot_1_str)
        .await
        .context("fetch validators at slot_1")?;
    let validators_2 = api
        .get_validators(&slot_2_str)
        .await
        .context("fetch validators at slot_2")?;

    let num_validators_1 = validators_1.len() as u64;
    let num_validators_2 = validators_2.len() as u64;

    // Find which validators changed (including epoch-boundary activations/exits)
    let mutation_indices = find_mutations(&validators_1, &validators_2, epoch_1, epoch_2);
    anyhow::ensure!(
        !mutation_indices.is_empty(),
        "no mutations found between states"
    );

    // Build SSZ trees for both states, extracting siblings for mutation indices
    let old_roots = build_validator_roots(&validators_1);
    let new_roots = build_validator_roots(&validators_2);

    let (old_data_root, old_ssz_siblings_map) =
        build_validators_ssz_tree(&old_roots, depth, &mutation_indices);
    let (new_data_root, new_ssz_siblings_map) =
        build_validators_ssz_tree(&new_roots, depth, &mutation_indices);

    // Compute validators HTRs
    let old_validators_htr =
        zkasper_common::ssz::list_hash_tree_root(&old_data_root, num_validators_1);
    let new_validators_htr =
        zkasper_common::ssz::list_hash_tree_root(&new_data_root, num_validators_2);

    // Build state proofs — try real SSZ state, fall back to synthetic
    let raw_ssz_1 = api.get_state_ssz(&slot_1_str).await?;
    let raw_ssz_2 = api.get_state_ssz(&slot_2_str).await?;

    let (state_root_1, state_siblings_1) = if let Some(raw) = raw_ssz_1 {
        let header = api
            .get_header(&slot_1_str)
            .await
            .context("fetch header at slot_1")?;
        let proof = ssz_state::parse_fulu_state_proof(&raw, &old_validators_htr)?;
        anyhow::ensure!(
            proof.state_root == header.state_root,
            "SSZ state root mismatch at slot_1"
        );
        (proof.state_root, proof.siblings)
    } else {
        make_state_proof(&old_data_root, num_validators_1)
    };

    let (state_root_2, state_siblings_2) = if let Some(raw) = raw_ssz_2 {
        let header = api
            .get_header(&slot_2_str)
            .await
            .context("fetch header at slot_2")?;
        let proof = ssz_state::parse_fulu_state_proof(&raw, &new_validators_htr)?;
        anyhow::ensure!(
            proof.state_root == header.state_root,
            "SSZ state root mismatch at slot_2"
        );
        (proof.state_root, proof.siblings)
    } else {
        make_state_proof(&new_data_root, num_validators_2)
    };

    // Build mutations — process sequentially for correct Poseidon siblings
    let poseidon_root_1 = poseidon_tree.root();
    let mut mutations = Vec::with_capacity(mutation_indices.len());

    for &idx in &mutation_indices {
        let is_new = (idx as usize) >= validators_1.len();

        let new_v = if (idx as usize) < validators_2.len() {
            &validators_2[idx as usize]
        } else {
            anyhow::bail!("validator index {} out of range in new state", idx);
        };

        let new_data = validator_response_to_data(new_v);

        // Compute new Poseidon leaf and update tree — returns old siblings
        let new_active_balance = new_data.active_effective_balance(epoch_2);
        let new_poseidon_leaf = poseidon_leaf(&new_data.pubkey.0, new_active_balance);
        let poseidon_siblings = poseidon_tree.update_leaf(idx, new_poseidon_leaf);

        if is_new {
            // New validator: old data is zero (empty tree slot)
            let zero_data = ValidatorData {
                pubkey: BlsPubkey([0u8; 48]),
                effective_balance: 0,
                activation_epoch: 0,
                exit_epoch: 0,
            };

            mutations.push(ValidatorMutation {
                validator_index: idx,
                is_new: true,
                old_data: zero_data,
                new_data,
                old_field_leaves: [[0u8; 32]; 8],
                new_field_leaves: validator_response_to_field_leaves(new_v),
                old_pubkey_chunks: [[0u8; 32]; 2],
                new_pubkey_chunks: validator_response_to_pubkey_chunks(new_v),
                old_ssz_siblings: old_ssz_siblings_map[&idx].clone(),
                new_ssz_siblings: new_ssz_siblings_map[&idx].clone(),
                poseidon_siblings,
            });
        } else {
            let old_v = &validators_1[idx as usize];
            let old_data = validator_response_to_data(old_v);

            mutations.push(ValidatorMutation {
                validator_index: idx,
                is_new: false,
                old_data,
                new_data,
                old_field_leaves: validator_response_to_field_leaves(old_v),
                new_field_leaves: validator_response_to_field_leaves(new_v),
                old_pubkey_chunks: validator_response_to_pubkey_chunks(old_v),
                new_pubkey_chunks: validator_response_to_pubkey_chunks(new_v),
                old_ssz_siblings: old_ssz_siblings_map[&idx].clone(),
                new_ssz_siblings: new_ssz_siblings_map[&idx].clone(),
                poseidon_siblings,
            });
        }
    }

    // Compute new total active balance
    let new_total_active_balance: u64 = validators_2
        .iter()
        .map(|v| {
            let d = validator_response_to_data(v);
            d.active_effective_balance(epoch_2)
        })
        .sum();

    let witness = EpochDiffWitness {
        state_root_1,
        state_root_2,
        poseidon_root_1,
        total_active_balance_1,
        epoch_1,
        epoch_2,
        state_to_validators_siblings_1: state_siblings_1,
        state_to_validators_siblings_2: state_siblings_2,
        validators_list_length_1: num_validators_1,
        validators_list_length_2: num_validators_2,
        mutations,
    };

    Ok((witness, new_total_active_balance, num_validators_2))
}
