// Re-export verification functions for use by integration tests and other crates.

extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::types::EpochDiffWitness;

/// Core epoch-diff verification logic. Returns (new_accumulator_commitment, new_poseidon_root, new_total_active_balance).
pub fn verify_epoch_diff(witness: &EpochDiffWitness) -> ([u8; 32], [u8; 32], u64) {
    verify_epoch_diff_with_depth(
        witness,
        zkasper_common::constants::VALIDATORS_TREE_DEPTH,
        zkasper_common::constants::POSEIDON_TREE_DEPTH,
    )
}

/// Epoch-diff verification with configurable tree depths.
///
/// `ssz_depth`: depth of the SSZ validators data tree (40 per spec).
/// `poseidon_depth`: depth of the Poseidon accumulator tree.
pub fn verify_epoch_diff_with_depth(
    witness: &EpochDiffWitness,
    ssz_depth: u32,
    poseidon_depth: u32,
) -> ([u8; 32], [u8; 32], u64) {
    use zkasper_common::poseidon::{compute_poseidon_merkle_root, poseidon_leaf};
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, compute_validator_field_leaves, list_hash_tree_root,
        validator_hash_tree_root, validator_hash_tree_root_pair, verify_ssz_multi_proof,
    };

    // Verify Poseidon siblings length matches expected depth
    for mutation in &witness.mutations {
        assert_eq!(
            mutation.poseidon_siblings.len(),
            poseidon_depth as usize,
            "poseidon siblings length mismatch for validator {}",
            mutation.validator_index,
        );
    }

    let mut poseidon_root = witness.poseidon_root_1;
    let mut total_active_balance = witness.total_active_balance_1;
    let epoch_old = witness.epoch_1;
    let epoch_new = witness.epoch_2;

    // Phase 1: Per-mutation validation + Poseidon updates (sequential)
    // Collect SSZ leaves for multi-proof verification
    let mut old_ssz_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(witness.mutations.len());
    let mut new_ssz_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(witness.mutations.len());

    for mutation in &witness.mutations {
        let idx = mutation.validator_index;

        let new_field_leaves = compute_validator_field_leaves(&mutation.new_data);

        if mutation.is_new {
            // New validator: old leaf is all-zeros in both SSZ and Poseidon trees
            let zero_leaf = [0u8; 32];
            old_ssz_leaves.push((zero_leaf, idx));

            // Verify Poseidon: old leaf is zero
            let computed_old_root =
                compute_poseidon_merkle_root(&zero_leaf, idx, &mutation.poseidon_siblings);
            assert_eq!(
                computed_old_root, poseidon_root,
                "Poseidon root mismatch before new validator {}",
                idx
            );

            let new_validator_root = validator_hash_tree_root(&new_field_leaves);
            new_ssz_leaves.push((new_validator_root, idx));
        } else {
            let old_field_leaves = compute_validator_field_leaves(&mutation.old_data);

            // Ensure pubkey didn't change for existing validator
            assert_eq!(
                old_field_leaves[0], new_field_leaves[0],
                "pubkey leaf changed for existing validator {}",
                idx
            );

            // -- Compute old + new HTR, sharing work for identical subtrees --
            let (old_validator_root, new_validator_root) = validator_hash_tree_root_pair(
                &old_field_leaves,
                &new_field_leaves,
            );
            old_ssz_leaves.push((old_validator_root, idx));
            new_ssz_leaves.push((new_validator_root, idx));

            // -- Verify and update Poseidon accumulator (old) --
            let old_active_balance = mutation.old_data.active_effective_balance(epoch_old);
            let old_poseidon = poseidon_leaf(&mutation.old_data.pubkey.0, old_active_balance);
            let computed_old_root =
                compute_poseidon_merkle_root(&old_poseidon, idx, &mutation.poseidon_siblings);
            assert_eq!(
                computed_old_root, poseidon_root,
                "Poseidon root mismatch before mutation {}",
                idx
            );
        }

        // -- Update Poseidon accumulator (new) --
        let new_active_balance = mutation.new_data.active_effective_balance(epoch_new);
        let new_poseidon = poseidon_leaf(&mutation.new_data.pubkey.0, new_active_balance);
        poseidon_root =
            compute_poseidon_merkle_root(&new_poseidon, idx, &mutation.poseidon_siblings);

        // -- Balance delta --
        let old_active_balance = if mutation.is_new {
            0
        } else {
            mutation.old_data.active_effective_balance(epoch_old)
        };
        total_active_balance = total_active_balance - old_active_balance + new_active_balance;
    }

    // Phase 2: SSZ multi-proof verification
    let ssz_data_root_1 = verify_ssz_multi_proof(&old_ssz_leaves, &witness.ssz_multi_proof_1, ssz_depth);
    let ssz_data_root_2 = verify_ssz_multi_proof(&new_ssz_leaves, &witness.ssz_multi_proof_2, ssz_depth);

    // -- Verify SSZ data tree roots link to state roots --
    let validators_field_index = zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;

    let validators_root_1 = list_hash_tree_root(&ssz_data_root_1, witness.validators_list_length_1);
    let computed_state_root_1 = compute_ssz_merkle_root(
        &validators_root_1,
        validators_field_index,
        &witness.state_to_validators_siblings_1,
    );
    assert_eq!(
        computed_state_root_1, witness.state_root_1,
        "state_root_1 mismatch"
    );

    let validators_root_2 = list_hash_tree_root(&ssz_data_root_2, witness.validators_list_length_2);
    let computed_state_root_2 = compute_ssz_merkle_root(
        &validators_root_2,
        validators_field_index,
        &witness.state_to_validators_siblings_2,
    );
    assert_eq!(
        computed_state_root_2, witness.state_root_2,
        "state_root_2 mismatch"
    );

    let commitment =
        zkasper_common::poseidon::accumulator_commitment(&poseidon_root, total_active_balance);

    (commitment, poseidon_root, total_active_balance)
}
