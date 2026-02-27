// Re-export verification functions for use by integration tests and other crates.

use zkasper_common::types::EpochDiffWitness;

/// Core epoch-diff verification logic. Returns (new_accumulator_commitment, new_poseidon_root, new_total_active_balance).
pub fn verify_epoch_diff(witness: &EpochDiffWitness) -> ([u8; 32], [u8; 32], u64) {
    use zkasper_common::poseidon::{compute_poseidon_merkle_root, poseidon_leaf};
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
    };

    let mut poseidon_root = witness.poseidon_root_1;
    let mut total_active_balance = witness.total_active_balance_1;
    let epoch_old = witness.epoch_1;
    let epoch_new = witness.epoch_2;

    let mut ssz_data_root_1: Option<[u8; 32]> = None;
    let mut ssz_data_root_2: Option<[u8; 32]> = None;

    for mutation in &witness.mutations {
        let idx = mutation.validator_index;

        if mutation.is_new {
            // New validator: old leaf is all-zeros in both SSZ and Poseidon trees
            let zero_leaf = [0u8; 32];
            let old_data_root =
                compute_ssz_merkle_root(&zero_leaf, idx, &mutation.old_ssz_siblings);

            match ssz_data_root_1 {
                None => ssz_data_root_1 = Some(old_data_root),
                Some(r) => assert_eq!(r, old_data_root, "SSZ data root 1 mismatch (new validator)"),
            }

            // Verify Poseidon: old leaf is zero
            let computed_old_root =
                compute_poseidon_merkle_root(&zero_leaf, idx, &mutation.poseidon_siblings);
            assert_eq!(
                computed_old_root, poseidon_root,
                "Poseidon root mismatch before new validator {}",
                idx
            );
        } else {
            // -- Verify old validator against SSZ tree 1 --
            verify_field_leaves(
                &mutation.old_data,
                &mutation.old_field_leaves,
                &mutation.old_pubkey_chunks,
            );
            let old_validator_root = validator_hash_tree_root(&mutation.old_field_leaves);
            let old_data_root =
                compute_ssz_merkle_root(&old_validator_root, idx, &mutation.old_ssz_siblings);

            match ssz_data_root_1 {
                None => ssz_data_root_1 = Some(old_data_root),
                Some(r) => assert_eq!(r, old_data_root, "SSZ data root 1 mismatch"),
            }

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

        // -- Verify new validator against SSZ tree 2 --
        verify_field_leaves(
            &mutation.new_data,
            &mutation.new_field_leaves,
            &mutation.new_pubkey_chunks,
        );
        let new_validator_root = validator_hash_tree_root(&mutation.new_field_leaves);
        let new_data_root =
            compute_ssz_merkle_root(&new_validator_root, idx, &mutation.new_ssz_siblings);

        match ssz_data_root_2 {
            None => ssz_data_root_2 = Some(new_data_root),
            Some(r) => assert_eq!(r, new_data_root, "SSZ data root 2 mismatch"),
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

    // -- Verify SSZ data tree roots link to state roots --
    let ssz_data_root_1 = ssz_data_root_1.expect("no mutations");
    let ssz_data_root_2 = ssz_data_root_2.expect("no mutations");

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
