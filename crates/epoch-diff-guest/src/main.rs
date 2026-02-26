// Zisk guest program: Proof 1 — Epoch Diff
//
// Verifies that the Poseidon accumulator was correctly updated between two
// consecutive beacon states. For each validator mutation, the circuit:
//   1. Verifies old/new validator data against the SSZ trees
//   2. Verifies/updates the Poseidon accumulator leaf
//   3. Tracks the total active balance delta
//
// On Zisk this file would use:
//   #![no_main]
//   ziskos::entrypoint!(main);
//
// For now we keep it as a normal binary for native testing.

use zkasper_common::types::EpochDiffWitness;

fn main() {
    // In Zisk: let input = ziskos::read_input_slice();
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: EpochDiffWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (poseidon_root, total_active_balance) = verify_epoch_diff(&witness);

    // In Zisk: write via set_output
    eprintln!("poseidon_root_2: {:x?}", poseidon_root);
    eprintln!("total_active_balance_2: {}", total_active_balance);
}

/// Core epoch-diff verification logic. Returns (new_poseidon_root, new_total_active_balance).
pub fn verify_epoch_diff(witness: &EpochDiffWitness) -> ([u8; 32], u64) {
    use zkasper_common::poseidon::{compute_poseidon_merkle_root, poseidon_leaf};
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
    };

    let mut poseidon_root = witness.poseidon_root_1;
    let mut total_active_balance = witness.total_active_balance_1;
    let epoch_old = witness.epoch_2 - 1;
    let epoch_new = witness.epoch_2;

    let mut ssz_data_root_1: Option<[u8; 32]> = None;
    let mut ssz_data_root_2: Option<[u8; 32]> = None;

    for mutation in &witness.mutations {
        let idx = mutation.validator_index;

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

        // -- Verify and update Poseidon accumulator --
        let old_active_balance = mutation.old_data.active_effective_balance(epoch_old);
        let old_poseidon = poseidon_leaf(&mutation.old_data.pubkey.0, old_active_balance);
        let computed_old_root =
            compute_poseidon_merkle_root(&old_poseidon, idx, &mutation.poseidon_siblings);
        assert_eq!(
            computed_old_root, poseidon_root,
            "Poseidon root mismatch before mutation {}",
            idx
        );

        let new_active_balance = mutation.new_data.active_effective_balance(epoch_new);
        let new_poseidon = poseidon_leaf(&mutation.new_data.pubkey.0, new_active_balance);
        poseidon_root =
            compute_poseidon_merkle_root(&new_poseidon, idx, &mutation.poseidon_siblings);

        // -- Balance delta --
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

    (poseidon_root, total_active_balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::poseidon::poseidon_leaf;
    use zkasper_common::ssz::{list_hash_tree_root, sha256_pair, validator_hash_tree_root};
    use zkasper_common::test_utils::*;
    use zkasper_common::types::*;

    /// Build a fake "state root" from a validators data tree root, list length,
    /// and a set of sibling hashes for the top-level BeaconState tree.
    /// Returns (state_root, siblings).
    fn make_state_proof(data_tree_root: &[u8; 32], list_length: u64) -> ([u8; 32], Vec<[u8; 32]>) {
        let validators_root = list_hash_tree_root(data_tree_root, list_length);

        // Fake a depth-5 BeaconState tree where field 11 is `validators`.
        // We just need the siblings along the path from index 11 to root.
        // For simplicity, fill siblings with deterministic junk.
        let depth = 5;
        let mut siblings = Vec::with_capacity(depth);
        let mut current = validators_root;
        let mut idx = BEACON_STATE_VALIDATORS_FIELD_INDEX;

        for d in 0..depth {
            let mut sibling = [0u8; 32];
            sibling[0] = d as u8;
            sibling[1] = 0xBE;
            siblings.push(sibling);

            if idx & 1 == 0 {
                current = sha256_pair(&current, &sibling);
            } else {
                current = sha256_pair(&sibling, &current);
            }
            idx >>= 1;
        }

        (current, siblings)
    }

    #[test]
    fn test_epoch_diff_single_mutation() {
        // 4 validators, tree depth 2. Validator 1 changes balance from 32 -> 16 ETH.
        let depth = 2u32;
        let epoch_old = 100u64;
        let epoch_new = 101u64;

        let v0 = make_validator(0, 32);
        let v1_old = make_validator(1, 32);
        let v1_new = ValidatorData {
            effective_balance: 16_000_000_000,
            ..make_validator(1, 32)
        };
        let v2 = make_validator(2, 32);
        let v3 = make_validator(3, 32);

        // SSZ tree 1 (old state)
        let old_roots: Vec<_> = [&v0, &v1_old, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();
        let (old_data_root, old_ssz_siblings) = build_ssz_tree(&old_roots, depth);

        // SSZ tree 2 (new state) — only v1 changed
        let new_roots: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();
        let (new_data_root, new_ssz_siblings) = build_ssz_tree(&new_roots, depth);

        // Poseidon tree (old state)
        let old_poseidon_leaves: Vec<_> = [&v0, &v1_old, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_old)))
            .collect();
        let (old_poseidon_root, poseidon_siblings) =
            build_poseidon_tree(&old_poseidon_leaves, depth);

        // Compute expected new Poseidon root
        let new_poseidon_leaves: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_new)))
            .collect();
        let (expected_new_poseidon_root, _) = build_poseidon_tree(&new_poseidon_leaves, depth);

        // Build state proofs
        let num_validators = 4u64;
        let (state_root_1, state_siblings_1) = make_state_proof(&old_data_root, num_validators);
        let (state_root_2, state_siblings_2) = make_state_proof(&new_data_root, num_validators);

        let mutation = ValidatorMutation {
            validator_index: 1,
            old_data: v1_old.clone(),
            new_data: v1_new.clone(),
            old_field_leaves: make_field_leaves(&v1_old),
            new_field_leaves: make_field_leaves(&v1_new),
            old_pubkey_chunks: make_pubkey_chunks(&v1_old),
            new_pubkey_chunks: make_pubkey_chunks(&v1_new),
            old_ssz_siblings: old_ssz_siblings[1].clone(),
            new_ssz_siblings: new_ssz_siblings[1].clone(),
            poseidon_siblings: poseidon_siblings[1].clone(),
        };

        let total_old = 4 * 32_000_000_000u64;

        let witness = EpochDiffWitness {
            state_root_1,
            state_root_2,
            poseidon_root_1: old_poseidon_root,
            total_active_balance_1: total_old,
            epoch_2: epoch_new,
            state_to_validators_siblings_1: state_siblings_1,
            state_to_validators_siblings_2: state_siblings_2,
            validators_list_length_1: num_validators,
            validators_list_length_2: num_validators,
            mutations: vec![mutation],
        };

        let (new_poseidon_root, new_total_balance) = verify_epoch_diff(&witness);

        assert_eq!(new_poseidon_root, expected_new_poseidon_root);
        assert_eq!(
            new_total_balance,
            3 * 32_000_000_000 + 16_000_000_000 // v0,v2,v3 at 32 ETH + v1 at 16 ETH
        );
    }
}
