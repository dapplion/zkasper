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
use zkasper_epoch_diff_guest::verify_epoch_diff;

fn main() {
    // In Zisk: let input = ziskos::read_input_slice();
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: EpochDiffWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (commitment, poseidon_root, total_active_balance) = verify_epoch_diff(&witness);

    // In Zisk: write via set_output
    eprintln!("accumulator_commitment_2: {:x?}", commitment);
    eprintln!("poseidon_root_2: {:x?}", poseidon_root);
    eprintln!("total_active_balance_2: {}", total_active_balance);
}

#[cfg(test)]
mod tests {
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::poseidon::poseidon_leaf;
    use zkasper_common::ssz::{list_hash_tree_root, sha256_pair, validator_hash_tree_root};
    use zkasper_common::test_utils::*;
    use zkasper_common::types::*;
    use zkasper_epoch_diff_guest::verify_epoch_diff;

    fn make_state_proof(data_tree_root: &[u8; 32], list_length: u64) -> ([u8; 32], Vec<[u8; 32]>) {
        let validators_root = list_hash_tree_root(data_tree_root, list_length);
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

        let old_roots: Vec<_> = [&v0, &v1_old, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();
        let (old_data_root, old_ssz_siblings) = build_ssz_tree(&old_roots, depth);

        let new_roots: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();
        let (new_data_root, new_ssz_siblings) = build_ssz_tree(&new_roots, depth);

        let old_poseidon_leaves: Vec<_> = [&v0, &v1_old, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_old)))
            .collect();
        let (old_poseidon_root, poseidon_siblings) =
            build_poseidon_tree(&old_poseidon_leaves, depth);

        let new_poseidon_leaves: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_new)))
            .collect();
        let (expected_new_poseidon_root, _) = build_poseidon_tree(&new_poseidon_leaves, depth);

        let num_validators = 4u64;
        let (state_root_1, state_siblings_1) = make_state_proof(&old_data_root, num_validators);
        let (state_root_2, state_siblings_2) = make_state_proof(&new_data_root, num_validators);

        let mutation = ValidatorMutation {
            validator_index: 1,
            is_new: false,
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
            epoch_1: epoch_old,
            epoch_2: epoch_new,
            state_to_validators_siblings_1: state_siblings_1,
            state_to_validators_siblings_2: state_siblings_2,
            validators_list_length_1: num_validators,
            validators_list_length_2: num_validators,
            mutations: vec![mutation],
        };

        let (commitment, new_poseidon_root, new_total_balance) = verify_epoch_diff(&witness);

        assert_eq!(new_poseidon_root, expected_new_poseidon_root);
        let expected_total = 3 * 32_000_000_000 + 16_000_000_000;
        assert_eq!(new_total_balance, expected_total);
        assert_eq!(
            commitment,
            zkasper_common::poseidon::accumulator_commitment(&new_poseidon_root, expected_total)
        );
    }
}
