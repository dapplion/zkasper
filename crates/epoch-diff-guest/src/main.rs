// Zisk guest program: Proof 1 — Epoch Diff
//
// Verifies that the Poseidon accumulator was correctly updated between two
// consecutive beacon states. For each validator mutation, the circuit:
//   1. Verifies old/new validator data against the SSZ trees
//   2. Verifies/updates the Poseidon accumulator leaf
//   3. Tracks the total active balance delta
#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_common::types::EpochDiffWitness;
use zkasper_epoch_diff_guest::verify_epoch_diff;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    #[cfg(target_os = "zkvm")]
    let input = ziskos::read_input_slice();
    #[cfg(not(target_os = "zkvm"))]
    let input = std::fs::read("input.bin").expect("read input.bin");

    let witness: EpochDiffWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (commitment, _poseidon_root, _total_active_balance) = verify_epoch_diff(&witness);

    // Public outputs: [commitment(8), state_root_1(8), state_root_2(8)]
    #[cfg(target_os = "zkvm")]
    {
        write_bytes32_output(0, &commitment);
        write_bytes32_output(8, &witness.state_root_1);
        write_bytes32_output(16, &witness.state_root_2);
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        eprintln!("accumulator_commitment_2: {:x?}", commitment);
        eprintln!("state_root_1: {:x?}", witness.state_root_1);
        eprintln!("state_root_2: {:x?}", witness.state_root_2);
    }
}

#[cfg(target_os = "zkvm")]
fn write_bytes32_output(offset: usize, bytes: &[u8; 32]) {
    for i in 0..8usize {
        let b = i * 4;
        let word = u32::from_le_bytes([bytes[b], bytes[b + 1], bytes[b + 2], bytes[b + 3]]);
        ziskos::set_output(offset + i, word);
    }
}

#[cfg(test)]
mod tests {
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::poseidon::poseidon_leaf;
    use zkasper_common::ssz::{
        compute_validator_field_leaves, list_hash_tree_root, sha256_pair, validator_hash_tree_root,
    };
    use zkasper_common::test_utils::*;
    use zkasper_common::types::*;
    use zkasper_epoch_diff_guest::verify_epoch_diff_with_depth;

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
        use zkasper_common::constants::VALIDATORS_TREE_DEPTH;
        let ssz_depth = VALIDATORS_TREE_DEPTH;
        let poseidon_depth = 4u32; // small depth for 4 validators
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
            .map(|v| validator_hash_tree_root(&compute_validator_field_leaves(v)))
            .collect();
        let (old_data_root, ssz_multi_proof_1) =
            build_ssz_tree_multi_proof(&old_roots, ssz_depth, &[1]);

        let new_roots: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&compute_validator_field_leaves(v)))
            .collect();
        let (new_data_root, ssz_multi_proof_2) =
            build_ssz_tree_multi_proof(&new_roots, ssz_depth, &[1]);

        let old_poseidon_leaves: Vec<_> = [&v0, &v1_old, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_old)))
            .collect();
        let (old_poseidon_root, poseidon_siblings) =
            build_poseidon_tree(&old_poseidon_leaves, poseidon_depth);

        let new_poseidon_leaves: Vec<_> = [&v0, &v1_new, &v2, &v3]
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_new)))
            .collect();
        let (expected_new_poseidon_root, _) =
            build_poseidon_tree(&new_poseidon_leaves, poseidon_depth);

        let num_validators = 4u64;
        let (state_root_1, state_siblings_1) = make_state_proof(&old_data_root, num_validators);
        let (state_root_2, state_siblings_2) = make_state_proof(&new_data_root, num_validators);

        let mutation = ValidatorMutation {
            validator_index: 1,
            is_new: false,
            old_data: v1_old,
            new_data: v1_new,
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
            ssz_multi_proof_1,
            ssz_multi_proof_2,
        };

        let (commitment, new_poseidon_root, new_total_balance) =
            verify_epoch_diff_with_depth(&witness, ssz_depth, poseidon_depth);

        assert_eq!(new_poseidon_root, expected_new_poseidon_root);
        let expected_total = 3 * 32_000_000_000 + 16_000_000_000;
        assert_eq!(new_total_balance, expected_total);
        assert_eq!(
            commitment,
            zkasper_common::poseidon::accumulator_commitment(&new_poseidon_root, expected_total)
        );
    }
}
