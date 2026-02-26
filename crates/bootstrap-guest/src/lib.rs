// Re-export verification functions for use by integration tests and other crates.

use zkasper_common::poseidon::{accumulator_commitment, poseidon_leaf, poseidon_pair};
use zkasper_common::ssz::{
    compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
};
use zkasper_common::types::BootstrapWitness;

/// Core bootstrap verification logic. Returns (accumulator_commitment, poseidon_root, total_active_balance).
pub fn verify_bootstrap(witness: &BootstrapWitness) -> ([u8; 32], [u8; 32], u64) {
    verify_bootstrap_with_depth(witness, zkasper_common::constants::VALIDATORS_TREE_DEPTH)
}

/// Bootstrap verification with a configurable tree depth (for testing with small trees).
pub fn verify_bootstrap_with_depth(
    witness: &BootstrapWitness,
    depth: u32,
) -> ([u8; 32], [u8; 32], u64) {
    let num_validators = witness.validators.len();
    let mut total_active_balance: u64 = 0;
    let mut validator_roots = Vec::with_capacity(num_validators);
    let mut poseidon_leaves = Vec::with_capacity(num_validators);

    for i in 0..num_validators {
        verify_field_leaves(
            &witness.validators[i],
            &witness.validator_field_chunks[i],
            &witness.validator_pubkey_chunks[i],
        );

        let root = validator_hash_tree_root(&witness.validator_field_chunks[i]);
        validator_roots.push(root);

        let active_balance = witness.validators[i].active_effective_balance(witness.epoch);
        let p_leaf = poseidon_leaf(&witness.validators[i].pubkey.0, active_balance);
        poseidon_leaves.push(p_leaf);

        total_active_balance += active_balance;
    }

    let ssz_data_root = rebuild_tree(&validator_roots, zkasper_common::ssz::sha256_pair, depth);
    let validators_root = list_hash_tree_root(&ssz_data_root, num_validators as u64);
    let computed_state_root = compute_ssz_merkle_root(
        &validators_root,
        zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX,
        &witness.state_to_validators_siblings,
    );
    assert_eq!(
        computed_state_root, witness.state_root,
        "state root mismatch"
    );

    let poseidon_root = rebuild_tree(&poseidon_leaves, poseidon_pair, depth);
    let commitment = accumulator_commitment(&poseidon_root, total_active_balance);

    (commitment, poseidon_root, total_active_balance)
}

/// Generic bottom-up Merkle tree rebuild with zero-hash padding.
fn rebuild_tree(
    leaves: &[[u8; 32]],
    hash_pair: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    depth: u32,
) -> [u8; 32] {
    let capacity = 1u64 << depth;

    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = hash_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let mut current_level: Vec<[u8; 32]> = Vec::with_capacity(leaves.len());
    current_level.extend_from_slice(leaves);

    #[allow(clippy::needless_range_loop)]
    for d in 0..depth as usize {
        let level_size = (capacity >> d) as usize;
        let parent_count = level_size / 2;
        let mut next_level = Vec::with_capacity(parent_count);

        for i in 0..parent_count {
            let left_idx = i * 2;
            let right_idx = left_idx + 1;

            let left = if left_idx < current_level.len() {
                current_level[left_idx]
            } else {
                zero_hashes[d]
            };
            let right = if right_idx < current_level.len() {
                current_level[right_idx]
            } else {
                zero_hashes[d]
            };

            next_level.push(hash_pair(&left, &right));
        }

        current_level = next_level;
    }

    assert_eq!(current_level.len(), 1);
    current_level[0]
}
