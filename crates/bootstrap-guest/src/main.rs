// Zisk guest program: Bootstrap
//
// One-time construction of the Poseidon accumulator from the full validator set.
// Verifies all validators against the SSZ state, builds the Poseidon tree,
// and outputs the root + total active balance.
//
// On Zisk this file would use:
//   #![no_main]
//   ziskos::entrypoint!(main);

use zkasper_common::poseidon::{poseidon_leaf, poseidon_pair};
use zkasper_common::ssz::{
    compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
};
use zkasper_common::types::BootstrapWitness;

fn main() {
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: BootstrapWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (poseidon_root, total_active_balance) = verify_bootstrap(&witness);

    eprintln!("poseidon_root: {:x?}", poseidon_root);
    eprintln!("total_active_balance: {}", total_active_balance);
}

/// Core bootstrap verification logic. Returns (poseidon_root, total_active_balance).
pub fn verify_bootstrap(witness: &BootstrapWitness) -> ([u8; 32], u64) {
    verify_bootstrap_with_depth(witness, zkasper_common::constants::VALIDATORS_TREE_DEPTH)
}

/// Bootstrap verification with a configurable tree depth (for testing with small trees).
pub fn verify_bootstrap_with_depth(witness: &BootstrapWitness, depth: u32) -> ([u8; 32], u64) {
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

    let ssz_data_root = rebuild_tree_sha256(&validator_roots, depth);
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

    let poseidon_root = rebuild_tree_poseidon(&poseidon_leaves, depth);

    (poseidon_root, total_active_balance)
}

/// Rebuild a SHA-256 Merkle tree bottom-up from leaves.
/// Pads to next power of 2 with zero hashes.
fn rebuild_tree_sha256(leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
    use zkasper_common::ssz::sha256_pair;
    rebuild_tree(leaves, sha256_pair, depth)
}

/// Rebuild a Poseidon Merkle tree bottom-up from leaves.
fn rebuild_tree_poseidon(leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
    rebuild_tree(leaves, poseidon_pair, depth)
}

/// Generic bottom-up Merkle tree rebuild with zero-hash padding.
fn rebuild_tree(
    leaves: &[[u8; 32]],
    hash_pair: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    depth: u32,
) -> [u8; 32] {
    let capacity = 1u64 << depth;

    // Precompute zero hashes: zero_hash[d] = hash(zero_hash[d-1], zero_hash[d-1])
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = hash_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    // Build level by level
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

#[cfg(test)]
mod tests {
    use super::*;
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::ssz::{list_hash_tree_root, sha256_pair};
    use zkasper_common::test_utils::*;
    use zkasper_common::types::*;

    /// Build a fake state root from a validators data tree root.
    /// Same helper pattern as the epoch-diff test.
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
    fn test_bootstrap_4_validators() {
        let depth = 2u32;
        let epoch = 100u64;
        let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();

        let field_chunks: Vec<_> = validators.iter().map(make_field_leaves).collect();
        let pubkey_chunks: Vec<_> = validators.iter().map(make_pubkey_chunks).collect();

        // Build expected SSZ data tree root
        let validator_roots: Vec<_> = field_chunks.iter().map(validator_hash_tree_root).collect();
        let ssz_data_root = rebuild_tree_sha256(&validator_roots, depth);

        // Build expected Poseidon tree root
        let poseidon_leaves_vec: Vec<_> = validators
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch)))
            .collect();
        let expected_poseidon_root = rebuild_tree_poseidon(&poseidon_leaves_vec, depth);

        let num_validators = 4u64;
        let (state_root, state_siblings) = make_state_proof(&ssz_data_root, num_validators);

        let witness = BootstrapWitness {
            state_root,
            epoch,
            validators: validators.clone(),
            state_to_validators_siblings: state_siblings,
            validators_list_length: num_validators,
            validator_field_chunks: field_chunks,
            validator_pubkey_chunks: pubkey_chunks,
        };

        let (poseidon_root, total_active_balance) = verify_bootstrap_with_depth(&witness, depth);

        assert_eq!(poseidon_root, expected_poseidon_root);
        assert_eq!(total_active_balance, 4 * 32_000_000_000);
    }

    #[test]
    fn test_bootstrap_mixed_validators() {
        let depth = 2u32;
        let epoch = 100u64;
        let v0 = make_validator(0, 32);
        let v1 = make_validator(1, 32);
        // v2 has exited before epoch 100 → active_effective_balance = 0
        let v2 = ValidatorData {
            exit_epoch: 50,
            ..make_validator(2, 32)
        };
        let v3 = make_validator(3, 16);
        let validators = vec![v0, v1, v2, v3];

        let field_chunks: Vec<_> = validators.iter().map(make_field_leaves).collect();
        let pubkey_chunks: Vec<_> = validators.iter().map(make_pubkey_chunks).collect();

        let validator_roots: Vec<_> = field_chunks.iter().map(validator_hash_tree_root).collect();
        let ssz_data_root = rebuild_tree_sha256(&validator_roots, depth);

        let num_validators = 4u64;
        let (state_root, state_siblings) = make_state_proof(&ssz_data_root, num_validators);

        let witness = BootstrapWitness {
            state_root,
            epoch,
            validators: validators.clone(),
            state_to_validators_siblings: state_siblings,
            validators_list_length: num_validators,
            validator_field_chunks: field_chunks,
            validator_pubkey_chunks: pubkey_chunks,
        };

        let (_, total_active_balance) = verify_bootstrap_with_depth(&witness, depth);

        // v0: 32 ETH, v1: 32 ETH, v2: exited so 0 ETH, v3: 16 ETH
        assert_eq!(
            total_active_balance,
            32_000_000_000 + 32_000_000_000 + 16_000_000_000
        );
    }
}
