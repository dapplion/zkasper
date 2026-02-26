//! Diff two beacon state validator registries and produce SSZ Merkle proofs.

use std::collections::HashMap;

use zkasper_common::ssz::{sha256_pair, u64_to_chunk, validator_hash_tree_root};
use zkasper_common::types::{BlsPubkey, ValidatorData};

use crate::beacon_api::ValidatorResponse;

// ---------------------------------------------------------------------------
// Validator response → common types conversions
// ---------------------------------------------------------------------------

/// Convert a beacon API validator response into the minimal `ValidatorData`.
pub fn validator_response_to_data(v: &ValidatorResponse) -> ValidatorData {
    ValidatorData {
        pubkey: BlsPubkey(v.pubkey),
        effective_balance: v.effective_balance,
        activation_epoch: v.activation_epoch,
        exit_epoch: v.exit_epoch,
    }
}

/// Build the 8 SSZ field leaves for a validator from the full API response.
///
/// SSZ Validator container field layout (8 fields):
/// ```text
/// leaf[0] = sha256(pubkey[0..32] || pubkey[32..48]++zeros)
/// leaf[1] = withdrawal_credentials (32 bytes, opaque)
/// leaf[2] = le_pad32(effective_balance)
/// leaf[3] = le_pad32(slashed)
/// leaf[4] = le_pad32(activation_eligibility_epoch)
/// leaf[5] = le_pad32(activation_epoch)
/// leaf[6] = le_pad32(exit_epoch)
/// leaf[7] = le_pad32(withdrawable_epoch)
/// ```
pub fn validator_response_to_field_leaves(v: &ValidatorResponse) -> [[u8; 32]; 8] {
    let chunks = validator_response_to_pubkey_chunks(v);
    let pubkey_leaf = sha256_pair(&chunks[0], &chunks[1]);

    [
        pubkey_leaf,
        v.withdrawal_credentials,
        u64_to_chunk(v.effective_balance),
        u64_to_chunk(if v.slashed { 1 } else { 0 }),
        u64_to_chunk(v.activation_eligibility_epoch),
        u64_to_chunk(v.activation_epoch),
        u64_to_chunk(v.exit_epoch),
        u64_to_chunk(v.withdrawable_epoch),
    ]
}

/// Split a 48-byte pubkey into 2×32-byte SSZ chunks.
pub fn validator_response_to_pubkey_chunks(v: &ValidatorResponse) -> [[u8; 32]; 2] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&v.pubkey[..32]);
    chunk1[..16].copy_from_slice(&v.pubkey[32..48]);
    [chunk0, chunk1]
}

// ---------------------------------------------------------------------------
// Registry diffing
// ---------------------------------------------------------------------------

/// Find indices of validators that changed between two registries.
///
/// A validator is considered "changed" if any of its mutable fields differ.
/// New validators (present in `new` but not `old`) are also returned.
pub fn find_mutations(
    old_validators: &[ValidatorResponse],
    new_validators: &[ValidatorResponse],
) -> Vec<u64> {
    let mut changed = Vec::new();

    // Compare overlapping validators
    for i in 0..old_validators.len().min(new_validators.len()) {
        let old = &old_validators[i];
        let new = &new_validators[i];
        if old.effective_balance != new.effective_balance
            || old.activation_epoch != new.activation_epoch
            || old.exit_epoch != new.exit_epoch
            || old.slashed != new.slashed
            || old.activation_eligibility_epoch != new.activation_eligibility_epoch
            || old.withdrawable_epoch != new.withdrawable_epoch
        {
            changed.push(i as u64);
        }
    }

    // New validators (registry grew)
    for i in old_validators.len()..new_validators.len() {
        changed.push(i as u64);
    }

    changed
}

// ---------------------------------------------------------------------------
// SSZ tree building
// ---------------------------------------------------------------------------

/// Build a full SHA-256 Merkle tree from validator roots and extract siblings
/// for the requested leaf indices.
///
/// Returns `(data_tree_root, index → siblings)`.
pub fn build_validators_ssz_tree(
    validator_roots: &[[u8; 32]],
    depth: u32,
    extract_indices: &[u64],
) -> ([u8; 32], HashMap<u64, Vec<[u8; 32]>>) {
    let capacity = 1usize << depth;

    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    // Build levels bottom-up
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; capacity];
    for (i, root) in validator_roots.iter().enumerate() {
        leaves[i] = *root;
    }
    levels.push(leaves);

    for d in 0..depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(sha256_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    let root = levels[depth as usize][0];

    // Extract siblings for requested indices
    let mut result = HashMap::new();
    for &leaf_idx in extract_indices {
        let mut siblings = Vec::with_capacity(depth as usize);
        let mut idx = leaf_idx as usize;
        for level in levels.iter().take(depth as usize) {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx >>= 1;
        }
        result.insert(leaf_idx, siblings);
    }

    (root, result)
}

/// Build all validator roots from API responses.
pub fn build_validator_roots(validators: &[ValidatorResponse]) -> Vec<[u8; 32]> {
    validators
        .iter()
        .map(|v| validator_hash_tree_root(&validator_response_to_field_leaves(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// State proof (BeaconState top-level tree)
// ---------------------------------------------------------------------------

/// Build a synthetic state proof from a validators data tree root.
///
/// Computes `validators_root = list_hash_tree_root(data_root, length)`,
/// then walks up a depth-5 BeaconState container tree at field index 11,
/// returning `(state_root, siblings)`.
///
/// The siblings are deterministic placeholders. For production use with a
/// real beacon node, these would be extracted from the full SSZ state.
pub fn make_state_proof(data_tree_root: &[u8; 32], list_length: u64) -> ([u8; 32], Vec<[u8; 32]>) {
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::ssz::list_hash_tree_root;

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
