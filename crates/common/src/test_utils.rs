//! Test helpers for building synthetic witness data.

use alloc::vec;
use alloc::vec::Vec;

use crate::poseidon::poseidon_pair;
use crate::ssz::{sha256_pair, u64_to_chunk};
use crate::types::*;

/// Create a dummy validator with deterministic data.
pub fn make_validator(index: u8, balance_eth: u64) -> ValidatorData {
    let mut pubkey = [0u8; 48];
    pubkey[0] = index;
    pubkey[1] = index.wrapping_mul(7);
    ValidatorData {
        pubkey: BlsPubkey(pubkey),
        effective_balance: balance_eth * 1_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

/// Build the 8 SSZ field leaves for a validator.
/// Leaves 1, 3, 4, 7 (opaque fields) are filled with deterministic junk.
pub fn make_field_leaves(data: &ValidatorData) -> [[u8; 32]; 8] {
    let pubkey_chunks = make_pubkey_chunks(data);
    let pubkey_leaf = sha256_pair(&pubkey_chunks[0], &pubkey_chunks[1]);

    let mut withdrawal_creds = [0u8; 32];
    withdrawal_creds[0] = 0x01; // ETH1 withdrawal prefix
    let slashed = [0u8; 32]; // not slashed
    let activation_eligibility = u64_to_chunk(0);
    let withdrawable_epoch = u64_to_chunk(u64::MAX);

    [
        pubkey_leaf,
        withdrawal_creds,
        u64_to_chunk(data.effective_balance),
        slashed,
        activation_eligibility,
        u64_to_chunk(data.activation_epoch),
        u64_to_chunk(data.exit_epoch),
        withdrawable_epoch,
    ]
}

/// Split pubkey into 2x32-byte SSZ chunks.
pub fn make_pubkey_chunks(data: &ValidatorData) -> [[u8; 32]; 2] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&data.pubkey.0[..32]);
    chunk1[..16].copy_from_slice(&data.pubkey.0[32..48]);
    [chunk0, chunk1]
}

/// Build a small Merkle tree (SHA-256) from validator roots and return
/// (data_tree_root, siblings_per_leaf).
pub fn build_ssz_tree(
    validator_roots: &[[u8; 32]],
    depth: u32,
) -> (
    [u8; 32],
    Vec<Vec<[u8; 32]>>, // siblings[leaf_index] = vec of siblings
) {
    let capacity = 1usize << depth;

    // Precompute zero hashes
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = sha256_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    // Build levels
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();

    // Level 0: leaves
    let mut leaves = vec![[0u8; 32]; capacity];
    for (i, root) in validator_roots.iter().enumerate() {
        leaves[i] = *root;
    }
    // Fill remaining with zero_hashes[0]
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

    // Extract siblings for each leaf
    let mut all_siblings = Vec::new();
    for leaf_idx in 0..validator_roots.len() {
        let mut siblings = Vec::with_capacity(depth as usize);
        let mut idx = leaf_idx;
        for level in levels.iter().take(depth as usize) {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx >>= 1;
        }
        all_siblings.push(siblings);
    }

    (root, all_siblings)
}

/// Build a small Poseidon Merkle tree from leaves and return
/// (root, siblings_per_leaf).
pub fn build_poseidon_tree(
    poseidon_leaves: &[[u8; 32]],
    depth: u32,
) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let capacity = 1usize << depth;

    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = poseidon_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; capacity];
    for (i, leaf) in poseidon_leaves.iter().enumerate() {
        leaves[i] = *leaf;
    }
    levels.push(leaves);

    for d in 0..depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(poseidon_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    let root = levels[depth as usize][0];

    let mut all_siblings = Vec::new();
    for leaf_idx in 0..poseidon_leaves.len() {
        let mut siblings = Vec::with_capacity(depth as usize);
        let mut idx = leaf_idx;
        for level in levels.iter().take(depth as usize) {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx >>= 1;
        }
        all_siblings.push(siblings);
    }

    (root, all_siblings)
}
