/// Compute a Merkle root from a leaf, its index, and sibling hashes,
/// using the provided pair-hash function.
pub fn compute_root(
    hash_pair: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut current = *leaf;
    let mut idx = index;
    for sibling in siblings {
        if idx & 1 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        idx >>= 1;
    }
    current
}

/// Verify that a leaf at `index` with the given `siblings` produces `expected_root`.
pub fn verify_proof(
    hash_pair: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    compute_root(hash_pair, leaf, index, siblings) == *expected_root
}

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::types::MerkleMultiProof;

/// Verify multiple leaves against a single root using a multi-proof.
///
/// `leaves` is a slice of `(leaf_hash, leaf_index)` pairs.
/// Returns the computed root.
///
/// The algorithm walks bottom-up: at each level it collects the parent
/// indices that need to be computed, looks up left/right children from
/// the `known` map, and reads missing siblings from `proof.auxiliaries`.
pub fn verify_multi_proof(
    hash_pair: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    leaves: &[([u8; 32], u64)],
    proof: &MerkleMultiProof,
    depth: u32,
) -> [u8; 32] {
    assert!(!leaves.is_empty(), "multi-proof: no leaves");

    // (level, node_index) -> hash
    let mut known: BTreeMap<(u32, u64), [u8; 32]> = BTreeMap::new();

    // Insert all leaves at level 0
    for &(ref hash, idx) in leaves {
        known.insert((0, idx), *hash);
    }

    let mut aux_cursor = 0usize;

    for level in 0..depth {
        // Collect parent indices needed at this level
        let parent_indices: Vec<u64> = known
            .range((level, 0)..=(level, u64::MAX))
            .map(|(&(_, idx), _)| idx / 2)
            .collect::<alloc::collections::BTreeSet<u64>>()
            .into_iter()
            .collect();

        for parent_idx in parent_indices {
            let left_idx = parent_idx * 2;
            let right_idx = parent_idx * 2 + 1;

            let left = match known.get(&(level, left_idx)) {
                Some(h) => *h,
                None => {
                    assert!(
                        aux_cursor < proof.auxiliaries.len(),
                        "multi-proof: ran out of auxiliaries at level {level}, left child {left_idx}"
                    );
                    let h = proof.auxiliaries[aux_cursor];
                    aux_cursor += 1;
                    h
                }
            };

            let right = match known.get(&(level, right_idx)) {
                Some(h) => *h,
                None => {
                    assert!(
                        aux_cursor < proof.auxiliaries.len(),
                        "multi-proof: ran out of auxiliaries at level {level}, right child {right_idx}"
                    );
                    let h = proof.auxiliaries[aux_cursor];
                    aux_cursor += 1;
                    h
                }
            };

            known.insert((level + 1, parent_idx), hash_pair(&left, &right));
        }
    }

    assert_eq!(
        aux_cursor,
        proof.auxiliaries.len(),
        "multi-proof: {} unused auxiliaries",
        proof.auxiliaries.len() - aux_cursor
    );

    *known
        .get(&(depth, 0))
        .expect("multi-proof: root not computed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial identity hash for testing: H(a,b) = sha256(a||b) simplified.
    fn xor_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a[i] ^ b[i];
        }
        out
    }

    #[test]
    fn test_single_leaf() {
        let leaf = [1u8; 32];
        let root = compute_root(xor_hash, &leaf, 0, &[]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_verify_proof() {
        let leaf = [1u8; 32];
        let sibling = [2u8; 32];
        let root = compute_root(xor_hash, &leaf, 0, &[sibling]);
        assert!(verify_proof(xor_hash, &leaf, 0, &[sibling], &root));
    }
}
