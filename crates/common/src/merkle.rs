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
