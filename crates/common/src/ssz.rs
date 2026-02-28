use sha2::{Digest, Sha256};

use crate::merkle;
use crate::types::ValidatorData;

/// SHA-256 hash of two concatenated 32-byte inputs.
pub fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_sha256();
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Merkleize 8 leaves (depth-3 binary tree, 7 hashes).
/// Used for the Validator container hash_tree_root.
pub fn validator_hash_tree_root(field_leaves: &[[u8; 32]; 8]) -> [u8; 32] {
    // level 2 (4 nodes)
    let n0 = sha256_pair(&field_leaves[0], &field_leaves[1]);
    let n1 = sha256_pair(&field_leaves[2], &field_leaves[3]);
    let n2 = sha256_pair(&field_leaves[4], &field_leaves[5]);
    let n3 = sha256_pair(&field_leaves[6], &field_leaves[7]);
    // level 1 (2 nodes)
    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);
    // root
    sha256_pair(&n4, &n5)
}

/// Compute both old and new validator hash tree roots, sharing intermediate
/// SHA-256 computations when subtrees are identical.
///
/// For activity-only mutations (no SSZ field changes), this does 7 hashes
/// instead of 14. For single-field changes (e.g. effective_balance), ~10
/// instead of 14.
pub fn validator_hash_tree_root_pair(
    old_leaves: &[[u8; 32]; 8],
    new_leaves: &[[u8; 32]; 8],
) -> ([u8; 32], [u8; 32]) {
    // level 2 (4 nodes)
    let (old_n0, new_n0) = shared_sha256_pair(&old_leaves[0], &old_leaves[1], &new_leaves[0], &new_leaves[1]);
    let (old_n1, new_n1) = shared_sha256_pair(&old_leaves[2], &old_leaves[3], &new_leaves[2], &new_leaves[3]);
    let (old_n2, new_n2) = shared_sha256_pair(&old_leaves[4], &old_leaves[5], &new_leaves[4], &new_leaves[5]);
    let (old_n3, new_n3) = shared_sha256_pair(&old_leaves[6], &old_leaves[7], &new_leaves[6], &new_leaves[7]);
    // level 1
    let (old_n4, new_n4) = shared_sha256_pair(&old_n0, &old_n1, &new_n0, &new_n1);
    let (old_n5, new_n5) = shared_sha256_pair(&old_n2, &old_n3, &new_n2, &new_n3);
    // root
    shared_sha256_pair(&old_n4, &old_n5, &new_n4, &new_n5)
}

/// Hash two pairs, but compute only once if both pairs are identical.
#[inline]
fn shared_sha256_pair(
    old_l: &[u8; 32], old_r: &[u8; 32],
    new_l: &[u8; 32], new_r: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    if old_l == new_l && old_r == new_r {
        let h = sha256_pair(new_l, new_r);
        (h, h)
    } else {
        (sha256_pair(old_l, old_r), sha256_pair(new_l, new_r))
    }
}

/// SSZ List hash_tree_root: `sha256(data_tree_root || le_pad32(length))`.
pub fn list_hash_tree_root(data_tree_root: &[u8; 32], length: u64) -> [u8; 32] {
    let mut length_chunk = [0u8; 32];
    length_chunk[..8].copy_from_slice(&length.to_le_bytes());
    sha256_pair(data_tree_root, &length_chunk)
}

/// Compute a SHA-256 Merkle root from leaf, index, and siblings.
pub fn compute_ssz_merkle_root(leaf: &[u8; 32], index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    merkle::compute_root(sha256_pair, leaf, index, siblings)
}

/// Verify a SHA-256 Merkle proof.
pub fn verify_ssz_merkle_proof(
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    merkle::verify_proof(sha256_pair, leaf, index, siblings, root)
}

/// Verify multiple leaves against a single SHA-256 Merkle root using a multi-proof.
/// Returns the computed root.
pub fn verify_ssz_multi_proof(
    leaves: &[([u8; 32], u64)],
    proof: &crate::types::MerkleMultiProof,
    depth: u32,
) -> [u8; 32] {
    merkle::verify_multi_proof(sha256_pair, leaves, proof, depth)
}

/// Compute `hash_tree_root(AttestationData)` from its constituent fields.
///
/// AttestationData is a 5-field SSZ container merkleized into an 8-leaf tree:
/// ```text
/// field[0] = le_pad32(slot)
/// field[1] = le_pad32(index)
/// field[2] = beacon_block_root
/// field[3] = hash_tree_root(source) = sha256(le_pad32(epoch) || root)
/// field[4] = hash_tree_root(target) = sha256(le_pad32(epoch) || root)
/// field[5..7] = zero
/// ```
pub fn attestation_data_root(
    slot: u64,
    index: u64,
    beacon_block_root: &[u8; 32],
    source_epoch: u64,
    source_root: &[u8; 32],
    target_epoch: u64,
    target_root: &[u8; 32],
) -> [u8; 32] {
    let zero = [0u8; 32];

    let field0 = u64_to_chunk(slot);
    let field1 = u64_to_chunk(index);
    let field2 = *beacon_block_root;
    let field3 = sha256_pair(&u64_to_chunk(source_epoch), source_root);
    let field4 = sha256_pair(&u64_to_chunk(target_epoch), target_root);

    // Depth-3 tree with 8 leaves (5 data + 3 zero)
    let n0 = sha256_pair(&field0, &field1);
    let n1 = sha256_pair(&field2, &field3);
    let n2 = sha256_pair(&field4, &zero);
    let n3 = sha256_pair(&zero, &zero);

    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);

    sha256_pair(&n4, &n5)
}

/// Pad a u64 value to a 32-byte LE SSZ chunk.
pub fn u64_to_chunk(val: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&val.to_le_bytes());
    chunk
}

/// Verify that the SSZ field leaves are consistent with the claimed `ValidatorData`.
///
/// Checks:
/// - `field_leaves[0]` = `sha256(pubkey_chunks[0] || pubkey_chunks[1])`
/// - `pubkey_chunks` encode the raw pubkey bytes
/// - `field_leaves[2]` encodes `effective_balance`
/// - `field_leaves[5]` encodes `activation_epoch`
/// - `field_leaves[6]` encodes `exit_epoch`
///
/// Leaves 1, 3, 4, 7 are opaque (withdrawal_credentials, slashed,
/// activation_eligibility_epoch, withdrawable_epoch).
///
/// For a cheaper variant that skips the pubkey SHA-256 hash (when pubkey is
/// known to match another already-verified set), use [`verify_field_leaves_no_pubkey_hash`].
pub fn verify_field_leaves(
    data: &ValidatorData,
    field_leaves: &[[u8; 32]; 8],
    pubkey_chunks: &[[u8; 32]; 2],
) {
    // pubkey: field_leaves[0] = sha256(chunk0 || chunk1)
    let computed_pubkey_leaf = sha256_pair(&pubkey_chunks[0], &pubkey_chunks[1]);
    assert_eq!(
        field_leaves[0], computed_pubkey_leaf,
        "pubkey leaf mismatch"
    );

    // pubkey raw bytes match the chunks
    assert_eq!(
        &pubkey_chunks[0][..32],
        &data.pubkey.0[..32],
        "pubkey chunk 0 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][..16],
        &data.pubkey.0[32..48],
        "pubkey chunk 1 mismatch"
    );
    // remaining 16 bytes of chunk 1 must be zero
    assert_eq!(
        &pubkey_chunks[1][16..],
        &[0u8; 16],
        "pubkey chunk 1 padding not zero"
    );

    // effective_balance
    assert_eq!(
        field_leaves[2],
        u64_to_chunk(data.effective_balance),
        "effective_balance leaf mismatch"
    );

    // activation_epoch
    assert_eq!(
        field_leaves[5],
        u64_to_chunk(data.activation_epoch),
        "activation_epoch leaf mismatch"
    );

    // exit_epoch
    assert_eq!(
        field_leaves[6],
        u64_to_chunk(data.exit_epoch),
        "exit_epoch leaf mismatch"
    );
}

/// Like [`verify_field_leaves`] but skips the pubkey SHA-256 hash.
///
/// Use when the pubkey leaf has already been verified elsewhere (e.g. the
/// new validator's field_leaves were verified with [`verify_field_leaves`]
/// and we know old_field_leaves[0] == new_field_leaves[0] because pubkeys
/// don't change for existing validators).
pub fn verify_field_leaves_no_pubkey_hash(
    data: &ValidatorData,
    field_leaves: &[[u8; 32]; 8],
    pubkey_chunks: &[[u8; 32]; 2],
) {
    // pubkey raw bytes match the chunks (no SHA-256 needed)
    assert_eq!(
        &pubkey_chunks[0][..32],
        &data.pubkey.0[..32],
        "pubkey chunk 0 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][..16],
        &data.pubkey.0[32..48],
        "pubkey chunk 1 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][16..],
        &[0u8; 16],
        "pubkey chunk 1 padding not zero"
    );

    assert_eq!(
        field_leaves[2],
        u64_to_chunk(data.effective_balance),
        "effective_balance leaf mismatch"
    );
    assert_eq!(
        field_leaves[5],
        u64_to_chunk(data.activation_epoch),
        "activation_epoch leaf mismatch"
    );
    assert_eq!(
        field_leaves[6],
        u64_to_chunk(data.exit_epoch),
        "exit_epoch leaf mismatch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_field_leaves, make_pubkey_chunks, make_validator};

    #[test]
    fn test_sha256_pair() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let result = sha256_pair(&a, &b);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_sha256_pair_not_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(sha256_pair(&a, &b), sha256_pair(&b, &a));
    }

    #[test]
    fn test_list_hash_tree_root() {
        let data_root = [1u8; 32];
        let result = list_hash_tree_root(&data_root, 100);
        assert_ne!(result, data_root);
    }

    #[test]
    fn test_list_hash_tree_root_different_lengths() {
        let data_root = [1u8; 32];
        let a = list_hash_tree_root(&data_root, 100);
        let b = list_hash_tree_root(&data_root, 101);
        assert_ne!(a, b);
    }

    #[test]
    fn test_u64_to_chunk() {
        let chunk = u64_to_chunk(32_000_000_000);
        assert_eq!(
            u64::from_le_bytes(chunk[..8].try_into().unwrap()),
            32_000_000_000
        );
        assert_eq!(&chunk[8..], &[0u8; 24]);
    }

    #[test]
    fn test_validator_hash_tree_root_deterministic() {
        let v = make_validator(1, 32);
        let leaves = make_field_leaves(&v);
        let a = validator_hash_tree_root(&leaves);
        let b = validator_hash_tree_root(&leaves);
        assert_eq!(a, b);
    }

    #[test]
    fn test_validator_hash_tree_root_changes_with_balance() {
        let v1 = make_validator(1, 32);
        let v2 = make_validator(1, 16);
        let a = validator_hash_tree_root(&make_field_leaves(&v1));
        let b = validator_hash_tree_root(&make_field_leaves(&v2));
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_field_leaves_valid() {
        let v = make_validator(5, 32);
        let leaves = make_field_leaves(&v);
        let chunks = make_pubkey_chunks(&v);
        // Should not panic
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    #[should_panic(expected = "effective_balance leaf mismatch")]
    fn test_verify_field_leaves_wrong_balance() {
        let v = make_validator(5, 32);
        let mut leaves = make_field_leaves(&v);
        // Tamper with the balance leaf
        leaves[2] = u64_to_chunk(16_000_000_000);
        let chunks = make_pubkey_chunks(&v);
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    #[should_panic(expected = "pubkey leaf mismatch")]
    fn test_verify_field_leaves_wrong_pubkey() {
        let v = make_validator(5, 32);
        let leaves = make_field_leaves(&v);
        let mut chunks = make_pubkey_chunks(&v);
        // Tamper with pubkey chunk
        chunks[0][0] = 0xFF;
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    fn test_ssz_merkle_proof_roundtrip() {
        let v0 = make_validator(0, 32);
        let v1 = make_validator(1, 32);
        let v2 = make_validator(2, 32);
        let v3 = make_validator(3, 32);

        let roots: Vec<_> = [&v0, &v1, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();

        let (tree_root, siblings) = crate::test_utils::build_ssz_tree(&roots, 2);

        for (i, root) in roots.iter().enumerate() {
            assert!(
                verify_ssz_merkle_proof(root, i as u64, &siblings[i], &tree_root),
                "proof failed for leaf {i}"
            );
        }
    }
}
