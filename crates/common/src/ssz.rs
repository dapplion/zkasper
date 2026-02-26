use sha2::{Digest, Sha256};

use crate::merkle;
use crate::types::ValidatorData;

/// SHA-256 hash of two concatenated 32-byte inputs.
pub fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
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

/// SSZ List hash_tree_root: `sha256(data_tree_root || le_pad32(length))`.
pub fn list_hash_tree_root(data_tree_root: &[u8; 32], length: u64) -> [u8; 32] {
    let mut length_chunk = [0u8; 32];
    length_chunk[..8].copy_from_slice(&length.to_le_bytes());
    sha256_pair(data_tree_root, &length_chunk)
}

/// Compute a SHA-256 Merkle root from leaf, index, and siblings.
pub fn compute_ssz_merkle_root(
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_pair() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let result = sha256_pair(&a, &b);
        // sha256 of 64 zero bytes — deterministic
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_list_hash_tree_root() {
        let data_root = [1u8; 32];
        let result = list_hash_tree_root(&data_root, 100);
        assert_ne!(result, data_root);
    }

    #[test]
    fn test_u64_to_chunk() {
        let chunk = u64_to_chunk(32_000_000_000); // 32 ETH in Gwei
        assert_eq!(
            u64::from_le_bytes(chunk[..8].try_into().unwrap()),
            32_000_000_000
        );
        assert_eq!(&chunk[8..], &[0u8; 24]);
    }
}
