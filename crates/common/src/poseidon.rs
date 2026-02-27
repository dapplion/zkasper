use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::merkle;

/// Compute a Poseidon accumulator leaf:
/// `Poseidon(pubkey_lo, pubkey_hi, active_effective_balance)`
///
/// - `pubkey_lo`: first 32 bytes of BLS pubkey as BN254 Fr element
/// - `pubkey_hi`: last 16 bytes of BLS pubkey (zero-padded to 32) as Fr
/// - `active_effective_balance`: u64 balance (0 if inactive)
pub fn poseidon_leaf(pubkey: &[u8; 48], active_eff_balance: u64) -> [u8; 32] {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_poseidon_t4();
    let pubkey_lo = Fr::from_le_bytes_mod_order(&pubkey[..32]);
    let pubkey_hi = {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&pubkey[32..48]);
        Fr::from_le_bytes_mod_order(&buf)
    };
    let balance = Fr::from(active_eff_balance);

    let mut poseidon = Poseidon::<Fr>::new_circom(3).expect("poseidon t=4");
    let hash = poseidon
        .hash(&[pubkey_lo, pubkey_hi, balance])
        .expect("poseidon hash");

    fr_to_bytes(&hash)
}

/// Poseidon hash of two field elements (for Merkle tree internal nodes).
pub fn poseidon_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_poseidon_t3();
    let l = Fr::from_le_bytes_mod_order(left);
    let r = Fr::from_le_bytes_mod_order(right);

    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("poseidon t=3");
    let hash = poseidon.hash(&[l, r]).expect("poseidon hash");

    fr_to_bytes(&hash)
}

/// Compute the accumulator commitment: `poseidon_pair(poseidon_root, total_active_balance)`.
///
/// This single value binds a Poseidon validator tree root to the total active balance,
/// allowing the on-chain contract to store one bytes32 instead of two separate values.
pub fn accumulator_commitment(poseidon_root: &[u8; 32], total_active_balance: u64) -> [u8; 32] {
    let root_fr = Fr::from_le_bytes_mod_order(poseidon_root);
    let balance_fr = Fr::from(total_active_balance);

    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("poseidon t=3");
    let hash = poseidon
        .hash(&[root_fr, balance_fr])
        .expect("poseidon hash");

    fr_to_bytes(&hash)
}

/// Compute a Poseidon Merkle root from leaf, index, and siblings.
pub fn compute_poseidon_merkle_root(
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    merkle::compute_root(poseidon_pair, leaf, index, siblings)
}

/// Verify a Poseidon Merkle proof.
pub fn verify_poseidon_merkle_proof(
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    merkle::verify_proof(poseidon_pair, leaf, index, siblings, root)
}

/// Serialize an Fr element to 32 bytes (little-endian).
fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut result = [0u8; 32];
    let len = le_bytes.len().min(32);
    result[..len].copy_from_slice(&le_bytes[..len]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_leaf_deterministic() {
        let pubkey = [42u8; 48];
        let balance = 32_000_000_000u64; // 32 ETH
        let a = poseidon_leaf(&pubkey, balance);
        let b = poseidon_leaf(&pubkey, balance);
        assert_eq!(a, b);
    }

    #[test]
    fn test_poseidon_leaf_different_balance() {
        let pubkey = [42u8; 48];
        let a = poseidon_leaf(&pubkey, 32_000_000_000);
        let b = poseidon_leaf(&pubkey, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn test_poseidon_pair_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let r1 = poseidon_pair(&a, &b);
        let r2 = poseidon_pair(&a, &b);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_poseidon_pair_non_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let ab = poseidon_pair(&a, &b);
        let ba = poseidon_pair(&b, &a);
        assert_ne!(ab, ba);
    }
}
