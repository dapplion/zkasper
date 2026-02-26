//! BLS12-381 signature verification.
//!
//! Provides aggregate pubkey accumulation, hash-to-G2, and pairing-based
//! signature checks. On Zisk targets the underlying curve operations route
//! through `syscall_bls12_381_*` precompiles.
//!
//! TODO: implement once BLS12-381 pairing support in Zisk is confirmed.
//!       Key open questions:
//!       - Does `zisk-patch-bls12-381` expose the full pairing?
//!       - Is there a Zisk-optimized hash-to-curve (IETF hash-to-G2)?

use crate::ssz::sha256_pair;

/// Compute `signing_root = sha256(attestation_data_root || domain)`.
pub fn compute_signing_root(
    attestation_data_root: &[u8; 32],
    domain: &[u8; 32],
) -> [u8; 32] {
    sha256_pair(attestation_data_root, domain)
}

// TODO: aggregate_pubkeys, hash_to_g2, verify_aggregate_signature
