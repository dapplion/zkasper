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
pub fn compute_signing_root(attestation_data_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    sha256_pair(attestation_data_root, domain)
}

/// Verify an aggregate BLS signature over a signing root.
///
/// # Arguments
/// - `pubkeys`: raw 48-byte BLS public keys to aggregate
/// - `signing_root`: the message that was signed (attestation_data_root || domain)
/// - `signature`: the 96-byte aggregate BLS signature
///
/// # Panics
/// Always panics — BLS pairing verification is not yet implemented.
/// Blocked on confirmation of Zisk BLS12-381 pairing precompile support.
pub fn verify_aggregate_signature(
    _pubkeys: &[[u8; 48]],
    _signing_root: &[u8; 32],
    _signature: &[u8; 96],
) {
    unimplemented!(
        "BLS aggregate signature verification not yet implemented — \
         requires Zisk BLS12-381 pairing support"
    );
}
