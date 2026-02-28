//! BLS12-381 signature verification.
//!
//! Provides aggregate pubkey accumulation, hash-to-G2, and pairing-based
//! signature checks.
//!
//! When the `bls` feature is enabled, uses the `blst` library for native
//! verification. Without it, panics (placeholder for zkVM targets that
//! will use precompile-based verification).

use crate::ssz::sha256_pair;

/// Ethereum BLS signature Domain Separation Tag (ciphersuite).
#[cfg(feature = "bls")]
const ETH_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Compute `signing_root = sha256(attestation_data_root || domain)`.
pub fn compute_signing_root(attestation_data_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    sha256_pair(attestation_data_root, domain)
}

/// Compute the Ethereum signing domain for a given domain type, fork version,
/// and genesis validators root.
///
/// `domain = domain_type[0..4] || fork_data_root[0..28]`
/// where `fork_data_root = hash_tree_root(ForkData{current_version, genesis_validators_root})`
///                        = sha256(pad32(current_version) || genesis_validators_root)
pub fn compute_domain(
    domain_type: &[u8; 4],
    fork_version: &[u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(fork_version);
    let fork_data_root = sha256_pair(&version_chunk, genesis_validators_root);

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// DOMAIN_BEACON_ATTESTER as defined in the Ethereum consensus spec.
pub const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Verify an aggregate BLS signature over a signing root.
///
/// # Arguments
/// - `pubkeys`: raw 48-byte BLS public keys to aggregate
/// - `signing_root`: the message that was signed (attestation_data_root || domain)
/// - `signature`: the 96-byte aggregate BLS signature
///
/// # Panics
/// Panics if the signature is invalid or verification fails.
#[cfg(feature = "bls")]
pub fn verify_aggregate_signature(
    pubkeys: &[[u8; 48]],
    signing_root: &[u8; 32],
    signature: &[u8; 96],
) {
    use blst::min_pk::{PublicKey, Signature};
    use blst::BLST_ERROR;

    assert!(!pubkeys.is_empty(), "must have at least one pubkey");

    let sig = Signature::from_bytes(signature).expect("invalid BLS signature encoding");

    let pks: Vec<PublicKey> = pubkeys
        .iter()
        .map(|b| PublicKey::from_bytes(b.as_ref()).expect("invalid BLS pubkey encoding"))
        .collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    let result = sig.fast_aggregate_verify(true, signing_root, ETH_BLS_DST, &pk_refs);
    assert_eq!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "BLS aggregate signature verification failed: {:?}",
        result,
    );
}

/// Fallback when `bls` feature is not enabled (e.g. zkVM targets).
#[cfg(not(feature = "bls"))]
pub fn verify_aggregate_signature(
    _pubkeys: &[[u8; 48]],
    _signing_root: &[u8; 32],
    _signature: &[u8; 96],
) {
    unimplemented!(
        "BLS aggregate signature verification requires the `bls` feature — \
         enable it or use Zisk BLS12-381 pairing precompile"
    );
}
