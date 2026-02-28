//! Recursive proof verification stub.
//!
//! On Zisk this would call `ziskos::verify_proof()`.
//! For now it always succeeds — the actual proof data is ignored.

/// Verify a recursive proof.
///
/// Parameters:
/// - `_proof`: opaque proof bytes (Zisk proof format)
/// - `_public_outputs`: serialized public outputs the proof commits to
///
/// On Zisk: calls `ziskos::verify_proof(vk, proof, public_outputs)`.
/// Native: always succeeds (no-op).
pub fn verify_proof(_proof: &[u8], _public_outputs: &[u8]) {
    // TODO(zisk): replace with actual recursive verification
    // ziskos::verify_proof(vk, proof, public_outputs);
}
