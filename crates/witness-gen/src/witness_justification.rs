//! Assemble a JustificationWitness from slot proof outputs.

use zkasper_common::types::{JustificationWitness, SlotProofOutput};

/// Build a JustificationWitness from slot proof results.
///
/// `slot_proof_outputs`: the public outputs from each verified slot proof.
/// `slot_proof_proofs`: opaque proof bytes from each slot proof (empty in native mode).
/// `counted_indices_per_slot`: the sorted counted validator indices from each slot.
pub fn build(
    slot_proof_outputs: Vec<SlotProofOutput>,
    slot_proof_proofs: Vec<Vec<u8>>,
    counted_indices_per_slot: Vec<Vec<u64>>,
    accumulator_commitment: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
    total_active_balance: u64,
) -> JustificationWitness {
    JustificationWitness {
        accumulator_commitment,
        target_epoch,
        target_root,
        total_active_balance,
        slot_proof_outputs,
        slot_proof_proofs,
        counted_indices_per_slot,
    }
}
