extern crate alloc;

use zkasper_common::types::{FinalizationOutput, FinalizationWitness};

/// Verify a finalization: two consecutive justification proofs.
pub fn verify_finalization(witness: &FinalizationWitness) -> FinalizationOutput {
    use zkasper_common::recursion::verify_proof;

    assert_eq!(
        witness.justification_outputs.len(),
        2,
        "finalization requires exactly 2 justification outputs",
    );

    let just_e = &witness.justification_outputs[0];
    let just_e1 = &witness.justification_outputs[1];

    // Recursive proof verification (no-op in native, real on Zisk)
    verify_proof(
        &witness.justification_proofs[0],
        &[], // TODO: serialize justification output for real verification
    );
    verify_proof(
        &witness.justification_proofs[1],
        &[],
    );

    // Both justifications must use the same accumulator commitment
    assert_eq!(
        just_e.accumulator_commitment, witness.accumulator_commitment,
        "justification 0 accumulator mismatch",
    );
    assert_eq!(
        just_e1.accumulator_commitment, witness.accumulator_commitment,
        "justification 1 accumulator mismatch",
    );

    // Epochs must be consecutive: E and E+1
    assert_eq!(
        just_e1.target_epoch,
        just_e.target_epoch + 1,
        "justification epochs not consecutive: {} and {}",
        just_e.target_epoch,
        just_e1.target_epoch,
    );

    // Finalized epoch is E, root is E's target root
    FinalizationOutput {
        accumulator_commitment: witness.accumulator_commitment,
        finalized_epoch: just_e.target_epoch,
        finalized_root: just_e.target_root,
    }
}
