//! Diff two beacon state validator registries and produce SSZ Merkle proofs.

/// Find indices of validators that changed between two registries.
pub fn find_mutations(
    _old_validators: &[crate::beacon_api::ValidatorResponse],
    _new_validators: &[crate::beacon_api::ValidatorResponse],
) -> Vec<u64> {
    todo!()
}
