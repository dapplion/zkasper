extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::types::{SlotProofOutput, SlotProofWitness};

/// Verify a single slot's attestations and produce a SlotProofOutput.
///
/// This is the core slot-proof circuit logic. It:
/// 1. Verifies the accumulator commitment
/// 2. Verifies each validator via Poseidon multi-proof
/// 3. Verifies BLS aggregate signatures per attestation
/// 4. Computes a commitment over counted validator indices (for cross-slot dedup)
///
/// Does NOT check supermajority — that's the justification proof's job.
pub fn verify_slot_proof(witness: &SlotProofWitness) -> SlotProofOutput {
    verify_slot_proof_with_depth(
        witness,
        zkasper_common::constants::POSEIDON_TREE_DEPTH,
    )
}

/// Slot-proof verification with configurable Poseidon tree depth.
pub fn verify_slot_proof_with_depth(
    witness: &SlotProofWitness,
    poseidon_depth: u32,
) -> SlotProofOutput {
    use zkasper_common::bls::{compute_signing_root, verify_aggregate_signature};
    use zkasper_common::poseidon::{
        accumulator_commitment, counted_validators_commitment, poseidon_leaf,
        verify_poseidon_multi_proof,
    };

    // Verify the accumulator commitment binds poseidon_root + total_active_balance
    let expected_commitment =
        accumulator_commitment(&witness.poseidon_root, witness.total_active_balance);
    assert_eq!(
        expected_commitment, witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    // Phase 1: Collect all unique Poseidon leaves from attestations.
    let mut attesting_balance: u64 = 0;
    let mut multi_proof_leaves: Vec<([u8; 32], u64)> = Vec::new();
    let mut counted_indices: Vec<u64> = Vec::new();

    for attestation in &witness.attestations {
        let mut last_index: Option<u64> = None;

        for v in &attestation.attesting_validators {
            // Enforce strictly increasing validator indices within each attestation
            if let Some(prev) = last_index {
                assert!(
                    v.validator_index > prev,
                    "validator indices must be strictly increasing: {} followed {}",
                    v.validator_index,
                    prev,
                );
            }
            last_index = Some(v.validator_index);

            if v.count_balance {
                attesting_balance += v.active_effective_balance;
                counted_indices.push(v.validator_index);

                let leaf = poseidon_leaf(&v.pubkey.0, v.active_effective_balance);
                multi_proof_leaves.push((leaf, v.validator_index));
            }
        }
    }

    // Sort multi-proof leaves by validator index
    multi_proof_leaves.sort_unstable_by_key(|&(_, idx)| idx);

    // Verify no duplicate validator was counted
    for i in 1..multi_proof_leaves.len() {
        assert!(
            multi_proof_leaves[i].1 > multi_proof_leaves[i - 1].1,
            "duplicate validator counted: {}",
            multi_proof_leaves[i].1,
        );
    }

    // Phase 2: Verify all Poseidon leaves at once via multi-proof
    let computed_root = verify_poseidon_multi_proof(
        &multi_proof_leaves,
        &witness.poseidon_multi_proof,
        poseidon_depth,
    );
    assert_eq!(
        computed_root, witness.poseidon_root,
        "Poseidon multi-proof root mismatch",
    );

    // Phase 3: Verify BLS signatures and attestation target for each attestation
    for attestation in &witness.attestations {
        // Recompute attestation_data_root from raw fields and verify target
        assert_eq!(
            attestation.data_target_epoch, witness.target_epoch,
            "attestation target_epoch mismatch",
        );
        assert_eq!(
            attestation.data_target_root, witness.target_root,
            "attestation target_root mismatch",
        );

        let data_root = zkasper_common::ssz::attestation_data_root(
            attestation.data_slot,
            attestation.data_index,
            &attestation.data_beacon_block_root,
            attestation.data_source_epoch,
            &attestation.data_source_root,
            attestation.data_target_epoch,
            &attestation.data_target_root,
        );

        let pubkeys: Vec<[u8; 48]> = attestation
            .attesting_validators
            .iter()
            .map(|v| v.pubkey.0)
            .collect();

        let signing_root = compute_signing_root(&data_root, &witness.signing_domain);

        verify_aggregate_signature(&pubkeys, &signing_root, &attestation.signature.0);
    }

    // Phase 4: Compute counted validators commitment
    counted_indices.sort_unstable();
    let commitment = counted_validators_commitment(&counted_indices);

    SlotProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance,
        counted_validators_commitment: commitment,
        num_counted_validators: counted_indices.len() as u64,
    }
}
