// Zisk guest program: Proof 2 — Finality
//
// Proves that validators representing >= 2/3 of total active balance
// attested to a target checkpoint with valid BLS signatures.
//
// Public outputs: (accumulator_commitment, finalized_block_root)
//
// On Zisk this file would use:
//   #![no_main]
//   ziskos::entrypoint!(main);

use zkasper_common::types::FinalityWitness;

fn main() {
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: FinalityWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (commitment, block_root) = verify_finality(&witness);

    eprintln!("accumulator_commitment: {:x?}", commitment);
    eprintln!("finalized_block_root: {:x?}", block_root);
}

/// Core finality verification logic. Returns (accumulator_commitment, finalized_block_root).
pub fn verify_finality(witness: &FinalityWitness) -> ([u8; 32], [u8; 32]) {
    use zkasper_common::bls::{compute_signing_root, verify_aggregate_signature};
    use zkasper_common::poseidon::{accumulator_commitment, poseidon_leaf, verify_poseidon_merkle_proof};

    // Verify the accumulator commitment binds poseidon_root + total_active_balance
    let expected_commitment =
        accumulator_commitment(&witness.poseidon_root, witness.total_active_balance);
    assert_eq!(
        expected_commitment, witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    let mut attesting_balance: u64 = 0;

    for attestation in &witness.attestations {
        let mut pubkeys: Vec<[u8; 48]> = Vec::new();
        let mut last_index: Option<u64> = None;

        for v in &attestation.attesting_validators {
            // Enforce strictly increasing validator indices to prevent
            // double-counting the same validator within or across attestations
            // that share the same signing root.
            if let Some(prev) = last_index {
                assert!(
                    v.validator_index > prev,
                    "validator indices must be strictly increasing: {} followed {}",
                    v.validator_index,
                    prev,
                );
            }
            last_index = Some(v.validator_index);

            // Compute expected Poseidon leaf and verify against tree
            let expected_leaf = poseidon_leaf(&v.pubkey.0, v.active_effective_balance);
            assert!(
                verify_poseidon_merkle_proof(
                    &expected_leaf,
                    v.validator_index,
                    &v.poseidon_siblings,
                    &witness.poseidon_root,
                ),
                "Poseidon proof failed for validator {}",
                v.validator_index,
            );

            attesting_balance += v.active_effective_balance;
            pubkeys.push(v.pubkey.0);
        }

        // Compute signing root and verify aggregate BLS signature
        let signing_root =
            compute_signing_root(&attestation.attestation_data_root, &witness.signing_domain);

        verify_aggregate_signature(&pubkeys, &signing_root, &attestation.signature.0);
    }

    // Supermajority check
    assert!(
        attesting_balance as u128 * 3 >= witness.total_active_balance as u128 * 2,
        "insufficient attesting balance: {} / {}",
        attesting_balance,
        witness.total_active_balance,
    );

    (witness.accumulator_commitment, witness.finalized_block_root)
}
