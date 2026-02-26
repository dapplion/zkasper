// Zisk guest program: Proof 2 — Finality
//
// Proves that validators representing >= 2/3 of total active balance
// attested to a target checkpoint with valid BLS signatures.
//
// On Zisk this file would use:
//   #![no_main]
//   ziskos::entrypoint!(main);

use zkasper_common::bls::compute_signing_root;
use zkasper_common::poseidon::{poseidon_leaf, verify_poseidon_merkle_proof};
use zkasper_common::types::FinalityWitness;

fn main() {
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: FinalityWitness = bincode::deserialize(&input).expect("deserialize witness");

    let mut attesting_balance: u64 = 0;

    for attestation in &witness.attestations {
        let mut _pubkeys: Vec<[u8; 48]> = Vec::new();

        for v in &attestation.attesting_validators {
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
            _pubkeys.push(v.pubkey.0);
        }

        // Compute signing root
        let _signing_root = compute_signing_root(
            &attestation.attestation_data_root,
            &witness.signing_domain,
        );

        // TODO: BLS aggregate signature verification
        // 1. aggregate_pubkeys(&pubkeys)
        // 2. hash_to_g2(&signing_root)
        // 3. pairing check: e(agg_pk, H(m)) == e(G1, sig)
    }

    // Supermajority check
    assert!(
        attesting_balance as u128 * 3 >= witness.total_active_balance as u128 * 2,
        "insufficient attesting balance: {} / {}",
        attesting_balance,
        witness.total_active_balance,
    );

    // Output: finalized checkpoint
    eprintln!(
        "finalized: epoch={} root={:x?}",
        witness.finalized_checkpoint.epoch,
        witness.finalized_checkpoint.root,
    );
}
