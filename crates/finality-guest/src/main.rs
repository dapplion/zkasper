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
use zkasper_finality_guest::verify_finality;

fn main() {
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: FinalityWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (commitment, block_root) = verify_finality(&witness);

    eprintln!("accumulator_commitment: {:x?}", commitment);
    eprintln!("finalized_block_root: {:x?}", block_root);
}
