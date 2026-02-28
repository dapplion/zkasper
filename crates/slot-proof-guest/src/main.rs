#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_slot_proof_guest::verify_slot_proof;
use zkasper_common::types::SlotProofWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    #[cfg(target_os = "zkvm")]
    let input = ziskos::read_input_slice();
    #[cfg(not(target_os = "zkvm"))]
    let input = std::fs::read("input.bin").expect("read input.bin");

    let witness: SlotProofWitness = bincode::deserialize(&input).expect("deserialize witness");

    let output = verify_slot_proof(&witness);

    // Public outputs: [commitment(8), target_epoch(1), target_root(8), attesting_balance(1), counted_commitment(8), num_counted(1)]
    #[cfg(target_os = "zkvm")]
    {
        write_bytes32_output(0, &output.accumulator_commitment);
        ziskos::set_output(8, output.target_epoch as u32);
        write_bytes32_output(9, &output.target_root);
        ziskos::set_output(17, output.attesting_balance as u32);
        write_bytes32_output(18, &output.counted_validators_commitment);
        ziskos::set_output(26, output.num_counted_validators as u32);
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        eprintln!("accumulator_commitment: {:x?}", output.accumulator_commitment);
        eprintln!("target_epoch: {}", output.target_epoch);
        eprintln!("attesting_balance: {}", output.attesting_balance);
        eprintln!("counted_validators: {}", output.num_counted_validators);
        eprintln!("counted_commitment: {:x?}", output.counted_validators_commitment);
    }
}

#[cfg(target_os = "zkvm")]
fn write_bytes32_output(offset: usize, bytes: &[u8; 32]) {
    for i in 0..8usize {
        let b = i * 4;
        let word = u32::from_le_bytes([bytes[b], bytes[b + 1], bytes[b + 2], bytes[b + 3]]);
        ziskos::set_output(offset + i, word);
    }
}
