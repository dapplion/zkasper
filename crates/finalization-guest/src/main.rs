#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_finalization_guest::verify_finalization;
use zkasper_common::types::FinalizationWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    #[cfg(target_os = "zkvm")]
    let input = ziskos::read_input_slice();
    #[cfg(not(target_os = "zkvm"))]
    let input = std::fs::read("input.bin").expect("read input.bin");

    let witness: FinalizationWitness = bincode::deserialize(&input).expect("deserialize witness");

    let output = verify_finalization(&witness);

    // Public outputs: [commitment(8), finalized_block_root(8)]
    #[cfg(target_os = "zkvm")]
    {
        write_bytes32_output(0, &output.accumulator_commitment);
        write_bytes32_output(8, &output.finalized_root);
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        eprintln!("finalized_epoch: {}", output.finalized_epoch);
        eprintln!("finalized_root: {:x?}", output.finalized_root);
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
