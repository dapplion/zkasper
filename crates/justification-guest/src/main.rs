#![cfg_attr(target_os = "zkvm", no_main)]

use zkasper_justification_guest::verify_justification;
use zkasper_common::types::JustificationWitness;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

fn main() {
    #[cfg(target_os = "zkvm")]
    let input = ziskos::read_input_slice();
    #[cfg(not(target_os = "zkvm"))]
    let input = std::fs::read("input.bin").expect("read input.bin");

    let witness: JustificationWitness = bincode::deserialize(&input).expect("deserialize witness");

    let output = verify_justification(&witness);

    // Public outputs: [commitment(8), target_epoch(1), target_root(8)]
    #[cfg(target_os = "zkvm")]
    {
        write_bytes32_output(0, &output.accumulator_commitment);
        ziskos::set_output(8, output.target_epoch as u32);
        write_bytes32_output(9usize, &output.target_root);
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        eprintln!("justified target_epoch: {}", output.target_epoch);
        eprintln!("target_root: {:x?}", output.target_root);
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
