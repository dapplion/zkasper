// Zisk guest program: Bootstrap
//
// One-time construction of the Poseidon accumulator from the full validator set.
// Verifies all validators against the SSZ state, builds the Poseidon tree,
// and outputs the root + total active balance.
//
// On Zisk this file would use:
//   #![no_main]
//   ziskos::entrypoint!(main);

use zkasper_bootstrap_guest::verify_bootstrap;
use zkasper_common::types::BootstrapWitness;

fn main() {
    let input = std::fs::read("input.bin").expect("read input.bin");
    let witness: BootstrapWitness = bincode::deserialize(&input).expect("deserialize witness");

    let (commitment, poseidon_root, total_active_balance) = verify_bootstrap(&witness);

    eprintln!("accumulator_commitment: {:x?}", commitment);
    eprintln!("poseidon_root: {:x?}", poseidon_root);
    eprintln!("total_active_balance: {}", total_active_balance);
}

#[cfg(test)]
mod tests {
    use zkasper_bootstrap_guest::verify_bootstrap_with_depth;
    use zkasper_common::constants::BEACON_STATE_VALIDATORS_FIELD_INDEX;
    use zkasper_common::poseidon::poseidon_leaf;
    use zkasper_common::ssz::{list_hash_tree_root, sha256_pair, validator_hash_tree_root};
    use zkasper_common::test_utils::*;
    use zkasper_common::types::*;

    /// Build a fake state root from a validators data tree root.
    fn make_state_proof(data_tree_root: &[u8; 32], list_length: u64) -> ([u8; 32], Vec<[u8; 32]>) {
        let validators_root = list_hash_tree_root(data_tree_root, list_length);
        let depth = 5;
        let mut siblings = Vec::with_capacity(depth);
        let mut current = validators_root;
        let mut idx = BEACON_STATE_VALIDATORS_FIELD_INDEX;

        for d in 0..depth {
            let mut sibling = [0u8; 32];
            sibling[0] = d as u8;
            sibling[1] = 0xBE;
            siblings.push(sibling);

            if idx & 1 == 0 {
                current = sha256_pair(&current, &sibling);
            } else {
                current = sha256_pair(&sibling, &current);
            }
            idx >>= 1;
        }

        (current, siblings)
    }

    fn rebuild_tree_sha256(leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
        let (root, _) = build_ssz_tree(leaves, depth);
        root
    }

    fn rebuild_tree_poseidon(leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
        let (root, _) = build_poseidon_tree(leaves, depth);
        root
    }

    #[test]
    fn test_bootstrap_4_validators() {
        let depth = 2u32;
        let epoch = 100u64;
        let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();

        let field_chunks: Vec<_> = validators.iter().map(make_field_leaves).collect();
        let pubkey_chunks: Vec<_> = validators.iter().map(make_pubkey_chunks).collect();

        let validator_roots: Vec<_> = field_chunks.iter().map(validator_hash_tree_root).collect();
        let ssz_data_root = rebuild_tree_sha256(&validator_roots, depth);

        let poseidon_leaves_vec: Vec<_> = validators
            .iter()
            .map(|v| poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch)))
            .collect();
        let expected_poseidon_root = rebuild_tree_poseidon(&poseidon_leaves_vec, depth);

        let num_validators = 4u64;
        let (state_root, state_siblings) = make_state_proof(&ssz_data_root, num_validators);

        let witness = BootstrapWitness {
            state_root,
            epoch,
            validators: validators.clone(),
            state_to_validators_siblings: state_siblings,
            validators_list_length: num_validators,
            validator_field_chunks: field_chunks,
            validator_pubkey_chunks: pubkey_chunks,
        };

        let (commitment, poseidon_root, total_active_balance) =
            verify_bootstrap_with_depth(&witness, depth);

        assert_eq!(poseidon_root, expected_poseidon_root);
        assert_eq!(total_active_balance, 4 * 32_000_000_000);
        let expected_commitment =
            zkasper_common::poseidon::accumulator_commitment(&poseidon_root, total_active_balance);
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_bootstrap_mixed_validators() {
        let depth = 2u32;
        let epoch = 100u64;
        let v0 = make_validator(0, 32);
        let v1 = make_validator(1, 32);
        let v2 = ValidatorData {
            exit_epoch: 50,
            ..make_validator(2, 32)
        };
        let v3 = make_validator(3, 16);
        let validators = vec![v0, v1, v2, v3];

        let field_chunks: Vec<_> = validators.iter().map(make_field_leaves).collect();
        let pubkey_chunks: Vec<_> = validators.iter().map(make_pubkey_chunks).collect();

        let validator_roots: Vec<_> = field_chunks.iter().map(validator_hash_tree_root).collect();
        let ssz_data_root = rebuild_tree_sha256(&validator_roots, depth);

        let num_validators = 4u64;
        let (state_root, state_siblings) = make_state_proof(&ssz_data_root, num_validators);

        let witness = BootstrapWitness {
            state_root,
            epoch,
            validators: validators.clone(),
            state_to_validators_siblings: state_siblings,
            validators_list_length: num_validators,
            validator_field_chunks: field_chunks,
            validator_pubkey_chunks: pubkey_chunks,
        };

        let (_, _, total_active_balance) = verify_bootstrap_with_depth(&witness, depth);

        assert_eq!(
            total_active_balance,
            32_000_000_000 + 32_000_000_000 + 16_000_000_000
        );
    }
}
