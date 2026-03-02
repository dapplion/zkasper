//! End-to-end test: bootstrap → slot proofs → justification → finalization → epoch diff.
//!
//! Uses 4 validators with real BLS signatures from deterministic secret keys.
//! Small tree depths (2) for fast execution.

mod common;

use common::{make_header, validator_data_to_response, MockBeaconApi};

use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::poseidon::accumulator_commitment;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::test_utils::build_poseidon_tree;
use zkasper_common::types::*;
use zkasper_common::ChainConfig;

const TEST_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 4,
    validators_tree_depth: 2,
    poseidon_tree_depth: 2,
    beacon_state_validators_field_index: 11,
};

const TEST_DEPTH: u32 = 2;

// ---------------------------------------------------------------------------
// BLS key generation helpers
// ---------------------------------------------------------------------------

fn generate_test_keys(n: usize) -> Vec<(blst::min_pk::SecretKey, [u8; 48])> {
    (0..n)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB; // ensure min 32 bytes entropy
            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pk_bytes: [u8; 48] = pk.to_bytes();
            (sk, pk_bytes)
        })
        .collect()
}

fn sign_message(sks: &[&blst::min_pk::SecretKey], msg: &[u8; 32]) -> [u8; 96] {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sigs: Vec<blst::min_pk::Signature> =
        sks.iter().map(|sk| sk.sign(msg, dst, &[])).collect();
    let sig_refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
    let agg = blst::min_pk::AggregateSignature::aggregate(&sig_refs, true).unwrap();
    agg.to_signature().to_bytes()
}

// ---------------------------------------------------------------------------
// Test attestation builder
// ---------------------------------------------------------------------------

/// Build an AttestationWitness with real BLS aggregate signatures.
///
/// `validator_indices` indexes into the `keys` array.
/// `seen` tracks which validators have already been counted across attestations.
fn make_test_attestation(
    keys: &[(blst::min_pk::SecretKey, [u8; 48])],
    validator_data: &[ValidatorData],
    validator_indices: &[usize],
    data_slot: u64,
    data_index: u64,
    target_epoch: u64,
    target_root: [u8; 32],
    source_epoch: u64,
    source_root: [u8; 32],
    signing_domain: [u8; 32],
    epoch: u64,
    seen: &mut std::collections::BTreeSet<u64>,
) -> AttestationWitness {
    let beacon_block_root = [0u8; 32]; // synthetic

    // Compute attestation_data_root
    let data_root = attestation_data_root(
        data_slot,
        data_index,
        &beacon_block_root,
        source_epoch,
        &source_root,
        target_epoch,
        &target_root,
    );

    // Compute signing_root
    let sig_root = compute_signing_root(&data_root, &signing_domain);

    // Sign with selected keys
    let sks: Vec<&blst::min_pk::SecretKey> =
        validator_indices.iter().map(|&i| &keys[i].0).collect();
    let signature = sign_message(&sks, &sig_root);

    // Build attesting validators
    let mut attesting_validators = Vec::with_capacity(validator_indices.len());
    for &idx in validator_indices {
        let v = &validator_data[idx];
        let count_balance = seen.insert(idx as u64);
        attesting_validators.push(AttestingValidator {
            validator_index: idx as u64,
            pubkey: BlsPubkey(keys[idx].1),
            active_effective_balance: v.active_effective_balance(epoch),
            count_balance,
        });
    }

    AttestationWitness {
        data_slot,
        data_index,
        data_beacon_block_root: beacon_block_root,
        data_source_epoch: source_epoch,
        data_source_root: source_root,
        data_target_epoch: target_epoch,
        data_target_root: target_root,
        signature: BlsSignature(signature),
        attesting_validators,
    }
}

// ---------------------------------------------------------------------------
// Full E2E test
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_pipeline() {
    // 1. Generate 4 BLS key pairs
    let keys = generate_test_keys(4);
    let balance_gwei = 32_000_000_000u64;

    // 2. Create validator data with real pubkeys
    let validators: Vec<ValidatorData> = keys
        .iter()
        .map(|(_, pk)| {
            let mut wc = [0u8; 32];
            wc[0] = 0x01;
            ValidatorData {
                pubkey: BlsPubkey(*pk),
                withdrawal_credentials: wc,
                effective_balance: balance_gwei,
                slashed: false,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                withdrawable_epoch: u64::MAX,
            }
        })
        .collect();

    let total_active_balance = 4 * balance_gwei;

    // 3. Compute signing domain (synthetic fork version + genesis validators root)
    let fork_version = [0x04, 0x00, 0x00, 0x00]; // Electra
    let genesis_validators_root = [0xAA; 32];
    let signing_domain = compute_domain(
        &DOMAIN_BEACON_ATTESTER,
        &fork_version,
        &genesis_validators_root,
    );

    // 4. Build Poseidon tree
    let epoch_e = 10u64;
    let poseidon_leaves: Vec<[u8; 32]> = validators
        .iter()
        .map(|v| {
            zkasper_common::poseidon::poseidon_leaf(&v.pubkey.0, v.active_effective_balance(epoch_e))
        })
        .collect();
    let (poseidon_root, _poseidon_siblings) = build_poseidon_tree(&poseidon_leaves, TEST_DEPTH);
    let commitment = accumulator_commitment(&poseidon_root, total_active_balance);

    // 5. Target roots (synthetic block roots for epoch E and E+1)
    let target_root_e = [0x07u8; 32];
    let target_root_e1 = [0x08u8; 32];
    let source_root = [0x01u8; 32];

    // =========================================================
    // Step A: Bootstrap at slot E*4
    // =========================================================
    let bootstrap_slot = epoch_e * TEST_CONFIG.slots_per_epoch;

    let responses: Vec<_> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header = make_header(bootstrap_slot, &responses, TEST_DEPTH);
    mock.validators
        .insert(bootstrap_slot.to_string(), responses.clone());
    mock.headers
        .insert(bootstrap_slot.to_string(), header);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (bootstrap_witness, tree, _epoch_state, boot_balance, boot_count) = rt
        .block_on(zkasper_witness_gen::witness_bootstrap::build(
            &mock,
            &TEST_CONFIG,
            bootstrap_slot,
        ))
        .unwrap();

    assert_eq!(boot_count, 4);
    assert_eq!(boot_balance, total_active_balance);

    // Verify bootstrap
    let (boot_commitment, boot_poseidon_root, boot_total_balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(
            &bootstrap_witness,
            TEST_DEPTH,
            TEST_DEPTH,
        );

    assert_eq!(boot_poseidon_root, tree.root());
    assert_eq!(boot_poseidon_root, poseidon_root);
    assert_eq!(boot_total_balance, total_active_balance);
    assert_eq!(boot_commitment, commitment);

    eprintln!("✓ Bootstrap verified");

    // =========================================================
    // Step B: Slot proofs for epoch E (2 slots with attestations)
    // =========================================================
    // Slot E*4: validators [0,1] attest
    // Slot E*4+1: validators [2,3] attest

    let slot_e0 = epoch_e * TEST_CONFIG.slots_per_epoch;
    let slot_e1 = slot_e0 + 1;

    // Build attestations for slot 0
    let mut seen_e = std::collections::BTreeSet::new();
    let att_e_slot0 = make_test_attestation(
        &keys,
        &validators,
        &[0, 1],
        slot_e0,
        0,
        epoch_e,
        target_root_e,
        epoch_e.saturating_sub(1),
        source_root,
        signing_domain,
        epoch_e,
        &mut seen_e,
    );

    // Build attestations for slot 1
    let att_e_slot1 = make_test_attestation(
        &keys,
        &validators,
        &[2, 3],
        slot_e1,
        0,
        epoch_e,
        target_root_e,
        epoch_e.saturating_sub(1),
        source_root,
        signing_domain,
        epoch_e,
        &mut seen_e,
    );

    // Build SlotProofWitness for slot E*4 (validators 0,1)
    let slot0_indices: Vec<u64> = vec![0, 1];
    let slot0_leaf_indices: Vec<u64> = att_e_slot0
        .attesting_validators
        .iter()
        .map(|v| v.validator_index)
        .collect();
    let (_, slot0_poseidon_proof) =
        build_poseidon_tree_multi_proof(&poseidon_leaves, TEST_DEPTH, &slot0_leaf_indices);

    let slot0_witness = SlotProofWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e,
        target_root: target_root_e,
        signing_domain,
        poseidon_root,
        total_active_balance,
        attestations: vec![att_e_slot0],
        poseidon_multi_proof: slot0_poseidon_proof,
    };

    let slot0_output =
        zkasper_slot_proof_guest::verify_slot_proof_with_depth(&slot0_witness, TEST_DEPTH);

    assert_eq!(slot0_output.accumulator_commitment, commitment);
    assert_eq!(slot0_output.target_epoch, epoch_e);
    assert_eq!(slot0_output.target_root, target_root_e);
    assert_eq!(slot0_output.attesting_balance, 2 * balance_gwei);
    assert_eq!(slot0_output.num_counted_validators, 2);

    eprintln!("✓ Slot proof 0 (epoch E) verified");

    // Build SlotProofWitness for slot E*4+1 (validators 2,3)
    let slot1_indices: Vec<u64> = vec![2, 3];
    let slot1_leaf_indices: Vec<u64> = att_e_slot1
        .attesting_validators
        .iter()
        .map(|v| v.validator_index)
        .collect();
    let (_, slot1_poseidon_proof) =
        build_poseidon_tree_multi_proof(&poseidon_leaves, TEST_DEPTH, &slot1_leaf_indices);

    let slot1_witness = SlotProofWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e,
        target_root: target_root_e,
        signing_domain,
        poseidon_root,
        total_active_balance,
        attestations: vec![att_e_slot1],
        poseidon_multi_proof: slot1_poseidon_proof,
    };

    let slot1_output =
        zkasper_slot_proof_guest::verify_slot_proof_with_depth(&slot1_witness, TEST_DEPTH);

    assert_eq!(slot1_output.attesting_balance, 2 * balance_gwei);
    assert_eq!(slot1_output.num_counted_validators, 2);

    eprintln!("✓ Slot proof 1 (epoch E) verified");

    // =========================================================
    // Step C: Justification for epoch E
    // =========================================================
    let just_e_witness = JustificationWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e,
        target_root: target_root_e,
        total_active_balance,
        slot_proof_outputs: vec![slot0_output.clone(), slot1_output.clone()],
        slot_proof_proofs: vec![vec![], vec![]], // stub proofs
        counted_indices_per_slot: vec![slot0_indices.clone(), slot1_indices.clone()],
    };

    let just_e_output = zkasper_justification_guest::verify_justification(&just_e_witness);

    assert_eq!(just_e_output.accumulator_commitment, commitment);
    assert_eq!(just_e_output.target_epoch, epoch_e);
    assert_eq!(just_e_output.target_root, target_root_e);

    eprintln!("✓ Justification (epoch E) verified");

    // =========================================================
    // Step D: Slot proofs for epoch E+1
    // =========================================================
    let epoch_e1 = epoch_e + 1;
    let slot_e1_0 = epoch_e1 * TEST_CONFIG.slots_per_epoch;
    let slot_e1_1 = slot_e1_0 + 1;

    let mut seen_e1 = std::collections::BTreeSet::new();

    let att_e1_slot0 = make_test_attestation(
        &keys,
        &validators,
        &[0, 1],
        slot_e1_0,
        0,
        epoch_e1,
        target_root_e1,
        epoch_e,
        target_root_e,
        signing_domain,
        epoch_e1,
        &mut seen_e1,
    );

    let att_e1_slot1 = make_test_attestation(
        &keys,
        &validators,
        &[2, 3],
        slot_e1_1,
        0,
        epoch_e1,
        target_root_e1,
        epoch_e,
        target_root_e,
        signing_domain,
        epoch_e1,
        &mut seen_e1,
    );

    // Poseidon tree is the same (no epoch diff yet)
    let (_, slot_e1_0_proof) =
        build_poseidon_tree_multi_proof(&poseidon_leaves, TEST_DEPTH, &[0, 1]);
    let (_, slot_e1_1_proof) =
        build_poseidon_tree_multi_proof(&poseidon_leaves, TEST_DEPTH, &[2, 3]);

    let slot_e1_0_witness = SlotProofWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e1,
        target_root: target_root_e1,
        signing_domain,
        poseidon_root,
        total_active_balance,
        attestations: vec![att_e1_slot0],
        poseidon_multi_proof: slot_e1_0_proof,
    };

    let slot_e1_0_output =
        zkasper_slot_proof_guest::verify_slot_proof_with_depth(&slot_e1_0_witness, TEST_DEPTH);

    let slot_e1_1_witness = SlotProofWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e1,
        target_root: target_root_e1,
        signing_domain,
        poseidon_root,
        total_active_balance,
        attestations: vec![att_e1_slot1],
        poseidon_multi_proof: slot_e1_1_proof,
    };

    let slot_e1_1_output =
        zkasper_slot_proof_guest::verify_slot_proof_with_depth(&slot_e1_1_witness, TEST_DEPTH);

    eprintln!("✓ Slot proofs (epoch E+1) verified");

    // =========================================================
    // Step E: Justification for epoch E+1
    // =========================================================
    let just_e1_witness = JustificationWitness {
        accumulator_commitment: commitment,
        target_epoch: epoch_e1,
        target_root: target_root_e1,
        total_active_balance,
        slot_proof_outputs: vec![slot_e1_0_output, slot_e1_1_output],
        slot_proof_proofs: vec![vec![], vec![]],
        counted_indices_per_slot: vec![vec![0, 1], vec![2, 3]],
    };

    let just_e1_output = zkasper_justification_guest::verify_justification(&just_e1_witness);

    assert_eq!(just_e1_output.accumulator_commitment, commitment);
    assert_eq!(just_e1_output.target_epoch, epoch_e1);
    assert_eq!(just_e1_output.target_root, target_root_e1);

    eprintln!("✓ Justification (epoch E+1) verified");

    // =========================================================
    // Step F: Finalization (two consecutive justifications)
    // =========================================================
    let finalization_witness = FinalizationWitness {
        accumulator_commitment: commitment,
        justification_outputs: vec![just_e_output, just_e1_output],
        justification_proofs: vec![vec![], vec![]],
    };

    let finalization_output =
        zkasper_finalization_guest::verify_finalization(&finalization_witness);

    assert_eq!(finalization_output.accumulator_commitment, commitment);
    assert_eq!(finalization_output.finalized_epoch, epoch_e);
    assert_eq!(finalization_output.finalized_root, target_root_e);

    eprintln!("✓ Finalization verified: epoch={}, root=0x{}", epoch_e, hex::encode(target_root_e));

    // =========================================================
    // Step G: Epoch diff (mutate validator 0's balance: 32 → 16 ETH)
    // =========================================================
    let epoch_e2 = epoch_e1 + 1;
    let slot_e2 = epoch_e2 * TEST_CONFIG.slots_per_epoch;

    let mut validators_e2 = validators.clone();
    validators_e2[0].effective_balance = 16_000_000_000;

    let responses_e2: Vec<_> = validators_e2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    // Add slot_e2 data to mock
    let header_e2 = make_header(slot_e2, &responses_e2, TEST_DEPTH);
    mock.validators
        .insert(slot_e2.to_string(), responses_e2);
    mock.headers.insert(slot_e2.to_string(), header_e2);

    // We need the bootstrap slot validators too (for the old state)
    let old_state = zkasper_witness_gen::EpochState::empty(bootstrap_slot, 4);
    let mut tree_for_diff = tree;

    let (epoch_diff_witness, _new_epoch_state, new_balance, new_count) = rt
        .block_on(zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &TEST_CONFIG,
            &mut tree_for_diff,
            &old_state,
            slot_e2,
            total_active_balance,
        ))
        .unwrap();

    assert_eq!(new_count, 4);
    // New balance: 16 + 32 + 32 + 32 = 112 ETH
    let expected_new_balance = 16_000_000_000 + 3 * 32_000_000_000u64;
    assert_eq!(new_balance, expected_new_balance);

    // Verify epoch diff
    let (diff_commitment, diff_poseidon_root, diff_balance) =
        zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
            &epoch_diff_witness,
            TEST_DEPTH,
            TEST_DEPTH,
        );

    assert_eq!(diff_poseidon_root, tree_for_diff.root());
    assert_eq!(diff_balance, new_balance);
    assert_ne!(diff_commitment, commitment); // balance changed

    let expected_diff_commitment = accumulator_commitment(&diff_poseidon_root, new_balance);
    assert_eq!(diff_commitment, expected_diff_commitment);

    eprintln!("✓ Epoch diff verified: balance {} → {}", total_active_balance, new_balance);

    // =========================================================
    // Verify accumulator commitment chain
    // =========================================================
    // Bootstrap → epoch diff: commitment chains correctly
    assert_eq!(boot_commitment, commitment);
    assert_eq!(
        epoch_diff_witness.poseidon_root_1,
        poseidon_root,
        "epoch diff should start from bootstrap's poseidon root"
    );
    assert_eq!(
        epoch_diff_witness.total_active_balance_1,
        total_active_balance,
        "epoch diff should start from bootstrap's total balance"
    );

    eprintln!("✓ Full E2E pipeline passed!");
    eprintln!("  Bootstrap → Slot proofs (2 slots × 2 epochs) → Justification × 2 → Finalization → Epoch diff");
}

// ---------------------------------------------------------------------------
// Helper: build Poseidon tree multi-proof from poseidon leaves
// ---------------------------------------------------------------------------

fn build_poseidon_tree_multi_proof(
    poseidon_leaves: &[[u8; 32]],
    depth: u32,
    leaf_indices: &[u64],
) -> ([u8; 32], MerkleMultiProof) {
    use std::collections::BTreeSet;
    use zkasper_common::poseidon::poseidon_pair;

    // Build the full tree
    let (root, _all_siblings) = build_poseidon_tree(poseidon_leaves, depth);

    // Build multi-proof using the same algorithm as test_utils::build_ssz_tree_multi_proof
    // but with poseidon_pair
    let mut zero_hashes = vec![[0u8; 32]; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zero_hashes[d] = poseidon_pair(&zero_hashes[d - 1], &zero_hashes[d - 1]);
    }

    let dense_depth = if poseidon_leaves.is_empty() {
        1u32
    } else {
        (poseidon_leaves.len() as u64)
            .next_power_of_two()
            .trailing_zeros()
    }
    .max(1)
    .min(depth);
    let dense_capacity = 1usize << dense_depth;

    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut leaves = vec![[0u8; 32]; dense_capacity];
    for (i, leaf) in poseidon_leaves.iter().enumerate() {
        leaves[i] = *leaf;
    }
    levels.push(leaves);

    for d in 0..dense_depth as usize {
        let prev = &levels[d];
        let parent_count = prev.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            parents.push(poseidon_pair(&prev[i * 2], &prev[i * 2 + 1]));
        }
        levels.push(parents);
    }

    // Build auxiliaries
    let mut known_at_level: BTreeSet<u64> = leaf_indices.iter().copied().collect();
    let mut auxiliaries = Vec::new();

    for level in 0..depth {
        let parent_indices: BTreeSet<u64> = known_at_level.iter().map(|&idx| idx / 2).collect();

        for &parent_idx in &parent_indices {
            let left_idx = parent_idx * 2;
            let right_idx = parent_idx * 2 + 1;

            if !known_at_level.contains(&left_idx) {
                let node = get_poseidon_node(&levels, &zero_hashes, level, left_idx, dense_depth);
                auxiliaries.push(node);
            }
            if !known_at_level.contains(&right_idx) {
                let node = get_poseidon_node(&levels, &zero_hashes, level, right_idx, dense_depth);
                auxiliaries.push(node);
            }
        }

        known_at_level = parent_indices;
    }

    (root, MerkleMultiProof { auxiliaries })
}

fn get_poseidon_node(
    levels: &[Vec<[u8; 32]>],
    zero_hashes: &[[u8; 32]],
    level: u32,
    idx: u64,
    dense_depth: u32,
) -> [u8; 32] {
    if level < dense_depth {
        let level_data = &levels[level as usize];
        if (idx as usize) < level_data.len() {
            level_data[idx as usize]
        } else {
            zero_hashes[level as usize]
        }
    } else {
        if idx == 0 && level == dense_depth {
            levels[dense_depth as usize][0]
        } else {
            zero_hashes[level as usize]
        }
    }
}
