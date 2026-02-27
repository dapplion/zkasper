mod common;

use common::{make_header, validator_data_to_response, MockBeaconApi};

use zkasper_common::constants::SLOTS_PER_EPOCH;

/// Small tree depth for tests (2^2 = 4 leaves)
const TEST_DEPTH: u32 = 2;
use zkasper_common::poseidon::accumulator_commitment;
use zkasper_common::test_utils::make_validator;
use zkasper_common::types::ValidatorData;

use zkasper_witness_gen::beacon_api::ValidatorResponse;
use zkasper_witness_gen::state_diff::find_mutations;

// -----------------------------------------------------------------------
// state_diff unit tests
// -----------------------------------------------------------------------

#[test]
fn test_find_mutations_balance_change() {
    let v0 = make_response(0, 32);
    let v1_old = make_response(1, 32);
    let v1_new = make_response(1, 16);
    let v2 = make_response(2, 32);

    let old = vec![v0.clone(), v1_old, v2.clone()];
    let new = vec![v0, v1_new, v2];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![1]);
}

#[test]
fn test_find_mutations_new_validators() {
    let v0 = make_response(0, 32);
    let v1 = make_response(1, 32);
    let v2 = make_response(2, 32);

    let old = vec![v0.clone(), v1.clone()];
    let new = vec![v0, v1, v2];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![2]);
}

#[test]
fn test_find_mutations_no_changes() {
    let v0 = make_response(0, 32);
    let v1 = make_response(1, 32);

    let old = vec![v0.clone(), v1.clone()];
    let new = vec![v0, v1];

    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());
}

#[test]
fn test_find_mutations_activation_change() {
    let v0 = make_response(0, 32);
    let mut v0_new = make_response(0, 32);
    v0_new.exit_epoch = 100; // validator exiting

    let old = vec![v0];
    let new = vec![v0_new];

    let changed = find_mutations(&old, &new, 100, 100);
    assert_eq!(changed, vec![0]);
}

#[test]
fn test_find_mutations_epoch_boundary_activation() {
    // Validator activates at epoch 101 — no SSZ field changes between states
    let mut v = make_response(0, 32);
    v.activation_epoch = 101;
    v.exit_epoch = u64::MAX;

    let old = vec![v.clone()];
    let new = vec![v];

    // Same epoch: not detected
    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());

    // Spans activation: detected
    let changed = find_mutations(&old, &new, 100, 101);
    assert_eq!(changed, vec![0]);
}

#[test]
fn test_find_mutations_epoch_boundary_exit() {
    // Validator exits at epoch 101 — no SSZ field changes between states
    let mut v = make_response(0, 32);
    v.activation_epoch = 0;
    v.exit_epoch = 101;

    let old = vec![v.clone()];
    let new = vec![v];

    // Same epoch: not detected
    let changed = find_mutations(&old, &new, 100, 100);
    assert!(changed.is_empty());

    // Spans exit: detected
    let changed = find_mutations(&old, &new, 100, 101);
    assert_eq!(changed, vec![0]);
}

// -----------------------------------------------------------------------
// DB tests
// -----------------------------------------------------------------------

#[test]
fn test_db_save_and_load() {
    use zkasper_witness_gen::db::Db;
    use zkasper_witness_gen::poseidon_tree::PoseidonTree;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Db::new(&db_path);

    let validators: Vec<_> = (0..4).map(|i| make_validator(i, 32)).collect();
    let tree = PoseidonTree::build(&validators, 100, 2);
    let expected_root = tree.root();

    db.save(&tree, 100, 128_000_000_000, 4).unwrap();

    let (loaded_tree, epoch, balance, count) = db.load().unwrap().expect("should load");
    assert_eq!(loaded_tree.root(), expected_root);
    assert_eq!(epoch, 100);
    assert_eq!(balance, 128_000_000_000);
    assert_eq!(count, 4);
}

#[test]
fn test_db_load_nonexistent() {
    use zkasper_witness_gen::db::Db;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nonexistent.db");
    let db = Db::new(&db_path);

    assert!(db.load().unwrap().is_none());
}

// -----------------------------------------------------------------------
// Bootstrap round-trip test
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_bootstrap_round_trip() {
    let slot = 3200u64; // epoch 100
    let epoch = slot / SLOTS_PER_EPOCH;

    let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let responses: Vec<ValidatorResponse> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header = make_header(slot, &responses, TEST_DEPTH);
    mock.validators.insert(slot.to_string(), responses.clone());
    mock.headers.insert(slot.to_string(), header);

    let (witness, tree, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, slot, TEST_DEPTH)
            .await
            .unwrap();

    assert_eq!(num_validators, 4);
    assert_eq!(total_active_balance, 4 * 32_000_000_000);
    assert_eq!(witness.epoch, epoch);
    assert_eq!(witness.validators.len(), 4);

    // Verify with bootstrap guest verification function
    let (commitment, poseidon_root, balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(&witness, TEST_DEPTH);

    assert_eq!(poseidon_root, tree.root());
    assert_eq!(balance, total_active_balance);

    let expected_commitment = accumulator_commitment(&poseidon_root, total_active_balance);
    assert_eq!(commitment, expected_commitment);
}

// -----------------------------------------------------------------------
// Epoch diff round-trip test
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_epoch_diff_round_trip() {
    let slot_1 = 3200u64; // epoch 100
    let slot_2 = 3232u64; // epoch 101

    // 4 validators, validator 1 changes balance from 32 -> 16 ETH
    let validators_1: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let mut validators_2 = validators_1.clone();
    validators_2[1].effective_balance = 16_000_000_000;

    let responses_1: Vec<ValidatorResponse> = validators_1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();
    let responses_2: Vec<ValidatorResponse> = validators_2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH);
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH);
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // First bootstrap to build the PoseidonTree
    let (_, mut tree, total_active_balance_1, _) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, slot_1, TEST_DEPTH)
            .await
            .unwrap();

    let old_root = tree.root();

    // Then epoch diff
    let (witness, new_total_active_balance, new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &mut tree,
            slot_1,
            slot_2,
            total_active_balance_1,
            TEST_DEPTH,
        )
        .await
        .unwrap();

    assert_eq!(new_num_validators, 4);
    let expected_balance = 3 * 32_000_000_000 + 16_000_000_000;
    assert_eq!(new_total_active_balance, expected_balance);
    assert_ne!(tree.root(), old_root);

    // Verify with epoch-diff guest verification function
    let (commitment, poseidon_root, balance) =
        zkasper_epoch_diff_guest::verify_epoch_diff(&witness);

    assert_eq!(poseidon_root, tree.root());
    assert_eq!(balance, new_total_active_balance);

    let expected_commitment = accumulator_commitment(&poseidon_root, balance);
    assert_eq!(commitment, expected_commitment);
}

// -----------------------------------------------------------------------
// Full pipeline: bootstrap -> epoch diff
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_full_pipeline_bootstrap_then_epoch_diff() {
    let slot_1 = 3200u64;
    let slot_2 = 3232u64;

    // 4 validators, validator 0: exits at epoch 101, validator 3: balance 32 -> 24
    let validators_1: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let mut validators_2 = validators_1.clone();
    validators_2[0].exit_epoch = 101; // will be inactive at epoch 101
    validators_2[3].effective_balance = 24_000_000_000;

    let responses_1: Vec<ValidatorResponse> = validators_1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();
    let responses_2: Vec<ValidatorResponse> = validators_2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi::new();
    let header_1 = make_header(slot_1, &responses_1, TEST_DEPTH);
    let header_2 = make_header(slot_2, &responses_2, TEST_DEPTH);
    mock.validators
        .insert(slot_1.to_string(), responses_1.clone());
    mock.validators
        .insert(slot_2.to_string(), responses_2.clone());
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    // Bootstrap
    let (bootstrap_witness, tree, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&mock, slot_1, TEST_DEPTH)
            .await
            .unwrap();

    // Verify bootstrap
    let (_bootstrap_commitment, bootstrap_poseidon_root, bootstrap_balance) =
        zkasper_bootstrap_guest::verify_bootstrap_with_depth(&bootstrap_witness, TEST_DEPTH);
    assert_eq!(bootstrap_poseidon_root, tree.root());
    assert_eq!(bootstrap_balance, total_active_balance);

    // Save + load via DB
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = zkasper_witness_gen::db::Db::new(&db_path);
    db.save(&tree, 100, total_active_balance, num_validators)
        .unwrap();

    let (mut loaded_tree, _cursor_epoch, loaded_balance, _loaded_count) =
        db.load().unwrap().expect("should load");
    assert_eq!(loaded_tree.root(), tree.root());

    // Epoch diff
    let (epoch_diff_witness, new_balance, _new_count) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &mut loaded_tree,
            slot_1,
            slot_2,
            loaded_balance,
            TEST_DEPTH,
        )
        .await
        .unwrap();

    // Verify epoch diff
    let (_diff_commitment, diff_poseidon_root, diff_balance) =
        zkasper_epoch_diff_guest::verify_epoch_diff(&epoch_diff_witness);

    assert_eq!(diff_poseidon_root, loaded_tree.root());
    assert_eq!(diff_balance, new_balance);

    // epoch 101: v0 exits (0 ETH active), v1=32, v2=32, v3=24
    let expected = 0 + 32_000_000_000 + 32_000_000_000 + 24_000_000_000;
    assert_eq!(new_balance, expected);
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

fn make_response(index: u8, balance_eth: u64) -> ValidatorResponse {
    let v = make_validator(index, balance_eth);
    validator_data_to_response(&v, index as u64)
}
