//! Integration tests using real SSZ beacon state files.
//!
//! State blobs are hosted as GitHub release assets and downloaded on first run.
//! Files are cached in `test_data/` to avoid re-downloading (~320MB each).
//!
//! Run with:
//! ```sh
//! cargo test --release --test ssz_file_tests -- --ignored --nocapture
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;

use zkasper_common::constants::{SLOTS_PER_EPOCH, VALIDATORS_TREE_DEPTH};
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, CommitteeResponse, HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::ssz_state;

// ---------------------------------------------------------------------------
// Test data definitions
// ---------------------------------------------------------------------------

const GITHUB_REPO: &str = "dapplion/zkasper";
const RELEASE_TAG: &str = "test-data-v1";

struct TestState {
    filename: &'static str,
    expected_root: &'static str,
}

const STATE_1: TestState = TestState {
    filename: "state_13776608.ssz",
    expected_root: "521d21fb0fffa1e7197ae149ae7c2d81bd66cd30be6cd5744f3a4f7105c5daef",
};

const STATE_2: TestState = TestState {
    filename: "state_13776928.ssz",
    expected_root: "3a9ab0228848b15f90fdd878cac181ab80e5109147a72534b7038b446ee1c8c9",
};

// ---------------------------------------------------------------------------
// File-backed BeaconApi
// ---------------------------------------------------------------------------

struct SszFileApi {
    states: HashMap<String, Arc<StateData>>,
}

struct StateData {
    raw_ssz: Vec<u8>,
    validators: Vec<ValidatorResponse>,
    header: HeaderResponse,
}

impl SszFileApi {
    fn load(entries: &[(&str, &str)]) -> Self {
        let mut states = HashMap::new();

        for &(path, expected_root_hex) in entries {
            eprintln!("loading SSZ state from {path}...");
            let raw_ssz = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            eprintln!("  {} bytes", raw_ssz.len());

            let (state_root, _num_validators) = ssz_state::compute_fulu_state_root(&raw_ssz)
                .unwrap_or_else(|e| panic!("compute state root for {path}: {e}"));

            let expected_bytes = hex::decode(expected_root_hex).unwrap();
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&expected_bytes);
            assert_eq!(state_root, expected_root, "state root mismatch for {path}");
            eprintln!("  state root verified: 0x{}", hex::encode(state_root));

            let validators = ssz_state::extract_validators(&raw_ssz)
                .unwrap_or_else(|e| panic!("extract validators from {path}: {e}"));
            eprintln!("  {} validators", validators.len());

            let mut header = ssz_state::extract_header(&raw_ssz)
                .unwrap_or_else(|e| panic!("extract header from {path}: {e}"));
            header.state_root = state_root;

            let slot_str = header.slot.to_string();
            eprintln!("  slot: {}", header.slot);

            states.insert(
                slot_str,
                Arc::new(StateData {
                    raw_ssz,
                    validators,
                    header,
                }),
            );
        }

        SszFileApi { states }
    }

    fn get_state(&self, state_id: &str) -> &StateData {
        self.states
            .get(state_id)
            .unwrap_or_else(|| panic!("no state loaded for id '{state_id}'"))
    }
}

#[async_trait::async_trait]
impl BeaconApi for SszFileApi {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>> {
        Ok(self.get_state(state_id).validators.clone())
    }

    async fn get_block_attestations(&self, _block_id: &str) -> Result<Vec<AttestationResponse>> {
        Ok(vec![])
    }

    async fn get_committees(&self, _state_id: &str, _epoch: u64) -> Result<Vec<CommitteeResponse>> {
        Ok(vec![])
    }

    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse> {
        Ok(self.get_state(block_id).header.clone())
    }

    async fn get_state_ssz(&self, state_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.get_state(state_id).raw_ssz.clone()))
    }
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

/// Get the path to the test_data directory (repo root / test_data).
fn test_data_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_data")
}

/// Ensure a test state file exists locally, downloading from GitHub release if needed.
fn ensure_state(state: &TestState) -> String {
    let dir = test_data_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(state.filename);

    if path.exists() {
        return path.to_str().unwrap().to_string();
    }

    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_TAG}/{}",
        state.filename
    );
    eprintln!("downloading {url} ...");

    let status = std::process::Command::new("curl")
        .args(["-L", "-f", "-o", path.to_str().unwrap(), &url])
        .status()
        .expect("failed to run curl");

    assert!(status.success(), "failed to download {}", state.filename);
    eprintln!("  saved to {}", path.display());

    path.to_str().unwrap().to_string()
}

fn load_one_state() -> (SszFileApi, u64) {
    let path1 = ensure_state(&STATE_1);
    let api = SszFileApi::load(&[(&path1, STATE_1.expected_root)]);
    let slot = api.states.values().next().unwrap().header.slot;
    (api, slot)
}

fn load_two_states() -> (SszFileApi, u64, u64) {
    let path1 = ensure_state(&STATE_1);
    let path2 = ensure_state(&STATE_2);
    let api = SszFileApi::load(&[
        (&path1, STATE_1.expected_root),
        (&path2, STATE_2.expected_root),
    ]);

    let slots: Vec<u64> = api.states.values().map(|s| s.header.slot).collect();
    let slot_1 = *slots.iter().min().unwrap();
    let slot_2 = *slots.iter().max().unwrap();

    (api, slot_1, slot_2)
}

// ---------------------------------------------------------------------------
// Test: bootstrap witness generation from SSZ file
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~320MB, takes ~2min"]
async fn test_ssz_file_bootstrap() {
    let (api, slot) = load_one_state();
    let epoch = slot / SLOTS_PER_EPOCH;
    eprintln!("\ntesting bootstrap at slot {slot} (epoch {epoch})");

    let (witness, tree, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, slot, VALIDATORS_TREE_DEPTH)
            .await
            .unwrap();

    eprintln!("  validators: {num_validators}");
    eprintln!("  total_active_balance: {total_active_balance}");
    eprintln!("  poseidon_root: 0x{}", hex::encode(tree.root()));

    assert!(num_validators > 0);
    assert!(total_active_balance > 0);
    assert_eq!(witness.epoch, epoch);
    assert_eq!(witness.validators.len(), num_validators as usize);
    assert_eq!(witness.state_to_validators_siblings.len(), 6);

    eprintln!("  witness generation OK");
}

// ---------------------------------------------------------------------------
// Test: epoch diff witness generation + guest verification
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~640MB, takes ~3min"]
async fn test_ssz_file_epoch_diff() {
    let (api, slot_1, slot_2) = load_two_states();
    let epoch_1 = slot_1 / SLOTS_PER_EPOCH;
    let epoch_2 = slot_2 / SLOTS_PER_EPOCH;

    eprintln!(
        "\ntesting epoch diff: slot {slot_1} (epoch {epoch_1}) -> slot {slot_2} (epoch {epoch_2})"
    );

    // Bootstrap at slot_1
    eprintln!("  bootstrapping at slot {slot_1}...");
    let (_witness, mut tree, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, slot_1, VALIDATORS_TREE_DEPTH)
            .await
            .unwrap();

    eprintln!("  bootstrap: {num_validators} validators, balance={total_active_balance}");
    eprintln!("  poseidon_root: 0x{}", hex::encode(tree.root()));

    // Epoch diff
    eprintln!("  computing epoch diff...");
    let (diff_witness, new_balance, new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &mut tree,
            slot_1,
            slot_2,
            total_active_balance,
            VALIDATORS_TREE_DEPTH,
        )
        .await
        .unwrap();

    eprintln!(
        "  epoch diff: {} mutations, new_validators={new_num_validators}, new_balance={new_balance}",
        diff_witness.mutations.len()
    );
    eprintln!("  new poseidon_root: 0x{}", hex::encode(tree.root()));

    assert!(!diff_witness.mutations.is_empty());
    assert_eq!(diff_witness.state_to_validators_siblings_1.len(), 6);
    assert_eq!(diff_witness.state_to_validators_siblings_2.len(), 6);

    eprintln!("  witness generation OK, verifying in guest...");

    // Verify the witness through the guest circuit logic
    let (commitment, poseidon_root, total_active_balance_out) =
        zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);

    assert_eq!(
        poseidon_root,
        tree.root(),
        "poseidon root mismatch after verify"
    );
    assert_eq!(
        total_active_balance_out, new_balance,
        "total active balance mismatch"
    );
    assert_eq!(
        commitment,
        zkasper_common::poseidon::accumulator_commitment(&poseidon_root, total_active_balance_out),
    );

    let new_count = diff_witness.mutations.iter().filter(|m| m.is_new).count();
    let changed_count = diff_witness.mutations.len() - new_count;
    eprintln!("  guest verification OK: {changed_count} changed + {new_count} new validators");
    eprintln!("  commitment: 0x{}", hex::encode(commitment));
}
