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
use tracing_subscriber::fmt::format::FmtSpan;

use zkasper_common::constants::{SLOTS_PER_EPOCH, VALIDATORS_TREE_DEPTH};
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, CommitteeResponse, HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::ssz_state;

// ---------------------------------------------------------------------------
// Tracing setup
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

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
            let raw_ssz = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));

            let (state_root, _num_validators) = ssz_state::compute_fulu_state_root(&raw_ssz)
                .unwrap_or_else(|e| panic!("compute state root for {path}: {e}"));

            let expected_bytes = hex::decode(expected_root_hex).unwrap();
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&expected_bytes);
            assert_eq!(state_root, expected_root, "state root mismatch for {path}");

            let validators = ssz_state::extract_validators(&raw_ssz)
                .unwrap_or_else(|e| panic!("extract validators from {path}: {e}"));

            let mut header = ssz_state::extract_header(&raw_ssz)
                .unwrap_or_else(|e| panic!("extract header from {path}: {e}"));
            header.state_root = state_root;

            let slot_str = header.slot.to_string();

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
    init_tracing();

    let (api, slot) = load_one_state();
    let epoch = slot / SLOTS_PER_EPOCH;
    eprintln!("testing bootstrap at slot {slot} (epoch {epoch})");

    let (witness, _tree, _epoch_state, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, slot, VALIDATORS_TREE_DEPTH)
            .await
            .unwrap();

    assert!(num_validators > 0);
    assert!(total_active_balance > 0);
    assert_eq!(witness.epoch, epoch);
    assert_eq!(witness.validators.len(), num_validators as usize);
    assert_eq!(witness.state_to_validators_siblings.len(), 6);
}

// ---------------------------------------------------------------------------
// Test: epoch diff witness generation + guest verification
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~640MB, takes ~3min"]
async fn test_ssz_file_epoch_diff() {
    init_tracing();

    let (api, slot_1, slot_2) = load_two_states();
    let epoch_1 = slot_1 / SLOTS_PER_EPOCH;
    let epoch_2 = slot_2 / SLOTS_PER_EPOCH;
    eprintln!("testing epoch diff: slot {slot_1} (epoch {epoch_1}) -> slot {slot_2} (epoch {epoch_2})");

    // Bootstrap at slot_1
    let (_witness, mut tree, epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, slot_1, VALIDATORS_TREE_DEPTH)
            .await
            .unwrap();

    // Epoch diff
    let (diff_witness, _new_epoch_state, new_balance, _new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance,
            VALIDATORS_TREE_DEPTH,
        )
        .await
        .unwrap();

    assert!(!diff_witness.mutations.is_empty());
    assert_eq!(diff_witness.state_to_validators_siblings_1.len(), 6);
    assert_eq!(diff_witness.state_to_validators_siblings_2.len(), 6);

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
}

// ---------------------------------------------------------------------------
// Benchmark: count circuit operations in epoch-diff guest
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~640MB, takes ~3min"]
async fn bench_epoch_diff_guest_ops() {
    use zkasper_common::op_counter;
    use zkasper_common::poseidon::{compute_poseidon_merkle_root, poseidon_leaf};
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root, verify_field_leaves,
        verify_ssz_multi_proof,
    };

    init_tracing();

    let (api, slot_1, slot_2) = load_two_states();
    let epoch_1 = slot_1 / SLOTS_PER_EPOCH;
    let epoch_2 = slot_2 / SLOTS_PER_EPOCH;

    // Build witness (host-side, not measured)
    let (_witness, mut tree, epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, slot_1, VALIDATORS_TREE_DEPTH)
            .await
            .unwrap();

    let (diff_witness, _new_epoch_state, _new_balance, _new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance,
            VALIDATORS_TREE_DEPTH,
        )
        .await
        .unwrap();

    let num_mutations = diff_witness.mutations.len();
    eprintln!("\n=== epoch-diff guest op count ({num_mutations} mutations) ===\n");

    // --- Measure the full guest verification ---
    op_counter::reset();
    let before_total = op_counter::snapshot();
    let _ = zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);
    let total = op_counter::snapshot().delta(&before_total);
    eprintln!("TOTAL:              {total}");

    // --- Per-phase breakdown: replay the guest logic manually ---
    // Phase 1: verify_field_leaves (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if !m.is_new {
            verify_field_leaves(&m.old_data, &m.old_field_leaves, &m.old_pubkey_chunks);
        }
        verify_field_leaves(&m.new_data, &m.new_field_leaves, &m.new_pubkey_chunks);
    }
    let phase_field_leaves = op_counter::snapshot().delta(&s0);
    eprintln!("verify_field_leaves: {phase_field_leaves}");

    // Phase 2: validator_hash_tree_root (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if !m.is_new {
            validator_hash_tree_root(&m.old_field_leaves);
        }
        validator_hash_tree_root(&m.new_field_leaves);
    }
    let phase_htr = op_counter::snapshot().delta(&s0);
    eprintln!("validator_htr:       {phase_htr}");

    // Phase 3: SSZ multi-proof verification (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    {
        let old_leaves: Vec<([u8; 32], u64)> = diff_witness.mutations.iter().map(|m| {
            let idx = m.validator_index;
            if m.is_new {
                ([0u8; 32], idx)
            } else {
                (validator_hash_tree_root(&m.old_field_leaves), idx)
            }
        }).collect();
        let new_leaves: Vec<([u8; 32], u64)> = diff_witness.mutations.iter().map(|m| {
            (validator_hash_tree_root(&m.new_field_leaves), m.validator_index)
        }).collect();
        verify_ssz_multi_proof(&old_leaves, &diff_witness.ssz_multi_proof_1, VALIDATORS_TREE_DEPTH);
        verify_ssz_multi_proof(&new_leaves, &diff_witness.ssz_multi_proof_2, VALIDATORS_TREE_DEPTH);
    }
    let phase_ssz_merkle = op_counter::snapshot().delta(&s0);
    let ssz_merkle_sha256 = phase_ssz_merkle.sha256 - phase_htr.sha256;
    eprintln!("ssz_multi_proofs:    sha256: {} (~{}M constraints)",
        ssz_merkle_sha256,
        ssz_merkle_sha256 * 29_000 / 1_000_000,
    );

    // Phase 4: Poseidon leaf computation (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if !m.is_new {
            let old_balance = m.old_data.active_effective_balance(epoch_1);
            poseidon_leaf(&m.old_data.pubkey.0, old_balance);
        }
        let new_balance = m.new_data.active_effective_balance(epoch_2);
        poseidon_leaf(&m.new_data.pubkey.0, new_balance);
    }
    let phase_poseidon_leaf = op_counter::snapshot().delta(&s0);
    eprintln!("poseidon_leaf:       {phase_poseidon_leaf}");

    // Phase 5: Poseidon Merkle proofs (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        let idx = m.validator_index;
        if m.is_new {
            compute_poseidon_merkle_root(&[0u8; 32], idx, &m.poseidon_siblings);
        } else {
            let old_balance = m.old_data.active_effective_balance(epoch_1);
            let old_leaf = poseidon_leaf(&m.old_data.pubkey.0, old_balance);
            compute_poseidon_merkle_root(&old_leaf, idx, &m.poseidon_siblings);
        }
        let new_balance = m.new_data.active_effective_balance(epoch_2);
        let new_leaf = poseidon_leaf(&m.new_data.pubkey.0, new_balance);
        compute_poseidon_merkle_root(&new_leaf, idx, &m.poseidon_siblings);
    }
    let phase_poseidon_merkle = op_counter::snapshot().delta(&s0);
    let poseidon_merkle_t3 = phase_poseidon_merkle.poseidon_t3 - phase_poseidon_leaf.poseidon_t3;
    eprintln!("poseidon_merkle:     poseidon_t3: {} (~{}k constraints), (leaf ops excluded)",
        poseidon_merkle_t3,
        poseidon_merkle_t3 * 250 / 1_000,
    );

    // Phase 6: State proofs (2x list_hash_tree_root + 2x compute_ssz_merkle_root)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    let dummy = [0u8; 32];
    list_hash_tree_root(&dummy, 100);
    list_hash_tree_root(&dummy, 100);
    compute_ssz_merkle_root(&dummy, 11, &diff_witness.state_to_validators_siblings_1);
    compute_ssz_merkle_root(&dummy, 11, &diff_witness.state_to_validators_siblings_2);
    let phase_state_proof = op_counter::snapshot().delta(&s0);
    eprintln!("state_proofs:        {phase_state_proof}");

    // Phase 7: accumulator_commitment (1 poseidon_pair)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    zkasper_common::poseidon::accumulator_commitment(&dummy, 100);
    let phase_commit = op_counter::snapshot().delta(&s0);
    eprintln!("accumulator_commit:  {phase_commit}");

    // Summary
    eprintln!("\n=== constraint breakdown ===\n");
    let items: &[(&str, u64)] = &[
        ("verify_field_leaves", phase_field_leaves.total_constraints()),
        ("validator_htr", phase_htr.total_constraints()),
        ("ssz_multi_proofs", ssz_merkle_sha256 * 29_000),
        ("poseidon_leaf", phase_poseidon_leaf.total_constraints()),
        ("poseidon_merkle", poseidon_merkle_t3 * 250),
        ("state_proofs", phase_state_proof.total_constraints()),
        ("accumulator_commit", phase_commit.total_constraints()),
    ];
    let grand_total: u64 = items.iter().map(|(_, c)| c).sum();
    for (name, constraints) in items {
        let pct = (*constraints as f64 / grand_total as f64) * 100.0;
        eprintln!("  {name:24} {constraints:>12} ({pct:5.1}%)");
    }
    eprintln!("  {:24} {:>12}", "TOTAL", grand_total);
    eprintln!("\n  per mutation: ~{} constraints", grand_total / num_mutations as u64);

    eprintln!("\n  multi-proof auxiliaries: old={}, new={}",
        diff_witness.ssz_multi_proof_1.auxiliaries.len(),
        diff_witness.ssz_multi_proof_2.auxiliaries.len());
}
