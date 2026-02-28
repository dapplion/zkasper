use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Merkle multi-proof: verify multiple leaves against a single root
/// using a minimal set of auxiliary sibling nodes.
///
/// The auxiliary nodes are ordered bottom-up, left-to-right — the same
/// order the verifier consumes them when walking from leaves to root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleMultiProof {
    pub auxiliaries: Vec<[u8; 32]>,
}

/// 48-byte BLS public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPubkey(#[serde(with = "BigArray")] pub [u8; 48]);

/// 96-byte BLS signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsSignature(#[serde(with = "BigArray")] pub [u8; 96]);

/// Minimal validator data — only the fields needed for zkasper.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorData {
    pub pubkey: BlsPubkey,
    /// Effective balance in Gwei.
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

impl ValidatorData {
    /// Whether this validator is active at the given epoch.
    pub fn is_active(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `effective_balance` if active, else 0.
    pub fn active_effective_balance(&self, epoch: u64) -> u64 {
        if self.is_active(epoch) {
            self.effective_balance
        } else {
            0
        }
    }
}

/// Casper FFG checkpoint (epoch + block root).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

/// One changed validator between two consecutive epochs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorMutation {
    pub validator_index: u64,
    /// True if this validator is new (not present in the old state).
    /// When true, the old leaf in both SSZ and Poseidon trees is all-zeros.
    pub is_new: bool,
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    /// 8 field-level SSZ hash-tree leaves for the Validator container.
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    /// Raw pubkey split into 2x32-byte SSZ chunks (to verify field_leaves[0]).
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    /// Poseidon Merkle siblings (depth = POSEIDON_TREE_DEPTH).
    pub poseidon_siblings: Vec<[u8; 32]>,
}

/// Witness for Proof 1: Epoch Diff.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochDiffWitness {
    // -- public inputs (bound by on-chain state) --
    pub state_root_1: [u8; 32],
    pub state_root_2: [u8; 32],
    pub poseidon_root_1: [u8; 32],
    pub total_active_balance_1: u64,
    /// Epoch of state_root_1 (used for old is_active checks).
    pub epoch_1: u64,
    /// Epoch of state_root_2 (used for new is_active checks).
    pub epoch_2: u64,

    // -- SSZ proof: state_root -> validators data tree root --
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,

    // -- mutations --
    pub mutations: Vec<ValidatorMutation>,

    // -- SSZ multi-proofs for validator trees --
    /// Multi-proof for old validator tree (state 1).
    pub ssz_multi_proof_1: MerkleMultiProof,
    /// Multi-proof for new validator tree (state 2).
    pub ssz_multi_proof_2: MerkleMultiProof,
}

/// Per-validator data carried inside an attestation witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestingValidator {
    pub validator_index: u64,
    pub pubkey: BlsPubkey,
    pub active_effective_balance: u64,
    /// Whether this validator's balance should be counted towards the
    /// attesting total. False when the same validator appears in an
    /// earlier attestation (prevents double-counting).
    pub count_balance: bool,
}

/// One aggregated attestation for the finality proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationWitness {
    // -- Raw AttestationData fields (circuit recomputes hash_tree_root) --
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    /// Aggregate BLS signature over the signing root.
    pub signature: BlsSignature,
    /// All validators that participated (bit set in aggregation_bits).
    pub attesting_validators: Vec<AttestingValidator>,
}

/// Witness for Proof 2: Finality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityWitness {
    // -- public inputs (circuit outputs) --
    /// `poseidon(poseidon_root, total_active_balance)` — binds to the accumulator
    /// state tracked by the epoch-diff chain. The circuit verifies this internally.
    pub accumulator_commitment: [u8; 32],
    /// The block root being proven finalized (circuit output).
    pub finalized_block_root: [u8; 32],

    // -- private witness --
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    /// `compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_validators_root)`,
    /// precomputed by the witness generator.
    pub signing_domain: [u8; 32],

    // -- attestations --
    pub attestations: Vec<AttestationWitness>,

    /// Poseidon multi-proof for all unique attesting validators at once.
    /// Proves every (poseidon_leaf, validator_index) against poseidon_root.
    pub poseidon_multi_proof: MerkleMultiProof,
}

// ---------------------------------------------------------------------------
// Slot-level proving types (incremental architecture)
// ---------------------------------------------------------------------------

/// Public outputs of a slot proof.
///
/// After recursive verification, the justification circuit sees only these values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotProofOutput {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    /// Sum of `active_effective_balance` for validators with `count_balance=true`.
    pub attesting_balance: u64,
    /// Poseidon hash chain over sorted counted validator indices.
    pub counted_validators_commitment: [u8; 32],
    /// Number of counted validators (for commitment verification).
    pub num_counted_validators: u64,
}

/// Witness for a slot proof (one block's attestations).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotProofWitness {
    // -- public inputs --
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],

    // -- private witness --
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub attestations: Vec<AttestationWitness>,
    pub poseidon_multi_proof: MerkleMultiProof,
}

/// Public outputs of a justification proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JustificationOutput {
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
}

/// Witness for a justification proof (aggregates slot proofs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JustificationWitness {
    // -- public inputs --
    pub accumulator_commitment: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub total_active_balance: u64,

    // -- slot proof outputs (verified recursively via ziskos::verify_proof) --
    pub slot_proof_outputs: Vec<SlotProofOutput>,
    /// Opaque proof bytes per slot (empty in native testing mode).
    pub slot_proof_proofs: Vec<Vec<u8>>,

    // -- dedup witness: per-slot sorted counted validator indices --
    pub counted_indices_per_slot: Vec<Vec<u64>>,
}

/// Public outputs of a finalization proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizationOutput {
    pub accumulator_commitment: [u8; 32],
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
}

/// Witness for a finalization proof (pairs two consecutive justifications).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizationWitness {
    pub accumulator_commitment: [u8; 32],
    /// Justification outputs for epochs E and E+1.
    pub justification_outputs: Vec<JustificationOutput>,
    /// Opaque proof bytes for each justification (empty in native testing mode).
    pub justification_proofs: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Original types
// ---------------------------------------------------------------------------

/// Witness for Bootstrap: one-time Poseidon tree construction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapWitness {
    pub state_root: [u8; 32],
    pub epoch: u64,
    pub validators: Vec<ValidatorData>,
    /// SSZ proof from state_root to the validators data tree root.
    pub state_to_validators_siblings: Vec<[u8; 32]>,
    pub validators_list_length: u64,
    /// Per-validator: the 8 SSZ field-level hash-tree leaves.
    pub validator_field_chunks: Vec<[[u8; 32]; 8]>,
    /// Per-validator: raw pubkey split into 2x32-byte SSZ chunks.
    pub validator_pubkey_chunks: Vec<[[u8; 32]; 2]>,
}
