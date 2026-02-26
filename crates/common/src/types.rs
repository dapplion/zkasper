use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

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
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    /// 8 field-level SSZ hash-tree leaves for the Validator container.
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    /// Raw pubkey split into 2x32-byte SSZ chunks (to verify field_leaves[0]).
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    /// SHA-256 Merkle siblings in the validators data tree (depth 40).
    pub old_ssz_siblings: Vec<[u8; 32]>,
    pub new_ssz_siblings: Vec<[u8; 32]>,
    /// Poseidon Merkle siblings (depth 40).
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
    /// Epoch of state_root_2 (used for is_active checks).
    pub epoch_2: u64,

    // -- SSZ proof: state_root -> validators data tree root --
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,

    // -- mutations --
    pub mutations: Vec<ValidatorMutation>,
}

/// Per-validator data carried inside an attestation witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestingValidator {
    pub validator_index: u64,
    pub pubkey: BlsPubkey,
    pub active_effective_balance: u64,
    /// Poseidon Merkle siblings (depth 40).
    pub poseidon_siblings: Vec<[u8; 32]>,
}

/// One aggregated attestation for the finality proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationWitness {
    /// `hash_tree_root(AttestationData)` — the guest trusts this is correctly
    /// derived from an `AttestationData` whose `target` matches the claimed
    /// finalized checkpoint. Full verification of the other AttestationData
    /// fields is deferred to V2.
    pub attestation_data_root: [u8; 32],
    /// Aggregate BLS signature over the signing root.
    pub signature: BlsSignature,
    /// All validators that participated (bit set in aggregation_bits).
    pub attesting_validators: Vec<AttestingValidator>,
}

/// Witness for Proof 2: Finality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityWitness {
    // -- public inputs --
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub finalized_checkpoint: Checkpoint,
    /// `compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_validators_root)`,
    /// precomputed by the witness generator.
    pub signing_domain: [u8; 32],

    // -- attestations --
    pub attestations: Vec<AttestationWitness>,
}

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
