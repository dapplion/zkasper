#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bls;
pub mod merkle;
#[cfg(feature = "count-ops")]
pub mod op_counter;
pub mod poseidon;
pub mod ssz;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod recursion;
pub mod types;

/// Network-specific configuration for beacon chain parameters.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub slots_per_epoch: u64,
    pub validators_tree_depth: u32,
    pub poseidon_tree_depth: u32,
    pub beacon_state_validators_field_index: u64,
}

impl ChainConfig {
    pub const MAINNET: Self = Self {
        slots_per_epoch: 32,
        validators_tree_depth: 40,
        poseidon_tree_depth: 22,
        beacon_state_validators_field_index: 11,
    };

    pub const GNOSIS: Self = Self {
        slots_per_epoch: 16,
        validators_tree_depth: 40,
        poseidon_tree_depth: 22,
        beacon_state_validators_field_index: 11,
    };
}

/// Beacon chain constants
pub mod constants {
    /// Depth of the SSZ validators data tree (capacity 2^40, per spec).
    pub const VALIDATORS_TREE_DEPTH: u32 = 40;

    /// Depth of the Poseidon accumulator tree (capacity 2^22 = 4,194,304).
    /// Independent of the SSZ tree depth — only needs to hold the actual
    /// validator count (~2.2M as of 2025).
    pub const POSEIDON_TREE_DEPTH: u32 = 22;

    /// Number of fields in a Validator container
    pub const VALIDATOR_FIELDS_COUNT: usize = 8;

    /// Generalized index of `validators` in BeaconState (field index 11, depth 6 for Fulu)
    pub const BEACON_STATE_VALIDATORS_FIELD_INDEX: u64 = 11;

    /// Slots per epoch
    pub const SLOTS_PER_EPOCH: u64 = 32;

    /// BLS domain type for beacon attester
    pub const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

    /// Far future epoch sentinel
    pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;
}
