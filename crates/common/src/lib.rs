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
pub mod types;

/// Beacon chain constants
pub mod constants {
    /// Depth of the validators data tree (capacity 2^40)
    pub const VALIDATORS_TREE_DEPTH: u32 = 40;

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
