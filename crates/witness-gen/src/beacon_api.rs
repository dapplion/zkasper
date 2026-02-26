//! Beacon REST API client.
//!
//! Talks to a standard Ethereum beacon node via the Beacon API:
//! - `/eth/v2/debug/beacon/states/{state_id}` — full SSZ state
//! - `/eth/v1/beacon/states/{state_id}/validators` — validator list
//! - `/eth/v1/beacon/blocks/{block_id}/attestations` — block attestations
//! - `/eth/v1/beacon/states/{state_id}/committees` — committee assignments
//! - `/eth/v1/beacon/headers/{block_id}` — block header

use anyhow::Result;

pub struct BeaconApiClient {
    pub base_url: String,
    pub client: reqwest::Client,
}

impl BeaconApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Fetch the full list of validators at a given state.
    pub async fn get_validators(&self, _state_id: &str) -> Result<Vec<ValidatorResponse>> {
        todo!()
    }

    /// Fetch attestations from a block.
    pub async fn get_block_attestations(
        &self,
        _block_id: &str,
    ) -> Result<Vec<AttestationResponse>> {
        todo!()
    }

    /// Fetch committee assignments for an epoch.
    pub async fn get_committees(
        &self,
        _state_id: &str,
        _epoch: u64,
    ) -> Result<Vec<CommitteeResponse>> {
        todo!()
    }

    /// Fetch a block header.
    pub async fn get_header(&self, _block_id: &str) -> Result<HeaderResponse> {
        todo!()
    }
}

// Placeholder response types — will be filled in when implementing the API calls.

#[derive(Debug)]
pub struct ValidatorResponse {
    pub index: u64,
    pub pubkey: [u8; 48],
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    // All 8 SSZ field chunks for this validator
    pub withdrawal_credentials: [u8; 32],
    pub slashed: bool,
    pub activation_eligibility_epoch: u64,
    pub withdrawable_epoch: u64,
}

#[derive(Debug)]
pub struct AttestationResponse {
    pub aggregation_bits: Vec<u8>,
    pub committee_bits: Vec<u8>,
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    pub signature: [u8; 96],
}

#[derive(Debug)]
pub struct CommitteeResponse {
    pub slot: u64,
    pub index: u64,
    pub validators: Vec<u64>,
}

#[derive(Debug)]
pub struct HeaderResponse {
    pub slot: u64,
    pub state_root: [u8; 32],
    pub parent_root: [u8; 32],
}
