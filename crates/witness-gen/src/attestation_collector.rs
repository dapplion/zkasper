//! Collect attestations for a target checkpoint and build AttestationWitness values.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result};

use zkasper_common::constants::SLOTS_PER_EPOCH;
use zkasper_common::ssz::{sha256_pair, u64_to_chunk};
use zkasper_common::types::{AttestationWitness, AttestingValidator, BlsPubkey, BlsSignature};

use crate::beacon_api::{AttestationResponse, BeaconApi, CommitteeResponse, ValidatorResponse};
use crate::poseidon_tree::PoseidonTree;
use crate::state_diff::validator_response_to_data;

/// Collect all attestations targeting a specific checkpoint and assemble
/// AttestationWitness values with Poseidon proofs.
///
/// Scans blocks in `[target_epoch * SLOTS_PER_EPOCH .. (target_epoch + 2) * SLOTS_PER_EPOCH)`
/// for attestations whose target matches `(target_epoch, target_root)`.
pub async fn collect_for_checkpoint(
    api: &impl BeaconApi,
    target_epoch: u64,
    target_root: &[u8; 32],
    validators: &[ValidatorResponse],
    poseidon_tree: &PoseidonTree,
    epoch: u64,
) -> Result<Vec<AttestationWitness>> {
    // Fetch committees for the target epoch
    let slot_str = (target_epoch * SLOTS_PER_EPOCH).to_string();
    let committees = api
        .get_committees(&slot_str, target_epoch)
        .await
        .context("fetch committees")?;

    // Build committee map: (slot, committee_index) -> validator_indices
    let committee_map = build_committee_map(&committees);

    // Scan blocks for matching attestations
    let scan_start = target_epoch * SLOTS_PER_EPOCH;
    let scan_end = (target_epoch + 2) * SLOTS_PER_EPOCH;
    let mut matching_attestations: Vec<AttestationResponse> = Vec::new();

    for slot in scan_start..scan_end {
        let block_id = slot.to_string();
        match api.get_block_attestations(&block_id).await {
            Ok(attestations) => {
                for att in attestations {
                    if att.data_target_epoch == target_epoch
                        && att.data_target_root == *target_root
                    {
                        matching_attestations.push(att);
                    }
                }
            }
            Err(_) => {
                // Block may not exist (missed slot), skip
                continue;
            }
        }
    }

    // Group attestations by data root, dedup validators
    let mut groups: HashMap<[u8; 32], GroupedAttestation> = HashMap::new();

    for att in &matching_attestations {
        let data_root = compute_attestation_data_root(att);
        let attesting_indices =
            resolve_attesting_validators(att, &committee_map).context("resolve attestors")?;

        let entry = groups.entry(data_root).or_insert_with(|| GroupedAttestation {
            data_root,
            signature: att.signature,
            validator_indices: BTreeSet::new(),
        });

        for idx in attesting_indices {
            entry.validator_indices.insert(idx);
        }
    }

    // Build AttestationWitness values
    let mut result = Vec::with_capacity(groups.len());

    for (_, group) in groups {
        let mut attesting_validators = Vec::with_capacity(group.validator_indices.len());

        // BTreeSet iterates in ascending order → strictly increasing indices
        for &idx in &group.validator_indices {
            let v_resp = validators
                .get(idx as usize)
                .context("validator index out of range")?;
            let v_data = validator_response_to_data(v_resp);
            let active_balance = v_data.active_effective_balance(epoch);
            let siblings = poseidon_tree.get_siblings(idx);

            attesting_validators.push(AttestingValidator {
                validator_index: idx,
                pubkey: BlsPubkey(v_resp.pubkey),
                active_effective_balance: active_balance,
                poseidon_siblings: siblings,
            });
        }

        result.push(AttestationWitness {
            attestation_data_root: group.data_root,
            signature: BlsSignature(group.signature),
            attesting_validators,
        });
    }

    Ok(result)
}

struct GroupedAttestation {
    data_root: [u8; 32],
    signature: [u8; 96],
    validator_indices: BTreeSet<u64>,
}

/// Build a committee lookup map from committee responses.
///
/// Key: (slot, committee_index) → Value: list of validator indices
fn build_committee_map(
    committees: &[CommitteeResponse],
) -> HashMap<(u64, u64), Vec<u64>> {
    let mut map = HashMap::new();
    for c in committees {
        map.insert((c.slot, c.index), c.validators.clone());
    }
    map
}

/// Resolve which global validator indices are attesting in an attestation.
///
/// For Electra-style attestations (committee_bits present), iterates over set
/// bits in committee_bits to find which committees are included, then uses
/// aggregation_bits to pick validators within each committee.
///
/// For pre-Electra attestations, uses data_index as the committee index directly.
fn resolve_attesting_validators(
    att: &AttestationResponse,
    committee_map: &HashMap<(u64, u64), Vec<u64>>,
) -> Result<Vec<u64>> {
    let mut result = Vec::new();

    if att.committee_bits.is_empty() {
        // Pre-Electra: single committee identified by data_index
        let committee = committee_map
            .get(&(att.data_slot, att.data_index))
            .context("committee not found")?;

        for (bit_idx, &validator_idx) in committee.iter().enumerate() {
            if get_bit(&att.aggregation_bits, bit_idx) {
                result.push(validator_idx);
            }
        }
    } else {
        // Electra: committee_bits indicates which committees are included
        let mut aggregation_offset = 0;

        for committee_idx in 0..att.committee_bits.len() * 8 {
            if !get_bit(&att.committee_bits, committee_idx) {
                continue;
            }

            let committee = match committee_map.get(&(att.data_slot, committee_idx as u64)) {
                Some(c) => c,
                None => continue,
            };

            for (j, &validator_idx) in committee.iter().enumerate() {
                if get_bit(&att.aggregation_bits, aggregation_offset + j) {
                    result.push(validator_idx);
                }
            }

            aggregation_offset += committee.len();
        }
    }

    Ok(result)
}

/// Get bit at position `idx` from a little-endian bitfield.
fn get_bit(bitfield: &[u8], idx: usize) -> bool {
    let byte_idx = idx / 8;
    let bit_idx = idx % 8;
    if byte_idx >= bitfield.len() {
        return false;
    }
    (bitfield[byte_idx] >> bit_idx) & 1 == 1
}

/// Compute `hash_tree_root(AttestationData)` — manual SSZ merkleization of 5 fields.
///
/// AttestationData layout:
/// ```text
/// field[0] = le_pad32(slot)
/// field[1] = le_pad32(index)
/// field[2] = beacon_block_root
/// field[3] = source: sha256(le_pad32(epoch) || root)
/// field[4] = target: sha256(le_pad32(epoch) || root)
/// ```
///
/// Merkle tree: 8 leaves (padded to next power of 2 with zeros).
fn compute_attestation_data_root(att: &AttestationResponse) -> [u8; 32] {
    let zero = [0u8; 32];

    let field0 = u64_to_chunk(att.data_slot);
    let field1 = u64_to_chunk(att.data_index);
    let field2 = att.data_beacon_block_root;
    let field3 = sha256_pair(&u64_to_chunk(att.data_source_epoch), &att.data_source_root);
    let field4 = sha256_pair(&u64_to_chunk(att.data_target_epoch), &att.data_target_root);

    // Depth-3 tree with 8 leaves (5 data + 3 zero)
    let n0 = sha256_pair(&field0, &field1);
    let n1 = sha256_pair(&field2, &field3);
    let n2 = sha256_pair(&field4, &zero);
    let n3 = sha256_pair(&zero, &zero);

    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);

    sha256_pair(&n4, &n5)
}
