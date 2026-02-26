//! Assemble an EpochDiffWitness for Proof 1.

pub async fn build(
    _api: &crate::beacon_api::BeaconApiClient,
    _poseidon_tree: &mut crate::poseidon_tree::PoseidonTree,
    _slot_1: u64,
    _slot_2: u64,
) -> anyhow::Result<zkasper_common::types::EpochDiffWitness> {
    todo!()
}
