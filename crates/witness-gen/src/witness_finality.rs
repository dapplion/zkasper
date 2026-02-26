//! Assemble a FinalityWitness for Proof 2.

pub async fn build(
    _api: &crate::beacon_api::BeaconApiClient,
    _poseidon_tree: &crate::poseidon_tree::PoseidonTree,
    _target_epoch: u64,
) -> anyhow::Result<zkasper_common::types::FinalityWitness> {
    todo!()
}
