//! Assemble a BootstrapWitness for one-time Poseidon tree construction.

pub async fn build(
    _api: &crate::beacon_api::BeaconApiClient,
    _slot: u64,
) -> anyhow::Result<(
    zkasper_common::types::BootstrapWitness,
    crate::poseidon_tree::PoseidonTree,
)> {
    todo!()
}
