//! Collect attestations for a target checkpoint across an epoch.

/// Collect all attestations targeting a specific checkpoint.
pub async fn collect_for_checkpoint(
    _api: &crate::beacon_api::BeaconApiClient,
    _target_epoch: u64,
    _target_root: &[u8; 32],
) -> anyhow::Result<()> {
    todo!()
}
