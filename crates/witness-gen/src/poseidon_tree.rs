//! Host-side Poseidon Merkle tree.
//!
//! Maintains the full tree in memory, supports incremental leaf updates,
//! and can extract Merkle proofs (sibling paths) for any leaf.

use zkasper_common::poseidon::{poseidon_leaf, poseidon_pair};
use zkasper_common::types::ValidatorData;

/// Full Poseidon Merkle tree stored level-by-level.
pub struct PoseidonTree {
    /// Tree depth (40 for VALIDATOR_REGISTRY_LIMIT = 2^40).
    pub(crate) depth: u32,
    /// Nodes stored level-by-level. Level 0 = leaves, level `depth` = root.
    /// Each level has `2^(depth - level)` nodes.
    pub(crate) levels: Vec<Vec<[u8; 32]>>,
}

impl PoseidonTree {
    /// Build the tree from a list of validators at a given epoch.
    pub fn build(validators: &[ValidatorData], epoch: u64, depth: u32) -> Self {
        let capacity = 1usize << depth;

        // Compute leaves
        let mut leaves = vec![[0u8; 32]; capacity];
        for (i, v) in validators.iter().enumerate() {
            let active_balance = v.active_effective_balance(epoch);
            leaves[i] = poseidon_leaf(&v.pubkey.0, active_balance);
        }

        // Build levels bottom-up
        let mut levels = Vec::with_capacity((depth + 1) as usize);
        levels.push(leaves);

        for d in 0..depth as usize {
            let prev = &levels[d];
            let parent_count = prev.len() / 2;
            let mut parents = Vec::with_capacity(parent_count);
            for i in 0..parent_count {
                parents.push(poseidon_pair(&prev[i * 2], &prev[i * 2 + 1]));
            }
            levels.push(parents);
        }

        Self { depth, levels }
    }

    /// Reconstruct from raw level data (for loading from DB).
    pub fn from_raw(levels: Vec<Vec<[u8; 32]>>, depth: u32) -> Self {
        Self { depth, levels }
    }

    /// Current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.levels[self.depth as usize][0]
    }

    /// Get Merkle proof siblings for a leaf at `index`.
    pub fn get_siblings(&self, index: u64) -> Vec<[u8; 32]> {
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut idx = index as usize;
        for d in 0..self.depth as usize {
            let sibling_idx = idx ^ 1;
            siblings.push(self.levels[d][sibling_idx]);
            idx >>= 1;
        }
        siblings
    }

    /// Update a leaf and recompute the path to root.
    /// Returns the siblings BEFORE the update (for the witness).
    pub fn update_leaf(&mut self, index: u64, new_leaf: [u8; 32]) -> Vec<[u8; 32]> {
        let siblings = self.get_siblings(index);

        // Update leaf
        self.levels[0][index as usize] = new_leaf;

        // Recompute path
        let mut idx = index as usize;
        for d in 0..self.depth as usize {
            let parent_idx = idx / 2;
            let left = self.levels[d][parent_idx * 2];
            let right = self.levels[d][parent_idx * 2 + 1];
            self.levels[d + 1][parent_idx] = poseidon_pair(&left, &right);
            idx = parent_idx;
        }

        siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkasper_common::types::BlsPubkey;

    fn dummy_validator(i: u8) -> ValidatorData {
        ValidatorData {
            pubkey: BlsPubkey([i; 48]),
            effective_balance: 32_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }
    }

    #[test]
    fn test_build_small_tree() {
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let tree = PoseidonTree::build(&validators, 100, 2); // depth 2 for 4 leaves
        let root = tree.root();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_update_leaf() {
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let mut tree = PoseidonTree::build(&validators, 100, 2);
        let old_root = tree.root();

        let new_leaf = poseidon_leaf(&[99u8; 48], 16_000_000_000);
        let _siblings = tree.update_leaf(1, new_leaf);
        let new_root = tree.root();

        assert_ne!(old_root, new_root);
    }

    #[test]
    fn test_siblings_verify() {
        use zkasper_common::poseidon::verify_poseidon_merkle_proof;

        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let tree = PoseidonTree::build(&validators, 100, 2);

        for i in 0..4u64 {
            let leaf = tree.levels[0][i as usize];
            let siblings = tree.get_siblings(i);
            assert!(verify_poseidon_merkle_proof(
                &leaf,
                i,
                &siblings,
                &tree.root()
            ));
        }
    }
}
