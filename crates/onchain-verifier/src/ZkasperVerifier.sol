// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IZiskVerifier {
    function verify(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external view returns (bool);
}

/// @title ZkasperVerifier
/// @notice Tracks Ethereum beacon chain finality via ZK proofs of Casper FFG.
///
/// Public output layouts (uint32 arrays, little-endian packed):
///
///   Bootstrap:  [poseidon_root(8), total_active_balance(2), state_root(8)]
///   EpochDiff:  [poseidon_root_2(8), total_active_balance_2(2), state_root_1(8), state_root_2(8)]
///   Finality:   [epoch(2), checkpoint_root(8), poseidon_root(8), total_active_balance(2)]
contract ZkasperVerifier {
    IZiskVerifier public immutable epochDiffVerifier;
    IZiskVerifier public immutable finalityVerifier;
    IZiskVerifier public immutable bootstrapVerifier;

    bytes32 public latestStateRoot;
    bytes32 public poseidonRoot;
    uint64 public totalActiveBalance;
    bytes32 public latestFinalizedCheckpointRoot;
    uint64 public latestFinalizedEpoch;
    bool public initialized;

    event Bootstrapped(bytes32 stateRoot, bytes32 poseidonRoot, uint64 totalActiveBalance);
    event EpochDiffVerified(bytes32 stateRoot2, bytes32 poseidonRoot2, uint64 totalActiveBalance2);
    event FinalityVerified(uint64 epoch, bytes32 root);

    constructor(
        address _epochDiffVerifier,
        address _finalityVerifier,
        address _bootstrapVerifier
    ) {
        epochDiffVerifier = IZiskVerifier(_epochDiffVerifier);
        finalityVerifier = IZiskVerifier(_finalityVerifier);
        bootstrapVerifier = IZiskVerifier(_bootstrapVerifier);
    }

    /// @notice One-time initialization from a trusted state root.
    /// Public outputs: [poseidon_root(8), total_active_balance(2), state_root(8)]
    function bootstrap(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(!initialized, "already initialized");
        require(publicOutputs.length >= 18, "invalid outputs length");
        require(bootstrapVerifier.verify(proof, publicOutputs), "invalid proof");

        poseidonRoot = _extractBytes32(publicOutputs, 0);
        totalActiveBalance = _extractUint64(publicOutputs, 8);
        latestStateRoot = _extractBytes32(publicOutputs, 10);
        initialized = true;

        emit Bootstrapped(latestStateRoot, poseidonRoot, totalActiveBalance);
    }

    /// @notice Submit an epoch diff proof to advance the accumulator.
    /// Public outputs: [poseidon_root_2(8), total_active_balance_2(2), state_root_1(8), state_root_2(8)]
    ///
    /// The circuit proves the transition from state_root_1 to state_root_2.
    /// The contract verifies state_root_1 matches the stored latestStateRoot,
    /// and derives state_root_2 from the verified proof outputs (not calldata).
    function submitEpochDiff(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 26, "invalid outputs length");
        require(epochDiffVerifier.verify(proof, publicOutputs), "invalid proof");

        // Verify the proof's state_root_1 matches our stored state
        bytes32 provenStateRoot1 = _extractBytes32(publicOutputs, 10);
        require(provenStateRoot1 == latestStateRoot, "state root 1 mismatch");

        // Extract all outputs from the verified proof
        poseidonRoot = _extractBytes32(publicOutputs, 0);
        totalActiveBalance = _extractUint64(publicOutputs, 8);
        latestStateRoot = _extractBytes32(publicOutputs, 18);

        emit EpochDiffVerified(latestStateRoot, poseidonRoot, totalActiveBalance);
    }

    /// @notice Submit a finality proof.
    /// Public outputs: [epoch(2), checkpoint_root(8), poseidon_root(8), total_active_balance(2)]
    ///
    /// The contract verifies the proof was generated against the current
    /// poseidon_root and total_active_balance, binding finality to the tracked
    /// validator set.
    function submitFinality(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 20, "invalid outputs length");
        require(finalityVerifier.verify(proof, publicOutputs), "invalid proof");

        // Verify the proof was generated against our current accumulator state
        bytes32 provenPoseidonRoot = _extractBytes32(publicOutputs, 10);
        uint64 provenTotalBalance = _extractUint64(publicOutputs, 18);
        require(provenPoseidonRoot == poseidonRoot, "poseidon root mismatch");
        require(provenTotalBalance == totalActiveBalance, "total active balance mismatch");

        // Extract finalized checkpoint from proof
        uint64 epoch = _extractUint64(publicOutputs, 0);
        bytes32 root = _extractBytes32(publicOutputs, 2);

        require(epoch > latestFinalizedEpoch, "not newer");

        latestFinalizedEpoch = epoch;
        latestFinalizedCheckpointRoot = root;

        emit FinalityVerified(epoch, root);
    }

    function _extractBytes32(uint32[] calldata data, uint256 offset) internal pure returns (bytes32) {
        bytes32 result;
        for (uint256 i = 0; i < 8; i++) {
            result |= bytes32(uint256(data[offset + i])) << (i * 32);
        }
        return result;
    }

    function _extractUint64(uint32[] calldata data, uint256 offset) internal pure returns (uint64) {
        return uint64(data[offset]) | (uint64(data[offset + 1]) << 32);
    }
}
