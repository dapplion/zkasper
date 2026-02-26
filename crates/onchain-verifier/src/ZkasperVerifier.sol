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
    function bootstrap(
        bytes calldata proof,
        uint32[] calldata publicOutputs,
        bytes32 stateRoot
    ) external {
        require(!initialized, "already initialized");
        require(bootstrapVerifier.verify(proof, publicOutputs), "invalid proof");

        poseidonRoot = _extractBytes32(publicOutputs, 0);
        totalActiveBalance = _extractUint64(publicOutputs, 8);
        latestStateRoot = stateRoot;
        initialized = true;

        emit Bootstrapped(stateRoot, poseidonRoot, totalActiveBalance);
    }

    /// @notice Submit an epoch diff proof to advance the accumulator.
    function submitEpochDiff(
        bytes calldata proof,
        uint32[] calldata publicOutputs,
        bytes32 stateRoot1,
        bytes32 stateRoot2
    ) external {
        require(initialized, "not initialized");
        require(stateRoot1 == latestStateRoot, "state root mismatch");

        require(epochDiffVerifier.verify(proof, publicOutputs), "invalid proof");

        poseidonRoot = _extractBytes32(publicOutputs, 0);
        totalActiveBalance = _extractUint64(publicOutputs, 8);
        latestStateRoot = stateRoot2;

        emit EpochDiffVerified(stateRoot2, poseidonRoot, totalActiveBalance);
    }

    /// @notice Submit a finality proof.
    function submitFinality(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(finalityVerifier.verify(proof, publicOutputs), "invalid proof");

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
