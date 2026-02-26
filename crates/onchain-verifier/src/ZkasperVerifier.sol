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
///   Bootstrap:  [accumulator_commitment(8), state_root(8)]
///   EpochDiff:  [accumulator_commitment(8), state_root_1(8), state_root_2(8)]
///   Finality:   [accumulator_commitment(8), finalized_block_root(8)]
///
/// The accumulator_commitment is poseidon(poseidon_root, total_active_balance),
/// binding the Poseidon validator tree to the total active balance in one value.
contract ZkasperVerifier {
    IZiskVerifier public immutable epochDiffVerifier;
    IZiskVerifier public immutable finalityVerifier;
    IZiskVerifier public immutable bootstrapVerifier;

    bytes32 public accumulatorCommitment;
    bytes32 public latestStateRoot;
    bytes32 public latestFinalizedBlockRoot;
    bool public initialized;

    event Bootstrapped(bytes32 stateRoot, bytes32 accumulatorCommitment);
    event EpochDiffVerified(bytes32 stateRoot2, bytes32 accumulatorCommitment);
    event FinalityVerified(bytes32 blockRoot);

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
    /// Public outputs: [accumulator_commitment(8), state_root(8)]
    function bootstrap(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(!initialized, "already initialized");
        require(publicOutputs.length >= 16, "invalid outputs length");
        require(bootstrapVerifier.verify(proof, publicOutputs), "invalid proof");

        accumulatorCommitment = _extractBytes32(publicOutputs, 0);
        latestStateRoot = _extractBytes32(publicOutputs, 8);
        initialized = true;

        emit Bootstrapped(latestStateRoot, accumulatorCommitment);
    }

    /// @notice Submit an epoch diff proof to advance the accumulator.
    /// Public outputs: [accumulator_commitment(8), state_root_1(8), state_root_2(8)]
    function submitEpochDiff(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 24, "invalid outputs length");
        require(epochDiffVerifier.verify(proof, publicOutputs), "invalid proof");

        bytes32 provenStateRoot1 = _extractBytes32(publicOutputs, 8);
        require(provenStateRoot1 == latestStateRoot, "state root 1 mismatch");

        accumulatorCommitment = _extractBytes32(publicOutputs, 0);
        latestStateRoot = _extractBytes32(publicOutputs, 16);

        emit EpochDiffVerified(latestStateRoot, accumulatorCommitment);
    }

    /// @notice Submit a finality proof.
    /// Public outputs: [accumulator_commitment(8), finalized_block_root(8)]
    function submitFinality(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 16, "invalid outputs length");
        require(finalityVerifier.verify(proof, publicOutputs), "invalid proof");

        bytes32 provenCommitment = _extractBytes32(publicOutputs, 0);
        require(provenCommitment == accumulatorCommitment, "accumulator mismatch");

        latestFinalizedBlockRoot = _extractBytes32(publicOutputs, 8);

        emit FinalityVerified(latestFinalizedBlockRoot);
    }

    function _extractBytes32(uint32[] calldata data, uint256 offset) internal pure returns (bytes32) {
        bytes32 result;
        for (uint256 i = 0; i < 8; i++) {
            result |= bytes32(uint256(data[offset + i])) << (i * 32);
        }
        return result;
    }
}
