// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ZkasperVerifier.sol";

contract MockVerifier is IZiskVerifier {
    function verify(bytes calldata, uint32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract RejectingVerifier is IZiskVerifier {
    function verify(bytes calldata, uint32[] calldata) external pure returns (bool) {
        return false;
    }
}

contract ZkasperVerifierTest is Test {
    ZkasperVerifier verifier;
    MockVerifier mockVerifier;

    // Mirror events from ZkasperVerifier for vm.expectEmit
    event Bootstrapped(bytes32 stateRoot, bytes32 accumulatorCommitment);
    event EpochDiffVerified(bytes32 stateRoot2, bytes32 accumulatorCommitment);
    event FinalityVerified(bytes32 blockRoot);

    // Synthetic test values
    bytes32 constant COMMITMENT_1 = bytes32(uint256(0x1111));
    bytes32 constant COMMITMENT_2 = bytes32(uint256(0x2222));
    bytes32 constant STATE_ROOT_1 = bytes32(uint256(0xAAAA));
    bytes32 constant STATE_ROOT_2 = bytes32(uint256(0xBBBB));
    bytes32 constant BLOCK_ROOT = bytes32(uint256(0xCCCC));

    function setUp() public {
        mockVerifier = new MockVerifier();
        verifier = new ZkasperVerifier(
            address(mockVerifier), // epochDiffVerifier
            address(mockVerifier), // finalityVerifier
            address(mockVerifier)  // bootstrapVerifier
        );
    }

    // --- Helpers ---

    /// @dev Pack a bytes32 into 8 LE uint32 words matching _extractBytes32 layout.
    /// _extractBytes32 does: result |= bytes32(uint256(data[offset+i])) << (i*32)
    /// So word[i] = uint32(uint256(value) >> (i*32))
    function _packBytes32(bytes32 value) internal pure returns (uint32[8] memory words) {
        uint256 v = uint256(value);
        for (uint256 i = 0; i < 8; i++) {
            words[i] = uint32(v >> (i * 32));
        }
    }

    function _bootstrapOutputs(
        bytes32 commitment,
        bytes32 stateRoot
    ) internal pure returns (uint32[] memory) {
        uint32[] memory out = new uint32[](16);
        uint32[8] memory c = _packBytes32(commitment);
        uint32[8] memory s = _packBytes32(stateRoot);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = c[i];
            out[8 + i] = s[i];
        }
        return out;
    }

    function _epochDiffOutputs(
        bytes32 commitment,
        bytes32 stateRoot1,
        bytes32 stateRoot2
    ) internal pure returns (uint32[] memory) {
        uint32[] memory out = new uint32[](24);
        uint32[8] memory c = _packBytes32(commitment);
        uint32[8] memory s1 = _packBytes32(stateRoot1);
        uint32[8] memory s2 = _packBytes32(stateRoot2);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = c[i];
            out[8 + i] = s1[i];
            out[16 + i] = s2[i];
        }
        return out;
    }

    function _finalityOutputs(
        bytes32 commitment,
        bytes32 blockRoot
    ) internal pure returns (uint32[] memory) {
        uint32[] memory out = new uint32[](16);
        uint32[8] memory c = _packBytes32(commitment);
        uint32[8] memory b = _packBytes32(blockRoot);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = c[i];
            out[8 + i] = b[i];
        }
        return out;
    }

    // --- Bootstrap tests ---

    function test_bootstrap() public {
        assertEq(verifier.initialized(), false);

        uint32[] memory outputs = _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1);
        verifier.bootstrap("", outputs);

        assertEq(verifier.initialized(), true);
        assertEq(verifier.accumulatorCommitment(), COMMITMENT_1);
        assertEq(verifier.latestStateRoot(), STATE_ROOT_1);
    }

    function test_bootstrap_emits_event() public {
        uint32[] memory outputs = _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1);

        vm.expectEmit(true, true, false, true);
        emit Bootstrapped(STATE_ROOT_1, COMMITMENT_1);

        verifier.bootstrap("", outputs);
    }

    function test_bootstrap_revert_double() public {
        uint32[] memory outputs = _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1);
        verifier.bootstrap("", outputs);

        vm.expectRevert("already initialized");
        verifier.bootstrap("", outputs);
    }

    function test_bootstrap_revert_invalid_proof() public {
        RejectingVerifier rejector = new RejectingVerifier();
        ZkasperVerifier v = new ZkasperVerifier(
            address(mockVerifier),
            address(mockVerifier),
            address(rejector) // bootstrapVerifier rejects
        );

        uint32[] memory outputs = _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1);
        vm.expectRevert("invalid proof");
        v.bootstrap("", outputs);
    }

    function test_bootstrap_revert_short_outputs() public {
        uint32[] memory outputs = new uint32[](15); // too short
        vm.expectRevert("invalid outputs length");
        verifier.bootstrap("", outputs);
    }

    // --- EpochDiff tests ---

    function test_epochDiff() public {
        // Bootstrap first
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        // Submit epoch diff: state_root_1 must match latestStateRoot
        uint32[] memory diffOutputs = _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2);
        verifier.submitEpochDiff("", diffOutputs);

        assertEq(verifier.accumulatorCommitment(), COMMITMENT_2);
        assertEq(verifier.latestStateRoot(), STATE_ROOT_2);
    }

    function test_epochDiff_emits_event() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory diffOutputs = _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2);

        vm.expectEmit(true, true, false, true);
        emit EpochDiffVerified(STATE_ROOT_2, COMMITMENT_2);

        verifier.submitEpochDiff("", diffOutputs);
    }

    function test_epochDiff_revert_not_initialized() public {
        uint32[] memory diffOutputs = _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2);
        vm.expectRevert("not initialized");
        verifier.submitEpochDiff("", diffOutputs);
    }

    function test_epochDiff_revert_state_root_mismatch() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        // state_root_1 in outputs doesn't match latestStateRoot
        uint32[] memory diffOutputs = _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_2, STATE_ROOT_2);
        vm.expectRevert("state root 1 mismatch");
        verifier.submitEpochDiff("", diffOutputs);
    }

    function test_epochDiff_revert_invalid_proof() public {
        RejectingVerifier rejector = new RejectingVerifier();
        ZkasperVerifier v = new ZkasperVerifier(
            address(rejector), // epochDiffVerifier rejects
            address(mockVerifier),
            address(mockVerifier)
        );

        v.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory diffOutputs = _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2);
        vm.expectRevert("invalid proof");
        v.submitEpochDiff("", diffOutputs);
    }

    function test_epochDiff_revert_short_outputs() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory outputs = new uint32[](23); // too short
        vm.expectRevert("invalid outputs length");
        verifier.submitEpochDiff("", outputs);
    }

    // --- Finality tests ---

    function test_finality() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        // Finality: commitment must match accumulatorCommitment
        uint32[] memory finalityOutputs = _finalityOutputs(COMMITMENT_1, BLOCK_ROOT);
        verifier.submitFinality("", finalityOutputs);

        assertEq(verifier.latestFinalizedBlockRoot(), BLOCK_ROOT);
    }

    function test_finality_emits_event() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory finalityOutputs = _finalityOutputs(COMMITMENT_1, BLOCK_ROOT);

        vm.expectEmit(true, true, false, true);
        emit FinalityVerified(BLOCK_ROOT);

        verifier.submitFinality("", finalityOutputs);
    }

    function test_finality_revert_not_initialized() public {
        uint32[] memory finalityOutputs = _finalityOutputs(COMMITMENT_1, BLOCK_ROOT);
        vm.expectRevert("not initialized");
        verifier.submitFinality("", finalityOutputs);
    }

    function test_finality_revert_accumulator_mismatch() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        // Wrong commitment
        uint32[] memory finalityOutputs = _finalityOutputs(COMMITMENT_2, BLOCK_ROOT);
        vm.expectRevert("accumulator mismatch");
        verifier.submitFinality("", finalityOutputs);
    }

    function test_finality_revert_invalid_proof() public {
        RejectingVerifier rejector = new RejectingVerifier();
        ZkasperVerifier v = new ZkasperVerifier(
            address(mockVerifier),
            address(rejector), // finalityVerifier rejects
            address(mockVerifier)
        );

        v.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory finalityOutputs = _finalityOutputs(COMMITMENT_1, BLOCK_ROOT);
        vm.expectRevert("invalid proof");
        v.submitFinality("", finalityOutputs);
    }

    function test_finality_revert_short_outputs() public {
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        uint32[] memory outputs = new uint32[](15); // too short
        vm.expectRevert("invalid outputs length");
        verifier.submitFinality("", outputs);
    }

    // --- Full pipeline test ---

    function test_full_pipeline() public {
        // 1. Bootstrap
        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));
        assertEq(verifier.initialized(), true);
        assertEq(verifier.accumulatorCommitment(), COMMITMENT_1);
        assertEq(verifier.latestStateRoot(), STATE_ROOT_1);

        // 2. Epoch diff: advances state root and commitment
        verifier.submitEpochDiff("", _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2));
        assertEq(verifier.accumulatorCommitment(), COMMITMENT_2);
        assertEq(verifier.latestStateRoot(), STATE_ROOT_2);

        // 3. Finality: proves a block root with the current commitment
        verifier.submitFinality("", _finalityOutputs(COMMITMENT_2, BLOCK_ROOT));
        assertEq(verifier.latestFinalizedBlockRoot(), BLOCK_ROOT);
    }

    function test_multiple_epoch_diffs() public {
        bytes32 commitment3 = bytes32(uint256(0x3333));
        bytes32 stateRoot3 = bytes32(uint256(0xDDDD));

        verifier.bootstrap("", _bootstrapOutputs(COMMITMENT_1, STATE_ROOT_1));

        // First epoch diff
        verifier.submitEpochDiff("", _epochDiffOutputs(COMMITMENT_2, STATE_ROOT_1, STATE_ROOT_2));
        assertEq(verifier.latestStateRoot(), STATE_ROOT_2);

        // Second epoch diff (chains from previous)
        verifier.submitEpochDiff("", _epochDiffOutputs(commitment3, STATE_ROOT_2, stateRoot3));
        assertEq(verifier.accumulatorCommitment(), commitment3);
        assertEq(verifier.latestStateRoot(), stateRoot3);

        // Finality with latest commitment
        verifier.submitFinality("", _finalityOutputs(commitment3, BLOCK_ROOT));
        assertEq(verifier.latestFinalizedBlockRoot(), BLOCK_ROOT);
    }

    // --- extractBytes32 round-trip test ---

    function test_extractBytes32_roundtrip() public {
        // Use a recognizable pattern
        bytes32 value = bytes32(uint256(0xDEADBEEFCAFEBABE0123456789ABCDEF));

        uint32[] memory outputs = _bootstrapOutputs(value, STATE_ROOT_1);
        verifier.bootstrap("", outputs);

        assertEq(verifier.accumulatorCommitment(), value);
    }
}
