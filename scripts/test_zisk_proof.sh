#!/bin/bash
set -euo pipefail

# Test ZK proof generation and verification using Zisk.
#
# Usage: ./scripts/test_zisk_proof.sh [proof-type]
#   proof-type: bootstrap | epoch-diff | slot-proof | justification | finalization
#
# Requires: cargo-zisk, ziskemu installed via ziskup

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PROOF_TYPE=${1:-bootstrap}
GUEST_CRATE="crates/${PROOF_TYPE}-guest"
GUEST_BIN="zkasper-${PROOF_TYPE}-guest"
ELF="target/riscv64ima-zisk-zkvm-elf/release/${GUEST_BIN}"
INPUT="${GUEST_CRATE}/input.bin"

echo "=== Zisk proof test: ${PROOF_TYPE} ==="
echo ""

echo "--- Step 1: Generate test witness ---"
cargo run --release --bin gen-test-witness -- "$PROOF_TYPE" "$INPUT"
echo ""

echo "--- Step 2: Build guest for Zisk (RISC-V) ---"
# cargo-zisk build doesn't support -p, must cd into the guest crate
(cd "$GUEST_CRATE" && cargo-zisk build --release)
echo ""

echo "--- Step 3: Run in Zisk emulator ---"
ziskemu -e "$ELF" -i "$INPUT"
echo ""

echo "--- Step 4: ROM setup ---"
cargo-zisk rom-setup -e "$ELF"
echo ""

echo "--- Step 5: Generate proof ---"
cargo-zisk prove -e "$ELF" -i "$INPUT" -o "${GUEST_CRATE}/proof" -a -y
echo ""

echo "--- Step 6: Verify proof ---"
cargo-zisk verify -p "${GUEST_CRATE}/proof/vadcop_final_proof.bin"
echo ""

echo "=== PASSED: ${PROOF_TYPE} proof generated and verified ==="
