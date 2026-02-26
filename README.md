# zkasper

ZK proof of Ethereum beacon chain finality for trustless bridges, targeting the [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM.

## Overview

zkasper proves that an Ethereum Casper FFG checkpoint has been finalized, without requiring the verifier to process the full beacon chain. It works in two stages:

1. **Epoch Diff** (Proof 1) — Tracks how the validator set changes between consecutive epochs using a Poseidon Merkle accumulator that mirrors the SSZ validator registry. Each proof verifies ~200 mutations (churn + balance updates) and outputs the updated accumulator root and total active balance.

2. **Finality** (Proof 2) — Proves that >= 2/3 of active stake attested to a target checkpoint with valid BLS aggregate signatures. Reads from the Poseidon accumulator to verify attesting validator membership and weight.

A one-time **Bootstrap** proof initializes the Poseidon tree from a trusted beacon state.

## Architecture

```
crates/
  common/              # shared types, SSZ, Poseidon, Merkle, BLS
  epoch-diff-guest/    # Zisk guest: epoch diff circuit (Proof 1)
  finality-guest/      # Zisk guest: finality circuit (Proof 2)
  bootstrap-guest/     # Zisk guest: one-time tree construction
  witness-gen/         # host-side witness generator (beacon API, tree management)
  onchain-verifier/    # Solidity verifier contract
```

### Why a Poseidon accumulator?

The beacon chain stores validators in an SSZ Merkle tree (SHA-256). Proving membership in-circuit is cheap per validator (~40 SHA-256 hashes), but the finality proof needs to verify ~700K attesting validators. Rebuilding or traversing the full SSZ tree in-circuit is prohibitive.

Instead, we maintain a parallel Poseidon Merkle tree (over BN254 Fr) that maps each validator to `Poseidon(pubkey_lo, pubkey_hi, active_effective_balance)`. Poseidon is SNARK-friendly and on Zisk routes through `arith256_mod` syscalls. The epoch-diff proof keeps this tree in sync with the SSZ state, and the finality proof reads from it.

## Building

```sh
cargo build
cargo test
```

Guest programs currently compile as normal binaries for native testing. To target Zisk, uncomment the `ziskos` dependency and `#![no_main]` / `entrypoint!` annotations in each guest crate.

## Status

- [x] Core library (SSZ, Poseidon, Merkle, types)
- [x] Epoch diff circuit with end-to-end tests
- [x] Bootstrap circuit with tests
- [x] Finality circuit (Poseidon verification done, BLS signature verification WIP)
- [x] Host-side Poseidon tree with incremental updates
- [ ] Witness generator (beacon API integration, state diffing, attestation collection)
- [ ] BLS12-381 aggregate signature verification (pending Zisk pairing support)
- [ ] Solidity verifier integration with Zisk proof format
- [ ] Recursive proof composition for bootstrap chunking

## Design

See [PLAN.md](PLAN.md) for the full implementation plan, cost analysis, and open questions.

## License

MIT
