# zkasper — implementation plan

ZK proof of Ethereum beacon chain finality for trustless bridges, targeting Zisk zkVM.

## workspace layout

```
zkasper/
├── Cargo.toml                          # workspace root
├── PLAN.md
├── crates/
│   ├── common/                         # shared types, SSZ, Poseidon, Merkle, BLS
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs                # witness structs, validator data, checkpoint
│   │       ├── ssz.rs                  # SHA-256 Merkle ops, validator chunking
│   │       ├── poseidon.rs             # Poseidon hash over BN254 Fr + Merkle ops
│   │       ├── bls.rs                  # BLS12-381 sig verification, hash-to-G2
│   │       └── merkle.rs              # generic Merkle verify/update (hash-agnostic)
│   │
│   ├── witness-gen/                    # host-side: beacon API, diffing, Poseidon tree
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # CLI (bootstrap / epoch-diff / finality / run)
│   │       ├── beacon_api.rs           # standard Beacon REST API client
│   │       ├── state_diff.rs           # diff two validator registries, build SSZ proofs
│   │       ├── poseidon_tree.rs        # full Poseidon tree in memory, incremental updates
│   │       ├── attestation_collector.rs # collect attestations for a target checkpoint
│   │       ├── witness_epoch_diff.rs   # assemble EpochDiffWitness
│   │       ├── witness_finality.rs     # assemble FinalityWitness
│   │       ├── witness_bootstrap.rs    # assemble BootstrapWitness
│   │       └── db.rs                   # sled persistence for Poseidon tree + cursor
│   │
│   ├── epoch-diff-guest/               # Zisk guest binary: Proof 1
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   ├── finality-guest/                 # Zisk guest binary: Proof 2
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   ├── bootstrap-guest/                # Zisk guest binary: one-time tree build
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   │
│   └── onchain-verifier/               # Solidity verifier stub
│       └── src/ZkasperVerifier.sol
```

## dependencies

workspace `Cargo.toml`:
```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.dependencies]
serde = { version = "1", default-features = false, features = ["derive"] }
bincode = "1.3"
sha2 = "0.10"
ark-ff = "0.5"
ark-bn254 = "0.5"
ark-bls12-381 = "0.5"
ark-ec = "0.5"
ark-serialize = "0.5"
light-poseidon = "0.4"
ziskos = { git = "https://github.com/0xPolygonHermez/zisk.git", tag = "v0.15.0" }
```

guest crates need `[patch.crates-io]` for Zisk-patched crypto:
```toml
[patch.crates-io]
sha2 = { git = "https://github.com/0xPolygonHermez/zisk-patch-hashes.git" }
ark-ff = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-bn254 = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-bls12-381 = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-ec = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
ark-serialize = { git = "https://github.com/0xPolygonHermez/zisk-patch-ark-algebra.git" }
```

`witness-gen` additionally depends on: `tokio`, `reqwest`, `clap`, `sled`, `anyhow`, `serde_json`.

## crate: `common`

### `types.rs` — core data structures

```rust
pub struct BlsPubkey(pub [u8; 48]);
pub struct BlsSignature(pub [u8; 96]);

/// only the fields we need from a Validator
pub struct ValidatorData {
    pub pubkey: BlsPubkey,
    pub effective_balance: u64,   // Gwei
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

/// one changed validator between two epochs
pub struct ValidatorMutation {
    pub validator_index: u64,
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    // 8 field-level SSZ hash tree leaves for the Validator container
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    // raw pubkey split into 2x32-byte chunks (to verify field_leaves[0])
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    // SHA-256 siblings in validators data tree (depth 40)
    pub old_ssz_siblings: Vec<[u8; 32]>,
    pub new_ssz_siblings: Vec<[u8; 32]>,
    // Poseidon siblings (depth 40)
    pub poseidon_siblings: Vec<[u8; 32]>,
}

pub struct EpochDiffWitness {
    pub state_root_1: [u8; 32],
    pub state_root_2: [u8; 32],
    pub poseidon_root_1: [u8; 32],
    pub total_active_balance_1: u64,
    pub epoch_2: u64,
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,
    pub mutations: Vec<ValidatorMutation>,
}

pub struct AttestingValidator {
    pub validator_index: u64,
    pub pubkey: BlsPubkey,
    pub active_effective_balance: u64,
    pub poseidon_siblings: Vec<[u8; 32]>,
}

pub struct AttestationWitness {
    pub attestation_data_root: [u8; 32],
    pub signature: BlsSignature,
    pub attesting_validators: Vec<AttestingValidator>,
}

pub struct FinalityWitness {
    pub poseidon_root: [u8; 32],
    pub total_active_balance: u64,
    pub finalized_checkpoint: Checkpoint,
    pub signing_domain: [u8; 32],
    pub attestations: Vec<AttestationWitness>,
}

pub struct BootstrapWitness {
    pub state_root: [u8; 32],
    pub epoch: u64,
    pub validators: Vec<ValidatorData>,
    pub state_to_validators_siblings: Vec<[u8; 32]>,
    pub validators_list_length: u64,
    pub validator_field_chunks: Vec<[[u8; 32]; 8]>,
    pub validator_pubkey_chunks: Vec<[[u8; 32]; 2]>,
}
```

### `ssz.rs` — SHA-256 Merkle operations

- `sha256_pair(left, right) -> [u8; 32]` — uses `sha2` crate (routes through `syscall_sha256_f` on Zisk)
- `validator_hash_tree_root(field_leaves: &[[u8; 32]; 8]) -> [u8; 32]` — merkleize 8 leaves (depth 3, 7 hashes)
- `list_hash_tree_root(data_root, length) -> [u8; 32]` — `sha256(data_root || le_bytes_pad32(length))`
- `verify_ssz_field_leaves(data: &ValidatorData, field_leaves: &[[u8; 32]; 8], pubkey_chunks: &[[u8; 32]; 2])` — check that the field leaves encode the claimed values

SSZ Validator container field layout (8 fields, each hashed to one leaf):
```
leaf[0] = sha256(pubkey[0..32] || pubkey[32..48]++zeros)
leaf[1] = withdrawal_credentials (32 bytes, opaque)
leaf[2] = le_pad32(effective_balance)
leaf[3] = le_pad32(slashed)
leaf[4] = le_pad32(activation_eligibility_epoch)
leaf[5] = le_pad32(activation_epoch)
leaf[6] = le_pad32(exit_epoch)
leaf[7] = le_pad32(withdrawable_epoch)
```

We verify leaves 0, 2, 5, 6 match the claimed `ValidatorData`. Leaves 1, 3, 4, 7 are opaque (provided by witness, hashed but not interpreted).

### `poseidon.rs` — Poseidon over BN254 Fr

- `poseidon_leaf(pubkey: &[u8; 48], active_eff_balance: u64) -> [u8; 32]`
  - `Poseidon(Fr(pubkey[0..32]), Fr(pubkey[32..48]++zeros), Fr(balance))`
  - uses `light-poseidon` with `new_circom(3)` (t=4, 3 inputs)
- `poseidon_pair(left, right) -> [u8; 32]` — for internal Merkle nodes, `new_circom(2)` (t=3)
- `compute_poseidon_merkle_root(leaf, index, siblings) -> [u8; 32]`
- `verify_poseidon_merkle_proof(leaf, index, siblings, root) -> bool`

On Zisk: `ark-ff` field ops route through `syscall_arith256_mod`, making each Poseidon hash ~300-500 modular arithmetic syscalls. No dedicated Poseidon precompile exists yet — this is the main perf bottleneck to discuss with Jordi.

### `bls.rs` — BLS12-381 signature verification

- `aggregate_pubkeys(pubkeys: &[[u8; 48]]) -> G1Projective` — G1 point additions
- `hash_to_g2(message: &[u8]) -> G2Projective` — IETF hash-to-curve (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`)
- `verify_aggregate_signature(agg_pk, signing_root, signature) -> bool` — pairing check

On Zisk: curve ops via `syscall_bls12_381_{curve_add,curve_dbl,complex_*}`. Pairing built from Miller loop + final exponentiation using these primitives via patched `ark-bls12-381`.

### `merkle.rs` — generic Merkle helpers

Hash-function-agnostic `compute_root` and `verify_proof` parameterized by a closure `Fn(&[u8;32], &[u8;32]) -> [u8;32]`. Used by both SSZ and Poseidon code.

## crate: `epoch-diff-guest` (Proof 1)

Guest program logic (`#![no_main]`, `ziskos::entrypoint!(main)`):

1. Deserialize `EpochDiffWitness` from `read_input_slice()` via bincode
2. For each mutation:
   a. Verify `old_field_leaves` encode `old_data` (check pubkey_chunks hash to leaf[0], check scalar fields in leaves 2/5/6)
   b. Same for `new_field_leaves` / `new_data`
   c. Compute `old_validator_root = merkleize(old_field_leaves)`, verify Merkle path to SSZ data tree root via `old_ssz_siblings`
   d. Same for new -> get SSZ data tree root 2
   e. Verify old Poseidon leaf against `poseidon_root` (accumulative — each mutation updates the running root)
   f. Compute new Poseidon leaf, derive new `poseidon_root`
   g. Accumulate balance delta
3. All mutations must agree on the same SSZ data tree roots (verified implicitly since they each compute a full Merkle root)
4. Verify SSZ data tree roots link to `state_root_1` / `state_root_2` via `state_to_validators_siblings` + list length mix-in
5. Output: `poseidon_root_2` (8 x u32) + `total_active_balance_2` (2 x u32)

**Cost**: ~200 mutations x (7 SHA256 per validator root + 40 SHA256 Merkle path) x 2 trees + 200 x 40 Poseidon = ~19K SHA256 + ~8K Poseidon. Cheap.

**V2 optimization**: diff walk — instead of independent Merkle proofs per mutation, walk both trees top-down opening only diverging branches. Reduces to ~4K SHA256. Deferred.

**Note on sequential Poseidon updates**: Mutations must be processed in order. The Poseidon siblings for mutation N are valid only BEFORE mutations 0..N-1 are applied. The witness generator extracts siblings then applies the update.

## crate: `finality-guest` (Proof 2)

Guest program logic:

1. Deserialize `FinalityWitness`
2. For each attestation:
   a. For each `AttestingValidator`: compute `poseidon_leaf(pubkey, active_eff_balance)`, verify against `poseidon_root` via siblings. Accumulate balance. Collect pubkey.
   b. Aggregate pubkeys via G1 addition
   c. Compute `signing_root = sha256(attestation_data_root || signing_domain)`
   d. `hash_to_g2(signing_root)` -> message point
   e. BLS pairing check: `e(agg_pk, H(m)) == e(G1, sig)`
3. Assert `attesting_balance * 3 >= total_active_balance * 2`
4. Output: `finalized_checkpoint` (epoch + root)

**Cost**: ~700K validators x 40 Poseidon siblings = ~28M Poseidon hashes (dominant cost). ~32 BLS pairing checks. With batch Poseidon tree traversal (V2), reduces to ~1M Poseidon.

**Double-counting safety**: protocol guarantees — a validator voting twice for the same target epoch commits a slashable double vote. No in-circuit dedup needed.

## crate: `bootstrap-guest`

Guest program logic:

1. Deserialize `BootstrapWitness`
2. For each validator: verify field_chunks encode the claimed data, compute `validator_hash_tree_root`
3. Rebuild SSZ data tree bottom-up from all validator roots (~1M SHA256)
4. Verify data tree root -> state_root via list mix-in + state siblings
5. Compute all Poseidon leaves, build Poseidon tree bottom-up (~2M Poseidon)
6. Output: `poseidon_root` + `total_active_balance`

**Cost**: ~8M SHA256 + ~2M Poseidon. Must be chunked via recursive proof composition. Each chunk proves a subtree (e.g. 2^16 validators), final proof aggregates subtree roots.

## crate: `witness-gen`

Host-side Rust binary. Not compiled for Zisk.

### `beacon_api.rs`
Standard Beacon REST API client (`/eth/v2/debug/beacon/states/{id}`, `/eth/v1/beacon/states/{id}/validators`, `/eth/v1/beacon/blocks/{id}/attestations`, `/eth/v1/beacon/states/{id}/committees`).

### `poseidon_tree.rs`
Full Poseidon Merkle tree in memory (2^40 capacity, ~1M populated leaves). Supports:
- `build(validators, epoch)` — initial construction (~4M Poseidon hashes on host)
- `update_leaf(index, new_leaf) -> old_siblings` — returns siblings BEFORE update, then mutates
- `get_siblings(index) -> siblings` — for finality proof reads
- `root() -> [u8; 32]`
- `save/load` via sled for persistence across runs

### `state_diff.rs`
- Fetch two beacon states, extract validator registries
- Compare field-by-field to find mutations (~200 per epoch from churn + balance updates)
- Build full SSZ data trees on host (depth 40, ~1M validators), extract Merkle siblings per mutation
- Extract state_root -> validators proof (BeaconState top-level tree, field index 11)

### `attestation_collector.rs`
- Scan blocks in the finalized epoch for attestations targeting the finalized checkpoint
- Resolve committee assignments (committee_bits + aggregation_bits -> global validator indices)
- For each attesting validator, extract Poseidon proof from host tree
- Group by `AttestationData` (same signing root -> aggregate)

### CLI (`main.rs`)
```
zkasper-witness-gen bootstrap --beacon-url <URL> --slot <SLOT>
zkasper-witness-gen epoch-diff --beacon-url <URL> --slot1 <S1> --slot2 <S2>
zkasper-witness-gen finality --beacon-url <URL> --epoch <E>
zkasper-witness-gen run --beacon-url <URL>   # continuous mode
```

Outputs: `input.bin` (bincode-serialized witness) for the corresponding guest program.

## crate: `onchain-verifier`

`ZkasperVerifier.sol`:
- Stores: `poseidonRoot`, `totalActiveBalance`, `latestStateRoot`, `latestFinalizedEpoch`, `latestFinalizedCheckpointRoot`
- `bootstrap(proof, publicOutputs, stateRoot)` — one-time init
- `submitEpochDiff(proof, publicOutputs, stateRoot1, stateRoot2)` — verify proof, update accumulator state
- `submitFinality(proof, publicOutputs)` — verify proof, update finalized checkpoint
- `isFinalized(blockRoot, epoch) -> bool` — query

Verifier interface depends on Zisk's proof format (likely Groth16/FFLONK wrapper). Placeholder `IZiskVerifier.verify(proof, publicOutputs)`.

## implementation order

1. **Scaffold**: workspace Cargo.toml, all crate stubs, PLAN.md
2. **`common/merkle.rs`**: generic Merkle verify/compute root
3. **`common/ssz.rs`**: sha256_pair, validator_hash_tree_root, list_hash_tree_root, field verification
4. **`common/poseidon.rs`**: poseidon_leaf, poseidon_pair, Poseidon Merkle ops
5. **`common/types.rs`**: all witness structs with serde derives
6. **`epoch-diff-guest/main.rs`**: Proof 1 circuit logic
7. **`witness-gen/beacon_api.rs`**: beacon node client
8. **`witness-gen/poseidon_tree.rs`**: host-side tree
9. **`witness-gen/state_diff.rs`**: SSZ tree building + diffing
10. **`witness-gen/witness_epoch_diff.rs`**: assemble epoch diff witness
11. **`common/bls.rs`**: BLS verification (depends on Zisk pairing support)
12. **`finality-guest/main.rs`**: Proof 2 circuit logic
13. **`witness-gen/attestation_collector.rs`**: attestation fetching + committee resolution
14. **`witness-gen/witness_finality.rs`**: assemble finality witness
15. **`bootstrap-guest/main.rs`**: bootstrap circuit
16. **`witness-gen/witness_bootstrap.rs`**: bootstrap witness assembly
17. **`onchain-verifier/ZkasperVerifier.sol`**: Solidity contract

## open questions for Jordi / Zisk team

1. **Poseidon precompile** — no dedicated Poseidon syscall exists. Poseidon through `arith256_mod` works but is the dominant cost (~28M calls in finality proof). Is a Poseidon precompile planned?
2. **BLS12-381 pairing** — precompile list shows curve_add/dbl + complex field ops but no explicit pairing. Does `zisk-patch-bls12-381` implement full pairing via these? Cost per pairing?
3. **Recursive proof composition** — bootstrap needs chunking. Is recursive verification available in Zisk?
4. **Public inputs vs outputs** — how does the on-chain verifier bind proof public inputs? Is `set_output` the only mechanism?
5. **`arith256_mod` generality** — does it work for arbitrary 256-bit moduli (BN254 Fr for Poseidon) or only curve-specific moduli?
6. **Max cycle count** — what's the practical limit for a single proof? Can finality proof (~28M Poseidon) fit?
7. **Hash-to-G2** — is there a Zisk-optimized implementation of IETF hash-to-curve for BLS12-381?
8. **Zisk version** — target v0.15.0 or newer?
