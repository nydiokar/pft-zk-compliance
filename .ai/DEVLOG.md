# DEVLOG.md — Session Narrative & Decision Journal

Chronological record of what was done each session, why decisions were made, and
API gotchas encountered. For current project status and task tracking see `CONTEXT.md`.

---

## Session 2026-03-04 — Initial Scaffold

**Problem Statement:**
Build a Compliance-Aware Transaction Filter for a Post Fiat validator stack using Halo2
ZK proofs. The filter intercepts transactions before consensus, generates a ZK proof that
the transaction satisfies compliance constraints (sender/receiver membership in an on-chain
compliance list), and either passes the proof to the validator or triggers a consensus
fallback (quarantine/reject).

**Halo2 Fork Decision:**
Chose PSE fork (`privacy-scaling-explorations/halo2`) over `zcash/halo2`:
- PSE fork is actively maintained by production ZK teams (Scroll, PSE itself)
- Better gadget library for Merkle proofs
- The BN128 constraint-sizing lessons from shards showed gadget quality matters
  enormously — PSE's maintained gadgets reduce risk of under-constrained circuits

---

## Session 2026-03-04 — Circuit Implementation

**What was done:**
Implemented the full `ComplianceCircuit` in `crates/compliance-circuit/src/circuit.rs`.

**Configure:**
- Three advice columns (`a`, `b`, `c`), one fixed constants column, one instance column
- Three selectors: `s_hash`, `s_merkle`, `s_range`
- `hash_binding` gate: `a + b = c` (C3)
- `merkle_path` gate: `node + sibling = parent` (C1/C2 per level)
- `range_check` gate: placeholder selector (tautological in prototype)

**Synthesize (5 regions):**
1. `load_witness` — assigns sender, receiver, amount into advice cells
2. `range_check` — copies amount into range-check row (gate fires, does nothing yet)
3. `hash_binding` — copies sender+receiver, assigns tx_hash_out, wires to instance[0]
4. `sender_merkle` — MERKLE_DEPTH rows of path traversal, root wired to instance[32]
5. `receiver_merkle` — same structure, root wired to instance[32] (same compliance root)
6. `block_height` — assigns bh into advice, wires to instance[64]

**Instance wiring fix:**
Previous scaffold had no `constrain_instance` calls — public inputs were declared but never
enforced. Added wiring for all three public commitments so the MockProver permutation
checker actually validates them.

**Prototype substitutions:**

| Spec | Prototype | Reason |
|------|-----------|--------|
| `Poseidon(sender ‖ receiver ‖ amount)` | `sender_sum + receiver_sum` | `halo2_gadgets` adds heavy dep + chip complexity |
| `Poseidon(left, right)` at each Merkle level | `left + right` | Same reason; path structure is production-correct |
| Lookup table range check | Tautological gate `s*(a-a)=0` | Lookup table needs a separate fixed table column |
| `bytes_to_field`: Poseidon sponge | Sum of byte values | Prototype encoding; not collision-resistant |

**Tests (all passing, `cargo test -p compliance-circuit`):**
- `test_valid_witness_passes` — MockProver verify() succeeds for valid witness
- `test_wrong_tx_hash_fails` — corrupted instance[0] → permutation error
- `test_wrong_merkle_root_fails` — corrupted instance[32] → permutation error
- `test_wrong_merkle_path_fails` — flipped sibling byte → root_anchor constrain_equal fails

**Key Halo2 API insight:**
`constrain_instance` is a `Layouter`-level call (not `Region`-level). It records a
copy-constraint in the permutation argument. MockProver.verify() checks all copy
constraints — including instance ones — automatically via the permutation checker.
No special instance verification step needed.

---

## Session 2026-03-05 — Unix Socket IPC Listener

**What was done:**
Implemented the full Unix domain socket listener in `crates/compliance-sidecar/src/main.rs`.

**Architecture:**
- `UnixListener` bound to `POSTFIAT_ZKP_SOCKET` env var (default `/tmp/postfiat_zkp.sock`)
- Stale socket cleanup on startup (`remove_file` before `bind`)
- `tokio::spawn` per connection — listener never blocks on slow provers
- Newline-delimited JSON framing: one `ProofRequest` in, one `ProofResponse` out, connection closed
- `into_split()` for owned read/write halves (avoids lifetime conflict with `BufReader`)
- `spawn_blocking` for circuit work — async runtime not starved by CPU-bound proving

**Prover integration:**
- `run_circuit()` decodes all hex fields, validates `merkle_path` length (`2 * MERKLE_DEPTH`)
- Builds `ComplianceCircuit { public, witness }` exactly as circuit tests do
- Constructs instance column using `bytes_to_field_fp` (exact mirror of `circuit.rs bytes_to_field`)
- Runs `MockProver::run + verify()` — constraint logic identical to production prover
- Returns `"compliant"` / `"non_compliant"` / `"error"` with populated `public_inputs` hex

**Prototype proof_bytes:**
Instance column serialized to bytes and base64-encoded as stand-in for real proof bytes.
Upgrade path: replace `MockProver` block with `create_proof` once `Params`/`ProvingKey` init added.

**Error handling:**
- Malformed JSON → `status: "error"`, sidecar continues
- Hex decode failure → `status: "error"`, precise field name in error message
- Wrong merkle_path length → `status: "error"` before circuit is even invoked
- Constraint violation → `status: "non_compliant"`, logged
- `spawn_blocking` panic → `status: "error"`, panic message forwarded

**Platform decision:**
`tokio::net::UnixListener` is gated on `cfg(unix)` by tokio. Added `compile_error!` on
non-Unix targets. All logic is in `mod inner { #[cfg(unix)] }`.
Build from Windows: `cargo check --target x86_64-unknown-linux-gnu -p compliance-sidecar`

**New dependencies added:**
- `halo2curves = "0.7"` — concrete `Fr` field type
- `base64 = "0.22"` — proof_bytes encoding
- `hex = "0.4"` — hex field decoding

---

## Session 2026-03-05 — Keygen CLI + BN254 Field Migration

**What was done:**
Migrated `compliance-sidecar` from Pasta scalar field (`Fp`) to BN254 scalar field (`Fr`)
and added a `keygen` subcommand to produce real `.vk`, `.pk`, and `.params` files.

**Why Fr?**
`ParamsKZG<Bn256>` — the only KZG commitment scheme in the pinned PSE halo2 fork —
requires `Circuit<Fr>`. `ComplianceCircuit` is already generic over `F: ff::PrimeField`,
so zero circuit gate logic changed; only the sidecar's hardcoded `Fp` references updated.

**Changes:**

| File | Change |
|------|--------|
| `crates/compliance-sidecar/Cargo.toml` | Added `clap = "4"`, `rand = "0.8"`, `rand_core = "0.6"` |
| `crates/compliance-sidecar/src/main.rs` | Replaced `Fp` → `Fr`; added `clap` CLI with `serve` / `keygen` subcommands |
| `crates/compliance-circuit/src/circuit.rs` (tests) | Replaced `use halo2curves::pasta::Fp` with `use halo2curves::bn256::Fr`; all 4 tests pass |

**Keygen implementation:**
```rust
let params = ParamsKZG::<Bn256>::setup(k, OsRng);
let vk = keygen_vk_custom(&params, &circuit, true).unwrap();   // compress_selectors=true
let pk = keygen_pk_custom(&params, vk.clone(), &circuit, true).unwrap();
params.write(w)?;   // requires `use halo2_proofs::poly::commitment::Params` in scope
vk.write(w, SerdeFormat::RawBytes).unwrap();
pk.write(w, SerdeFormat::RawBytes).unwrap();
```

**Verified on Windows (cross-platform keygen):**
```
compliance-sidecar keygen --k 8 --vk /tmp/test.vk --pk /tmp/test.pk --params /tmp/test.params
# Output: params (33K), vk (518B), pk (305K)
```

**API gotchas encountered:**
- `Fr::ZERO` requires `use halo2_proofs::arithmetic::Field` in scope
- `Fr::from_repr` requires `use halo2curves::ff::PrimeField` in scope
- `ParamsKZG::write` requires `use halo2_proofs::poly::commitment::Params` in scope
- BN254 Fr modulus LE byte[31] = 0x30. Modulus guard must be `arr[31] >= 0x30` (not 0x31) —
  values with byte[31] == 0x30 may equal p exactly and fail `from_repr` silently
