# CONTEXT.md — Session Log & Concept Lineage Tracker

## Purpose
This file is a timestamped session log. It tracks architectural decisions,
records what was borrowed from the shards repo, and notes why choices were made.
It is NOT the spec — see SPEC.md for the publishable architecture document.

---

## Session 2026-03-04 — Initial Scaffold

### Problem Statement
Build a Compliance-Aware Transaction Filter for a Post Fiat validator stack
using Halo2 ZK proofs. The filter intercepts transactions before consensus,
generates a ZK proof that the transaction satisfies compliance constraints
(sender/receiver membership in an on-chain compliance list), and either passes
the proof to the validator or triggers a consensus fallback (quarantine/reject).

### Shards Repo Lineage

This project borrows heavily from prior ZK work in
`C:/Users/Cicada38/Projects/shards`. Key concept transfers:

| Concept | Shards source | Applied here |
|---|---|---|
| Public/private input discipline | `MONSTER_HARMONIC_ZKSNARK.md` | `ComplianceCircuit` field split: `tx_hash`, `compliance_merkle_root`, `block_height` are public; witness data stays private |
| Constraint sizing awareness (BN128/Groth16 experience) | Groth16/BN128 notes in shards | Chose Halo2 (PLONK-based, no trusted setup) over Groth16 — avoids the MPC ceremony complexity we hit with BN128 |
| Consensus rejection + quorum fallback | `PAXOS_WITNESS_PROTOCOL.md`, `QUORUM_CONSENSUS.md` | Step 3 rejection logic: quarantine → timeout → BFT vote |
| Sidecar plugin submission pattern | `MONSTER_HARMONIC_ZKSNARK.md` (zkOS plugin) | IPC schema shape: JSON envelope with `proof_bytes`, `public_inputs`, `tx_hash` |

### Halo2 Fork Decision
Chose **PSE fork** (`privacy-scaling-explorations/halo2`) over `zcash/halo2`:
- PSE fork is actively maintained by production ZK teams (Scroll, PSE itself)
- Better gadget library for Merkle proofs (what we need for membership constraint)
- zcash/halo2 upstream is read-only reference for studying gate/constraint internals
- The BN128 constraint-sizing lessons from shards showed us that gadget quality
  matters enormously — PSE's maintained gadgets reduce the risk of under-constrained
  circuits

### Dependency pinning note
Currently using `git = "..."` without a rev pin. TODO before mainnet: pin to a
specific commit hash to prevent supply-chain drift.

---

## Session 2026-03-04 — Circuit Implementation

### What was done

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
Previous scaffold had no `constrain_instance` calls — public inputs were declared
but never enforced. Added wiring for all three public commitments so the MockProver
permutation checker actually validates them.

**Prototype substitutions (documented inline with PROTOTYPE/PRODUCTION comments):**

| Spec (circuit_io.md) | Prototype | Reason |
|---|---|---|
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

**Published:** https://github.com/nydiokar/pft-zk-compliance (commit d43ab7c)

---

## TODO (next sessions)
- [x] Step 1: Implement `configure` and `synthesize` in `circuit.rs`
- [x] Step 5: Push to GitHub remote
- [ ] Step 2: Wire up actual proof generation in sidecar (`halo2_proofs::plonk::create_proof`)
- [ ] Step 3: Implement rejection state machine
- [ ] Step 4: Polish SPEC.md into publishable form
- [ ] Production upgrade: swap linear gates for `halo2_gadgets::poseidon::Hash` chip
- [ ] Production upgrade: swap Merkle addition for binary Merkle chip
- [ ] Production upgrade: swap range placeholder for lookup table range check
- [ ] Pin halo2_proofs git dep to a specific commit hash (supply-chain hygiene)
