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

## TODO (next sessions)
- [ ] Step 1: Implement `configure` and `synthesize` in `circuit.rs`
- [ ] Step 2: Wire up actual proof generation in sidecar (halo2_proofs::plonk::create_proof)
- [ ] Step 3: Implement rejection state machine
- [ ] Step 4: Polish SPEC.md into publishable form
- [ ] Step 5: Push to GitHub remote (user-confirm before running)
