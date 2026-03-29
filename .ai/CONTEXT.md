# pf-zk-compliance — Project Context

**Branch:** `master`  **Last Updated:** 2026-03-29  **Status:** Real proof generation done — `create_proof` + Blake2b transcript, pk/params loaded at startup; ZK-14 lookup-backed u64 range check complete; oracle key witness/hash binding landed; canonical direction changed from Ed25519 oracle authorization to a circuit-friendly Schnorr-style oracle scheme

---

next tasks: 

The next work here is fairly clear from the current code and spec.

  1. Implement the missing in-circuit oracle authorization checks under the new canonical scheme. The next concrete
     task is Schnorr-over-Pasta: add an ADR for the scheme change, wire Schnorr verification for
     `sender_oracle_sig` / `receiver_oracle_sig` into the circuit against the already-constrained `oracle_pubkey`, and
     retire the temporary sidecar-only Ed25519 verification path once circuit coverage exists.
  2. Remove the remaining byte-packing prototype and switch fully to the production hashing model. bytes_to_field is
     still a stopgap in crates/compliance-circuit/src/circuit.rs:322, and the tx hash/public input wiring is still
     folded into one field element instead of true byte-level/public-input layout in crates/compliance-circuit/src/
     circuit.rs:634. That is the main remaining gap between “working prototype” and the I/O described in docs/
     circuit_io.md:8.
  3. Move from prototype sizing to production sizing. The Merkle path logic is now on the right shape after ZK-13, but
     MERKLE_DEPTH is still 4 with a comment saying production should be 20 in crates/compliance-circuit/src/
     circuit.rs:72. That likely means benchmark work, larger-fixture tests, and regenerated proving/verifying keys.
  4. Finish the validator-facing integration that is only specified, not present in this repo. The sidecar exists, but
     the validator timeout, quarantine, proof propagation, and on-validator re-verification flows are still
     architectural work described in docs/SPEC.md:313.


## Active Work

| Status | Task | Scope | Notes |
|:------:|:-----|:-----:|:------|
| ✅ | **[ZK-0] Repo scaffold** | S | Workspace Cargo.toml, compliance-circuit + compliance-sidecar crates, .gitignore, git init. `cargo check` passes. |
| ✅ | **[ZK-1] Circuit I/O definition** | M | Initial circuit/public input shape documented. `docs/SPEC.md` is the target architecture; `.ai/CONTEXT.md` records approved implementation deltas when the workspace is intentionally staged. |
| ✅ | **[ZK-2] Sidecar IPC schema** | S | JSON-over-socket request/response schema. ProofRequest + ProofResponse structs in `crates/compliance-sidecar/src/main.rs`. Documented in §3 of SPEC.md. |
| ✅ | **[ZK-3] Consensus fallback design** | M | Timeout → quarantine → BFT quorum vote. Pessimistic mode on sidecar crash. 2f+1 rejection receipt logic. Documented in §4 of SPEC.md. |
| ✅ | **[ZK-4] SPEC.md published** | S | Full architecture spec published to GitHub Gist. |
| ✅ | **[ZK-5] Circuit `configure` impl** | L | Advice columns (a/b/c), fixed constants, instance, selectors s_hash/s_merkle/s_range, three gates. Prototype substitutions annotated inline with PROTOTYPE/PRODUCTION comments. |
| ✅ | **[ZK-6] Circuit `synthesize` impl** | L | 5 regions: load_witness, range_check, hash_binding (C3), sender_merkle (C1), receiver_merkle (C2). All public inputs wired to instance column via constrain_instance. 4 MockProver tests pass. |
| ✅ | **[ZK-7] Sidecar socket listener** | M | Unix domain socket listener with tokio. Newline-delimited JSON, spawn_blocking for circuit work, stale socket cleanup on startup. Linux only (`cfg(unix)`). |
| ✅ | **[ZK-8] Key generation CLI** | M | `compliance-sidecar keygen --k 8` command. Outputs `.params`, `.vk`, `.pk` via `ParamsKZG<Bn256>` + `keygen_vk_custom` / `keygen_pk_custom`. |
| ✅ | **[ZK-9] Real proof generation** | M | `MockProver` replaced with `create_proof` (SHPLONK + Blake2b transcript). `ParamsKZG` + `ProvingKey` loaded via `pk_read` at startup into `Arc<ProverState>`. Proof bytes base64-encoded in `ProofResponse`. `serve` subcommand takes `--pk` and `--params` flags. |
| ✅ | **[ZK-10] Proof verification in sidecar** | M | `verify_proof_multi` (SHPLONK + Blake2b) called immediately after `create_proof`. VK loaded into `ProverState` at startup via `vk_read`. Verify failure → `"non_compliant"` status; internal errors → `"error"`. `serve` now takes `--vk` flag. `cargo check` passes. |
| ✅ | **[ZK-11] Spec v1.1 pubkey-model alignment** | M | Rust circuit and sidecar IPC now use the spec-defined XRPL ed25519 transaction-party pubkey model (`[u8; 32]`) plus oracle-signature/oracle-pubkey-hash fields. Validation rejects malformed pubkeys/oracle fields before proving. `cargo test -p compliance-circuit`, `cargo test -p compliance-sidecar`, and combined crate tests pass in a normal local environment. |
| ✅ | **[ZK-12] Poseidon hash gates** | L | C3 transaction binding now uses Poseidon over `[sender_pubkey, receiver_pubkey, amount]` in the Rust circuit. Public-input wiring stays at the folded `TX_HASH_START` field element. Added focused tests for valid witnesses, tampered public `tx_hash`, and tampered witness `amount`. Full `cargo test` passes. |
| ✅ | **[ZK-13] Binary Merkle chip** | L | Sender/receiver membership now use fixed-depth binary Poseidon paths to the shared compliance root, with per-level sibling + direction-bit witnesses. Merkle leaves are `Poseidon(pubkey)` to match the spec. Focused pass/fail tests and the sidecar's real proof/verify test both pass. |
| ✅ | **[ZK-14] Lookup table range check** | S | The tautological placeholder is gone. `amount` is now decomposed into eight 8-bit limbs, each constrained by a shared lookup table and recomposed back into the same witness value used by the Poseidon tx hash gate. Added pass/fail tests for valid u64 and non-u64 field values. |
| [ ] | **[ZK-15] In-circuit oracle authorization** | L | Correct task after ZK-14. `oracle_pubkey` is now present in the witness/request path and the circuit binds `Poseidon(oracle_pubkey)` to public `oracle_pubkey_hash`; remaining work is the actual Schnorr-over-Pasta verification gadget for `sender_oracle_sig` over `Poseidon(sender_pubkey)` and `receiver_oracle_sig` over `Poseidon(receiver_pubkey)`, plus an ADR and circuit-level valid/tampered authorization tests. |
| [ ] | **[ZK-16] postfiatd IPC hook** | L | C++ side of the socket interface in postfiatd. Calls sidecar before forwarding tx to RPCA consensus. Depends on ZK-9/10/11 being stable. **When implementing: add `tokio::sync::Semaphore` in `ProverState` to cap concurrent `spawn_blocking` proof jobs — each proof is ~100-300 MB at k=8, unbounded concurrency under burst load causes OOM. Limit should be a `--max-concurrent-proofs` CLI flag sized against real circuit memory at production k.** Integration target remains the Post Fiat `postfiatd` validator daemon described in `docs/SPEC.md`. |
| [ ] | **[ZK-17] Pin halo2 git dep** | S | Add `rev = "<commit>"` to halo2_proofs git dep in all Cargo.toml files. Supply-chain hygiene before any production deployment. |

---

## Architecture Decisions

| ID | Decision | Rationale | Alternatives rejected |
|:--:|:---------|:----------|:----------------------|
| AD-1 | PSE halo2 fork over zcash/halo2 | Actively maintained, production ZK teams (Scroll, PSE) use it, cleaner frontend/backend split | zcash fork: less active; arkworks: different arithmetization |
| AD-2 | Poseidon hash over SHA256 inside circuit | ~60 constraints vs ~27,000 for SHA256 in PLONK. Sub-second proof times on server hardware | SHA256: too expensive; Pedersen: less collision resistant |
| AD-3 | Sidecar as separate process | Crash isolation — sidecar failure doesn't crash validator. CPU-heavy proof gen doesn't block RPCA event loop | In-process: simpler but couples lifecycles |
| AD-4 | JSON-over-socket IPC | Simple, debuggable, language-agnostic (C++ postfiatd ↔ Rust sidecar) | gRPC: overkill for single-machine IPC; raw binary: harder to debug |
| AD-5 | ZK as complement to LLM OFAC screening | Post Fiat already has LLM-delegated compliance. ZK adds cryptographic provability on top, not a replacement | Replace LLM screening: would remove existing functionality |
| AD-6 | Gate degree target ≤ 5 | Leaves headroom under PLONK degree bound of 8 while accommodating in-circuit oracle authorization. Poseidon remains degree 3 and the Merkle gate degree 4 | Higher degree: risks constraint system errors |
| AD-7 | BN254 Fr over Pasta Fp | `ParamsKZG<Bn256>` requires `Circuit<Fr>`. ComplianceCircuit is generic over `F: PrimeField` so zero gate logic changed | Pasta as proving field: incompatible with current KZG choice |
| AD-8 | `compress_selectors = true` | Must be consistent across keygen / prove / verify. Chosen at keygen and locked in | false: wastes constraint columns |
| AD-9 | Two per-party Merkle proofs to one shared root | Matches the current circuit decomposition and keeps membership statements local to each pubkey while sharing the same compliance snapshot root | Single combined sender/receiver leaf: couples witness semantics unnecessarily and diverges from current implementation path |
| AD-10 | Oracle auth scheme is protocol-controlled | Because the oracle is internal to Post Fiat, the project can choose a circuit-friendly Schnorr-style scheme instead of forcing Ed25519 into the proof system | Keep Ed25519 for oracle auth: requires non-native Edwards arithmetic and a substantially more complex gadget path |

---

## Concept Lineage (from shards repo)

| Concept | Source file | Applied as |
|:--------|:------------|:-----------|
| Public/private input discipline | [`docs/MONSTER_HARMONIC_ZKSNARK.md`](../docs/MONSTER_HARMONIC_ZKSNARK.md) | Instance vs Advice column split in ComplianceCircuit |
| Constraint sizing awareness | Groth16/BN128 notes | Chose Halo2 (no trusted setup) over Groth16 — avoids MPC ceremony complexity |
| Consensus rejection + quorum fallback | [`docs/PAXOS_WITNESS_PROTOCOL.md`](../docs/PAXOS_WITNESS_PROTOCOL.md), [`docs/QUORUM_CONSENSUS.md`](../docs/QUORUM_CONSENSUS.md) | §4 quarantine + 2f+1 BFT vote logic |
| Sidecar plugin submission pattern | [`docs/MONSTER_HARMONIC_ZKSNARK.md`](../docs/MONSTER_HARMONIC_ZKSNARK.md) (zkOS plugin) | IPC schema shape + sidecar process model |

---

## Key Files

| File | Purpose |
|:-----|:--------|
| `docs/SPEC.md` | Canonical architecture spec (v1.1 proposal) for the target Post Fiat/pubkey-based design |
| `docs/circuit_io.md` | Detailed circuit input table + constraint equations |
| `crates/compliance-circuit/src/circuit.rs` | Full ComplianceCircuit: configure, synthesize, 4 MockProver tests |
| `crates/compliance-sidecar/src/main.rs` | CLI (serve / keygen), Unix socket listener, real `create_proof` dispatch |
| `.ai/DEVLOG.md` | Chronological session narrative — decisions, API gotchas, lineage detail |

---

## Known Issues / Notes

- **[ZK-9 done]** `run_circuit()` uses `create_proof` (SHPLONK + Blake2b). `serve` loads `.pk` + `.params` at startup via `pk_read` / `ParamsKZG::read`. `cargo check --target x86_64-unknown-linux-gnu` passes.
- **[ZK-10 done]** `verify_proof_multi` called after `create_proof` in `run_circuit`. VK loaded at startup via `vk_read` into `ProverState`. `serve --vk` flag added. Verify failure returns `"non_compliant"`; prover/decode errors return `"error"`. `cargo check` passes.
- **[source of truth]** `docs/SPEC.md` is the target architecture. `.ai/CONTEXT.md` is the implementation-status ledger and may record approved deltas while the Rust workspace is moved toward the spec in stages. If code diverges from both, update docs or code so one of them explicitly explains the delta.
- **[ZK-11 done]** Rust IPC/circuit boundary now uses `sender_pubkey` / `receiver_pubkey` (`[u8; 32]`) plus `sender_oracle_sig` / `receiver_oracle_sig` (`[u8; 64]`) and public `oracle_pubkey_hash`. Validation rejects malformed pubkey/oracle-field payloads before proving begins.
- **[open]** PSE halo2 git dep is unpinned (`git = "..."` without a rev). Must pin to a specific commit before any production deployment.
- **[ZK-12 done]** C3 transaction binding no longer uses the prototype linear gate. It now enforces a Poseidon-based hash path in `crates/compliance-circuit/src/circuit.rs`. The sidecar's proof-building test fixture was updated to derive the same `tx_hash` field value via the shared helper.
- **[ZK-13 done]** Merkle membership now uses two fixed-depth binary Poseidon paths, one for sender and one for receiver, converging to the shared public `compliance_merkle_root`. Merkle leaves are `Poseidon(pubkey)`, matching `docs/SPEC.md` and `docs/circuit_io.md`.
- **[ZK-14 done]** `amount` is now range-checked as a true u64 via an 8-bit lookup table plus linear recomposition. The same copied advice cell feeds both the range-check region and the C3 Poseidon binding, so the prover cannot swap in a different amount across regions.
- **[ZK-15 partial]** The circuit/sidecar boundary now includes the raw `oracle_pubkey`, and the circuit constrains `Poseidon(oracle_pubkey)` to the public `oracle_pubkey_hash`. This closes the unchecked pass-through gap and sets up the correct interface for the future in-circuit oracle authorization gadget.
- **[temporary]** `compliance-sidecar` currently performs native Ed25519 verification before proving because that was the staged prototype path. With the canonical direction changed to a circuit-friendly Schnorr-style oracle scheme, this sidecar check is now transitional rather than architectural.
- **[open]** The current `bytes_to_field` prototype only safely represents 32-byte values below the BN254 Fr modulus. That is acceptable for staged tests but not for arbitrary 32-byte public keys. The production byte-level public/witness encoding work must remove this limitation before the final in-circuit oracle authorization can be considered complete.
- **[open, by design]** Instance column wires one folded field element per public input. Production circuit would wire all 32 individual byte cells to match the full `[u8; 32]` layout in `docs/circuit_io.md`.
- **[open]** `postfiatd` is C++ (rippled fork). No C++ changes are needed until ZK-16 (IPC hook).
- **[platform]** Unix socket listener is Linux-only (`cfg(unix)`). Build/type-check on Windows with `cargo check --target x86_64-unknown-linux-gnu -p compliance-sidecar`.

---

## External References

- [postfiatd repo](https://github.com/postfiatorg/postfiatd) — C++ rippled fork, the validator daemon we integrate with
- [Post Fiat whitepaper](https://postfiat.org/whitepaper/) — LLM-based OFAC screening (what ZK layer complements)
- [PSE halo2](https://github.com/privacy-scaling-explorations/halo2) — proof system used
- [Poseidon paper](https://eprint.iacr.org/2019/458) — hash function used inside circuit
- [PLONK paper](https://eprint.iacr.org/2019/953) — arithmetization underpinning halo2
- [Halo2 book](https://zcash.github.io/halo2/) — circuit design reference
