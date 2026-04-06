# pf-zk-compliance — Project Context

**Branch:** `master`  **Last Updated:** 2026-04-06  **Status:** Real proof generation done — `create_proof` + Blake2b transcript, pk/params loaded at startup; ZK-14 lookup-backed u64 range check complete; Halo2 git dependency pinned across the sidecar build graph with documented upgrade steps; staged in-circuit oracle authorization landed with the sidecar-only Ed25519 path removed; Rust-side canonical Pallas pubkey and Schnorr `(R,s)` boundary guards reject malformed and BN254-incompatible encodings before witness generation; ZK-15c reference equation traces now pin fixed valid/tampered Schnorr-over-Pasta vectors to the current canonical Rust witness encoding and the sidecar normalization path

---

next tasks:

The next work should stop preparing and start committing protocol choices.

  1. Freeze the final Schnorr-over-Pasta verifier transcript and statement, then implement the real non-native
     authorization equation in-circuit against the fixed ZK-15c reference vectors. The important unresolved design
     choice is no longer witness shape; it is the exact challenge transcript and verifier relation the production
     circuit will enforce.
  2. Once that verifier is in, remove the staged scalar relation and only then start removing the remaining
     byte-packing prototype (`bytes_to_field`) where it materially blocks the final verifier path. Doing byte/limb work
     before the verifier statement is frozen risks more churn.
  3. After the real verifier lands, move from prototype sizing to production sizing. The Merkle path logic is now on
     the right shape after ZK-13, but `MERKLE_DEPTH` is still 4 with a comment saying production should be 20 in
     `crates/compliance-circuit/src/circuit.rs`. That likely means benchmark work, larger-fixture tests, and
     regenerated proving/verifying keys.
  4. Finish the validator-facing integration that is only specified, not present in this repo. The sidecar exists, but
     the validator timeout, quarantine, proof propagation, and on-validator re-verification flows are still
     architectural work described in `docs/SPEC.md`.


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
| [ ] | **[ZK-15] In-circuit oracle authorization** | L | The staged Rust-side migration is now in place: `oracle_pubkey` is parsed as a canonical compressed Pallas point, `sender_oracle_sig` / `receiver_oracle_sig` are parsed as canonical `(R,s)` bytes, malformed / identity / BN254-incompatible encodings are rejected before witness construction, the old sidecar-only Ed25519 path is gone, and ZK-15c reference traces now pin fixed valid/tampered equation vectors through both the circuit and sidecar normalization path. Remaining work is the protocol-final Schnorr transcript decision and the real non-native verifier equation inside the circuit, replacing the temporary scalar relation. |
| [ ] | **[ZK-16] postfiatd IPC hook** | L | C++ side of the socket interface in postfiatd. Calls sidecar before forwarding tx to RPCA consensus. Depends on ZK-9/10/11 being stable. **When implementing: add `tokio::sync::Semaphore` in `ProverState` to cap concurrent `spawn_blocking` proof jobs — each proof is ~100-300 MB at k=8, unbounded concurrency under burst load causes OOM. Limit should be a `--max-concurrent-proofs` CLI flag sized against real circuit memory at production k.** Integration target remains the Post Fiat `postfiatd` validator daemon described in `docs/SPEC.md`. |
| ✅ | **[ZK-17] Pin halo2 git dep** | S | `halo2_proofs` now pins `privacy-scaling-explorations/halo2` to `198e9ae30d322cd0ad003b6955f91ec095b1490d` in both `crates/compliance-sidecar` and `crates/compliance-circuit`. Added `DEPENDENCY_PINS.md`, refreshed local `Cargo.lock`, and verified with `cargo test -p compliance-sidecar --locked`. |

---

## ZK-15 Phases

ZK-15 is a sequence, not one atomic patch.

| Phase | Status | Meaning |
|:------|:------:|:--------|
| `ZK-15a` Remove split-trust path | ✅ | The sidecar-only Ed25519 authorization path is gone. Authorization now lives on the proof side of the boundary. |
| `ZK-15b` Canonical Rust boundary | ✅ | Oracle pubkeys are parsed as canonical compressed Pallas points; signatures are parsed as canonical `(R,s)` bytes; malformed, identity, and BN254-incompatible encodings are rejected before witness construction. |
| `ZK-15c` Reference equation vectors | ✅ | Fixed valid/tampered Schnorr-over-Pasta equation traces are now pinned to the current canonical Rust witness encoding, and the sidecar normalization path is checked against the same vector bytes. This is an audit fixture phase, not the final protocol transcript commitment. |
| `ZK-15d` Freeze transcript + real verifier equation | [ ] | Choose and document the final Schnorr challenge transcript and verifier statement, then replace the staged scalar relation with the real non-native Schnorr-over-Pasta verification equation in the circuit. |
| `ZK-15e` Remove byte-packing leftovers | [ ] | After the real verifier is chosen, move oracle material and eventually wider circuit I/O toward byte/limb-based witness handling instead of the current `bytes_to_field` staging path. |

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
- **[ZK-17 done]** Halo2 is pinned to `198e9ae30d322cd0ad003b6955f91ec095b1490d` everywhere the sidecar build graph declares `halo2_proofs`. `DEPENDENCY_PINS.md` records the current revision and upgrade procedure, and the repo now allows tracking `Cargo.lock` so the resolved graph can be audited in Git.
- **[ZK-12 done]** C3 transaction binding no longer uses the prototype linear gate. It now enforces a Poseidon-based hash path in `crates/compliance-circuit/src/circuit.rs`. The sidecar's proof-building test fixture was updated to derive the same `tx_hash` field value via the shared helper.
- **[ZK-13 done]** Merkle membership now uses two fixed-depth binary Poseidon paths, one for sender and one for receiver, converging to the shared public `compliance_merkle_root`. Merkle leaves are `Poseidon(pubkey)`, matching `docs/SPEC.md` and `docs/circuit_io.md`.
- **[ZK-14 done]** `amount` is now range-checked as a true u64 via an 8-bit lookup table plus linear recomposition. The same copied advice cell feeds both the range-check region and the C3 Poseidon binding, so the prover cannot swap in a different amount across regions.
- **[ZK-15 partial]** The circuit now enforces a staged in-circuit authorization relation and the sidecar no longer performs native Ed25519 verification before proving. The remaining gap is replacing that temporary scalar relation with the real non-native Schnorr-over-Pasta equation.
- **[ZK-15c done]** The repo now has fixed valid/tampered Schnorr-over-Pasta equation-trace fixtures in the circuit crate, tied to the current canonical Rust encoding (`oracle_pubkey_hash`, `Poseidon(pubkey)` bytes, canonical `R`) and checked through sidecar request normalization. These vectors are intentionally audit fixtures for the later non-native verifier patch, not a final transcript freeze.
- **[boundary hardening done]** Oracle pubkeys are now parsed as canonical compressed Pallas points, signatures as canonical `(R,s)` bytes, and the sidecar rejects malformed, identity, and BN254-incompatible encodings before witness construction. This makes the current staged circuit path auditable instead of silently collapsing incompatible bytes.
- **[open, highest priority]** The protocol-final Schnorr challenge transcript is still not frozen. That is now the main decision blocking the real non-native verifier implementation; further “bridge” work should be resisted unless it directly serves that patch.
- **[open]** The current `bytes_to_field` prototype still reduces 32-byte values into one BN254 field element inside the circuit. The new boundary guards ensure oracle material only enters that path when the encoding is exactly representable in BN254 `Fr`, but the production byte/limb-based witness encoding work should follow, not precede, the final verifier statement.
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
