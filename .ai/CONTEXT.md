# pf-zk-compliance — Project Context

**Branch:** `master`  **Last Updated:** 2026-03-06  **Status:** Keygen CLI done, MockProver serving over Unix socket

---

## Active Work

| Status | Task | Scope | Notes |
|:------:|:-----|:-----:|:------|
| ✅ | **[ZK-0] Repo scaffold** | S | Workspace Cargo.toml, compliance-circuit + compliance-sidecar crates, .gitignore, git init. `cargo check` passes. |
| ✅ | **[ZK-1] Circuit I/O definition** | M | Public inputs (tx_hash, merkle_root, block_height), private witness (sender, receiver, amount, merkle_path). Documented in `docs/circuit_io.md` and §2 of SPEC.md. |
| ✅ | **[ZK-2] Sidecar IPC schema** | S | JSON-over-socket request/response schema. ProofRequest + ProofResponse structs in `crates/compliance-sidecar/src/main.rs`. Documented in §3 of SPEC.md. |
| ✅ | **[ZK-3] Consensus fallback design** | M | Timeout → quarantine → BFT quorum vote. Pessimistic mode on sidecar crash. 2f+1 rejection receipt logic. Documented in §4 of SPEC.md. |
| ✅ | **[ZK-4] SPEC.md published** | S | Full architecture spec published to GitHub Gist. |
| ✅ | **[ZK-5] Circuit `configure` impl** | L | Advice columns (a/b/c), fixed constants, instance, selectors s_hash/s_merkle/s_range, three gates. Prototype substitutions annotated inline with PROTOTYPE/PRODUCTION comments. |
| ✅ | **[ZK-6] Circuit `synthesize` impl** | L | 5 regions: load_witness, range_check, hash_binding (C3), sender_merkle (C1), receiver_merkle (C2). All public inputs wired to instance column via constrain_instance. 4 MockProver tests pass. |
| ✅ | **[ZK-7] Sidecar socket listener** | M | Unix domain socket listener with tokio. Newline-delimited JSON, spawn_blocking for circuit work, stale socket cleanup on startup. Linux only (`cfg(unix)`). |
| ✅ | **[ZK-8] Key generation CLI** | M | `compliance-sidecar keygen --k 8` command. Outputs `.params`, `.vk`, `.pk` via `ParamsKZG<Bn256>` + `keygen_vk_custom` / `keygen_pk_custom`. |
| [ ] | **[ZK-9] Real proof generation** | M | Replace `MockProver` in `run_circuit()` with `create_proof`. Load `.pk` and `.params` from disk at sidecar startup. |
| [ ] | **[ZK-10] Proof verification in sidecar** | M | After `create_proof`, call `verify_proof` inside the sidecar before returning `"compliant"`. Ensures the sidecar never returns a verdict it can't back with a valid proof. |
| [ ] | **[ZK-11] XRPL address encoding** | S | Swap `[u8; 20]` placeholder for XRPL base58 classic address format in circuit struct and IPC schema. |
| [ ] | **[ZK-12] Poseidon hash gates** | L | Replace prototype linear gates (`a + b = c`) with `halo2_gadgets::poseidon::Hash` chip. Required for cryptographic soundness — current gates are not collision-resistant. |
| [ ] | **[ZK-13] Binary Merkle chip** | L | Replace prototype additive Merkle path with proper binary Merkle chip. Pair with ZK-12 (Poseidon at each level). |
| [ ] | **[ZK-14] Lookup table range check** | S | Replace tautological range gate with a proper lookup table constraining `amount` to u64. |
| [ ] | **[ZK-15] postfiatd IPC hook** | L | C++ side of the socket interface in postfiatd. Calls sidecar before forwarding tx to RPCA consensus. Depends on ZK-9/10/11 being stable. |
| [ ] | **[ZK-16] Pin halo2 git dep** | S | Add `rev = "<commit>"` to halo2_proofs git dep in all Cargo.toml files. Supply-chain hygiene before any production deployment. |

---

## Architecture Decisions

| ID | Decision | Rationale | Alternatives rejected |
|:--:|:---------|:----------|:----------------------|
| AD-1 | PSE halo2 fork over zcash/halo2 | Actively maintained, production ZK teams (Scroll, PSE) use it, cleaner frontend/backend split | zcash fork: less active; arkworks: different arithmetization |
| AD-2 | Poseidon hash over SHA256 inside circuit | ~60 constraints vs ~27,000 for SHA256 in PLONK. Sub-second proof times on server hardware | SHA256: too expensive; Pedersen: less collision resistant |
| AD-3 | Sidecar as separate process | Crash isolation — sidecar failure doesn't crash validator. CPU-heavy proof gen doesn't block RPCA event loop | In-process: simpler but couples lifecycles |
| AD-4 | JSON-over-socket IPC | Simple, debuggable, language-agnostic (C++ postfiatd ↔ Rust sidecar) | gRPC: overkill for single-machine IPC; raw binary: harder to debug |
| AD-5 | ZK as complement to LLM OFAC screening | Post Fiat already has LLM-delegated compliance. ZK adds cryptographic provability on top, not a replacement | Replace LLM screening: would remove existing functionality |
| AD-6 | Gate degree target ≤ 4 | Leaves headroom under PLONK degree bound of 8. Poseidon gate is degree 3, Merkle gate degree 4 | Higher degree: risks constraint system errors |
| AD-7 | BN254 Fr over Pasta Fp | `ParamsKZG<Bn256>` requires `Circuit<Fr>`. ComplianceCircuit is generic over `F: PrimeField` so zero gate logic changed | Pasta: incompatible with KZG commitment scheme |
| AD-8 | `compress_selectors = true` | Must be consistent across keygen / prove / verify. Chosen at keygen and locked in | false: wastes constraint columns |

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
| `SPEC.md` | Publishable architecture spec (v1.0 final) |
| `docs/circuit_io.md` | Detailed circuit input table + constraint equations |
| `crates/compliance-circuit/src/circuit.rs` | Full ComplianceCircuit: configure, synthesize, 4 MockProver tests |
| `crates/compliance-sidecar/src/main.rs` | CLI (serve / keygen), Unix socket listener, MockProver dispatch |
| `.ai/DEVLOG.md` | Chronological session narrative — decisions, API gotchas, lineage detail |

---

## Known Issues / Notes

- **[ZK-9 open]** `run_circuit()` still uses `MockProver`. Real proof generation requires loading `.pk` and `.params` at startup and calling `create_proof`.
- **[ZK-11 open]** `[u8; 20]` address type in `Witness` struct is an Ethereum-style placeholder. XRPL uses base58 classic addresses (different encoding).
- **[open]** PSE halo2 git dep is unpinned (`git = "..."` without a rev). Must pin to a specific commit before any production deployment.
- **[open, by design]** Prototype gates use linear arithmetic (`a + b = c`) in place of Poseidon. Circuit enforces correct constraint topology but is not cryptographically collision-resistant. Every substitution is annotated inline in `circuit.rs` with `PROTOTYPE:` / `PRODUCTION:` comments.
- **[open, by design]** Instance column wires one folded field element per public input. Production circuit would wire all 32 individual byte cells to match the full `[u8; 32]` layout in `docs/circuit_io.md`.
- **[open]** postfiatd is C++ (rippled fork). No C++ changes needed until ZK-10 (IPC hook).
- **[platform]** Unix socket listener is Linux-only (`cfg(unix)`). Build/type-check on Windows with `cargo check --target x86_64-unknown-linux-gnu -p compliance-sidecar`.

---

## External References

- [postfiatd repo](https://github.com/postfiatorg/postfiatd) — C++ rippled fork, the validator daemon we integrate with
- [Post Fiat whitepaper](https://postfiat.org/whitepaper/) — LLM-based OFAC screening (what ZK layer complements)
- [PSE halo2](https://github.com/privacy-scaling-explorations/halo2) — proof system used
- [Poseidon paper](https://eprint.iacr.org/2019/458) — hash function used inside circuit
- [PLONK paper](https://eprint.iacr.org/2019/953) — arithmetization underpinning halo2
- [Halo2 book](https://zcash.github.io/halo2/) — circuit design reference
