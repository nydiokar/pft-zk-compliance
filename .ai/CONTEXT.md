# pf-zk-compliance — Project Context

**Branch:** `master`  **Last Updated:** 2026-03-04  **Status:** Circuit prototype implemented + MockProver passing (4/4 tests)

---

## Active Work

| Status | Task | Scope | Notes |
|:------:|:-----|:-----:|:------|
| ✅ | **[ZK-0] Repo scaffold** | 🟢 S | Workspace Cargo.toml, compliance-circuit + compliance-sidecar crates, .gitignore, git init. `cargo check` passes. |
| ✅ | **[ZK-1] Circuit I/O definition** | 🟡 M | Public inputs (tx_hash, merkle_root, block_height), private witness (sender, receiver, amount, merkle_path). Documented in `docs/circuit_io.md` and §2 of SPEC.md. |
| ✅ | **[ZK-2] Sidecar IPC schema** | 🟢 S | JSON-over-socket request/response schema. ProofRequest + ProofResponse structs in `crates/compliance-sidecar/src/main.rs`. Documented in §3 of SPEC.md. |
| ✅ | **[ZK-3] Consensus fallback design** | 🟡 M | Timeout → quarantine → BFT quorum vote. Pessimistic mode on sidecar crash. 2f+1 rejection receipt logic. Documented in §4 of SPEC.md. |
| ✅ | **[ZK-4] SPEC.md published** | 🟢 S | Full architecture spec published to GitHub Gist: https://gist.github.com/nydiokar/b5f41e8638382c1eec3a571d891b5d51 |
| ✅ | **[ZK-5] Circuit `configure` impl** | 🔴 L | Advice columns (a/b/c), fixed constants, instance, selectors s_hash/s_merkle/s_range, three gates. Prototype substitutions annotated inline with PROTOTYPE/PRODUCTION comments. |
| ✅ | **[ZK-6] Circuit `synthesize` impl** | 🔴 L | 5 regions: load_witness, range_check, hash_binding (C3), sender_merkle (C1), receiver_merkle (C2). All public inputs wired to instance column via constrain_instance. 4 MockProver tests pass (valid + 3 rejection cases). |
| 🔲 | **[ZK-7] Sidecar socket listener** | 🟡 M | Replace daemon loop stub with real Unix socket / named pipe listener. Accept + dispatch ProofRequests. |
| 🔲 | **[ZK-8] Key generation CLI** | 🟡 M | `compliance-sidecar keygen --k 12` command. Output .pk / .vk files. |
| 🔲 | **[ZK-9] postfiatd IPC hook** | 🔴 L | C++ side of the socket interface in postfiatd. Calls sidecar before forwarding tx to RPCA consensus. |
| 🔲 | **[ZK-10] XRPL address encoding** | 🟢 S | Swap `[u8; 20]` placeholder for XRPL base58 address format in circuit struct and IPC schema. |

---

## Architecture Decisions

| ID | Decision | Rationale | Alternatives rejected |
|:--:|:---------|:----------|:----------------------|
| AD-1 | PSE halo2 fork over zcash/halo2 | Actively maintained, production ZK teams use it, v0.4 has cleaner frontend/backend split | zcash fork: less active; arkworks: different arithmetization |
| AD-2 | Poseidon hash over SHA256 inside circuit | ~60 constraints vs ~27,000 for SHA256 in PLONK. Enables sub-second proof times on server hardware | SHA256: too expensive; Pedersen: less collision resistant |
| AD-3 | Sidecar as separate process | Crash isolation — sidecar failure doesn't crash validator. CPU-heavy proof gen doesn't block RPCA event loop | In-process: simpler but couples lifecycles |
| AD-4 | JSON-over-socket IPC | Simple, debuggable, language-agnostic (C++ postfiatd ↔ Rust sidecar) | gRPC: overkill for single-machine IPC; raw binary: harder to debug |
| AD-5 | ZK as complement to LLM OFAC screening | Post Fiat already has LLM-delegated compliance. ZK adds cryptographic provability on top, not a replacement | Replace LLM screening: would remove existing functionality |
| AD-6 | Gate degree target ≤ 4 | Leaves headroom under PLONK degree bound of 8. Poseidon gate is degree 3, Merkle gate degree 4 | Higher degree: risks constraint system errors; lower: unnecessarily restrictive |

---

## Concept Lineage (from shards repo)

| Concept | Source file | Applied as |
|:--------|:------------|:-----------|
| Public/private input discipline | `MONSTER_HARMONIC_ZKSNARK.md` | Instance vs Advice column split in ComplianceCircuit |
| Consensus rejection + quorum fallback | `PAXOS_WITNESS_PROTOCOL.md`, `QUORUM_CONSENSUS.md` | §4 quarantine + 2f+1 BFT vote logic |
| Sidecar plugin submission pattern | `MONSTER_HARMONIC_ZKSNARK.md` (zkOS plugin) | IPC schema shape + sidecar process model |

---

## Key Files

| File | Purpose |
|:-----|:--------|
| `SPEC.md` | Publishable architecture spec (v1.0 final) |
| `docs/circuit_io.md` | Detailed circuit input table + constraint equations |
| `crates/compliance-circuit/src/circuit.rs` | Full ComplianceCircuit: configure, synthesize, 4 MockProver tests |
| `crates/compliance-sidecar/src/main.rs` | Sidecar daemon loop + IPC types (stub, awaits ZK-7) |

---

## Known Issues / Notes

- **[ZK-10 open]** `[u8; 20]` address type in `Witness` struct is still an Ethereum-style placeholder. XRPL uses base58 classic addresses (different encoding). Needs a dedicated encoding layer before production.
- **[open]** PSE halo2 git dep is unpinned (`git = "..."` without a rev). Must pin to a specific commit before any production deployment to prevent supply-chain drift.
- **[open, by design]** Prototype gates use linear arithmetic (`a + b = c`) in place of Poseidon. Circuit enforces the correct constraint topology but is not cryptographically collision-resistant. Every substitution is annotated inline in `circuit.rs` with `PROTOTYPE:` / `PRODUCTION:` comments.
- **[open, by design]** Instance column wires only one folded field element per public input (`tx_hash`, `merkle_root`). Production circuit would wire all 32 individual byte cells to match the full `[u8; 32]` layout in `docs/circuit_io.md`.
- **[open]** postfiatd is C++ (rippled fork). No C++ changes needed until ZK-9 (IPC hook).

---

## External References

- [postfiatd repo](https://github.com/postfiatorg/postfiatd) — C++ rippled fork, the validator daemon we integrate with
- [Post Fiat whitepaper](https://postfiat.org/whitepaper/) — LLM-based OFAC screening (what ZK layer complements)
- [PSE halo2](https://github.com/privacy-scaling-explorations/halo2) — proof system used
- [Poseidon paper](https://eprint.iacr.org/2019/458) — hash function used inside circuit
- [PLONK paper](https://eprint.iacr.org/2019/953) — arithmetization underpinning halo2
- [Halo2 book](https://zcash.github.io/halo2/) — circuit design reference
