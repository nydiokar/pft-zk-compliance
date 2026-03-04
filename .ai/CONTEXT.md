# pf-zk-compliance — Project Context

**Branch:** `master`  **Last Updated:** 2026-03-04  **Status:** Scaffold complete + SPEC.md v1.0 published

---

## Active Work

| Status | Task | Scope | Notes |
|:------:|:-----|:-----:|:------|
| ✅ | **[ZK-0] Repo scaffold** | 🟢 S | Workspace Cargo.toml, compliance-circuit + compliance-sidecar crates, .gitignore, git init. `cargo check` passes. |
| ✅ | **[ZK-1] Circuit I/O definition** | 🟡 M | Public inputs (tx_hash, merkle_root, block_height), private witness (sender, receiver, amount, merkle_path). Documented in `docs/circuit_io.md` and §2 of SPEC.md. |
| ✅ | **[ZK-2] Sidecar IPC schema** | 🟢 S | JSON-over-socket request/response schema. ProofRequest + ProofResponse structs in `crates/compliance-sidecar/src/main.rs`. Documented in §3 of SPEC.md. |
| ✅ | **[ZK-3] Consensus fallback design** | 🟡 M | Timeout → quarantine → BFT quorum vote. Pessimistic mode on sidecar crash. 2f+1 rejection receipt logic. Documented in §4 of SPEC.md. |
| ✅ | **[ZK-4] SPEC.md published** | 🟢 S | Full architecture spec published to GitHub Gist: https://gist.github.com/nydiokar/b5f41e8638382c1eec3a571d891b5d51 |
| 🔲 | **[ZK-5] Circuit `configure` impl** | 🔴 L | Add advice columns, selectors, Poseidon gate, Merkle path gate, range check lookup table. Replace stubs in `circuit.rs`. |
| 🔲 | **[ZK-6] Circuit `synthesize` impl** | 🔴 L | Assign witness values into regions. Wire C1/C2 (Merkle verify) and C3 (hash binding) constraints. |
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
| `crates/compliance-circuit/src/circuit.rs` | ComplianceCircuit struct + Circuit trait skeleton |
| `crates/compliance-sidecar/src/main.rs` | Sidecar daemon loop + IPC types |

---

## Known Issues / Notes

- `[u8; 20]` address type in circuit is a placeholder — XRPL uses base58 classic addresses. Track as ZK-10.
- PSE halo2 v0.4 quirk: `Circuit::synthesize` returns `Result<(), ErrorFront>` not `Error`. Import `halo2_proofs::plonk::ErrorFront`.
- `cargo check` passes with dead-code warnings on stub fields — expected until ZK-5/ZK-6 are implemented.
- postfiatd is C++ (rippled fork). The sidecar is Rust. The IPC socket boundary is the integration point — no C++ changes needed until ZK-9.

---

## External References

- [postfiatd repo](https://github.com/postfiatorg/postfiatd) — C++ rippled fork, the validator daemon we integrate with
- [Post Fiat whitepaper](https://postfiat.org/whitepaper/) — LLM-based OFAC screening (what ZK layer complements)
- [PSE halo2](https://github.com/privacy-scaling-explorations/halo2) — proof system used
- [Poseidon paper](https://eprint.iacr.org/2019/458) — hash function used inside circuit
- [PLONK paper](https://eprint.iacr.org/2019/953) — arithmetization underpinning halo2
- [Halo2 book](https://zcash.github.io/halo2/) — circuit design reference
