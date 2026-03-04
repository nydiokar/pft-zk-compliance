# Compliance-Aware Transaction Filter: Architecture Specification

**Project:** Post Fiat Validator Stack — ZK Compliance Layer (Design Proposal)
**Date:** 2026-03-04
**Status:** v1.0 — Design Proposal
**Audience:** L1 engineers working on postfiatd (the Post Fiat rippled fork)

> **Scope note:** This is an architecture *proposal* for a ZK compliance layer
> that does not yet exist in postfiatd. Post Fiat currently handles compliance
> via LLM-delegated OFAC screening. This document designs a cryptographic
> complement to that approach — a Halo2 ZK proof layer that would allow
> validators to *prove* compliance without revealing transaction data, as a
> future addition to the postfiatd C++ daemon. The ZK sidecar would integrate
> alongside the existing rippled-based consensus (RPCA) without modifying core
> consensus logic. Implementation would be iterative: this spec defines the
> interface contract so the sidecar can be built and tested independently before
> any postfiatd changes are required.

---

## Table of Contents

1. [Overview](#1-overview)
2. [ZK Circuit: Public & Private Inputs](#2-zk-circuit-public--private-inputs)
3. [Validator ↔ Sidecar Integration](#3-validator--sidecar-integration)
4. [Consensus Fallback & Rejection Logic](#4-consensus-fallback--rejection-logic)
5. [Security Analysis](#5-security-analysis)
6. [Performance Budget](#6-performance-budget)
7. [Deployment Guide](#7-deployment-guide)

---

## 1. Overview

A **Compliance-Aware Transaction Filter** sits between the mempool and consensus
in a Post Fiat validator node. Its job is to algorithmically prove that both the
sender and receiver of a transaction appear in the current compliance address set
— without revealing those addresses, the transaction amount, or the membership
path to the public ledger.

### Why ZK?

A naive compliance filter would require validators to either:
- Broadcast the full compliance list (privacy leak), or
- Trust a centralized oracle (introduces a single point of failure and censorship risk)

A Halo2 ZK proof lets the validator assert "this transaction satisfies compliance
rules" with a compact, verifiable proof. Verifiers check the proof, not the data.

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                   Validator Node                        │
│                                                         │
│  ┌──────────┐    IPC (socket)    ┌────────────────────┐ │
│  │ Validator│◄──────────────────►│ Compliance Sidecar │ │
│  │  Daemon  │                    │  (proof generator) │ │
│  └────┬─────┘                    └────────────────────┘ │
│       │ verified proof / rejection                       │
│  ┌────▼─────┐                                           │
│  │ Consensus│                                           │
│  │  Engine  │                                           │
│  └──────────┘                                           │
└─────────────────────────────────────────────────────────┘
```

**Flow summary:**
1. Transaction arrives in mempool
2. Validator daemon sends tx fields to compliance sidecar via IPC
3. Sidecar builds and proves a `ComplianceCircuit` using Halo2 (PSE fork)
4. Sidecar returns a proof + public inputs to the validator
5. Validator verifies the proof locally; compliant txs proceed to consensus
6. Non-compliant or timed-out txs enter the rejection/quarantine flow

---

## 2. ZK Circuit: Public & Private Inputs

The circuit is implemented using [halo2_proofs (PSE fork)](https://github.com/privacy-scaling-explorations/halo2),
which uses the PLONK arithmetization with custom gates and lookup tables. No
trusted setup is required.

### 2.1 Public Inputs (Instance Columns)

These values are committed on-chain and visible to all verifiers. They anchor
the proof to a specific transaction and a specific compliance snapshot.

| Field | Type | Halo2 cells | Description |
|---|---|---|---|
| `tx_hash` | `[u8; 32]` | 32 × `Instance` | Poseidon hash of `(sender_addr ‖ receiver_addr ‖ amount)` |
| `compliance_merkle_root` | `[u8; 32]` | 32 × `Instance` | Root of the compliance address Merkle tree at `block_height` |
| `block_height` | `u64` | 1 × `Instance` | Block at which the compliance snapshot was taken |

Total public instance cells: **65**

### 2.2 Private Inputs (Witness / Advice Columns)

These values are loaded by the prover and never appear in the proof transcript.
They constitute the zero-knowledge witness.

| Field | Type | Description |
|---|---|---|
| `sender_addr` | `[u8; 20]` | Sender Ethereum-style address |
| `receiver_addr` | `[u8; 20]` | Receiver address |
| `amount` | `u64` | Transaction amount |
| `merkle_path` | `Vec<[u8; 32]>` | Sibling hashes for Merkle membership proof (depth 20 = 640 bytes) |

Merkle tree depth 20 supports up to **~1M compliance addresses**.

### 2.3 Circuit Constraints

The circuit enforces three constraints simultaneously:

**C1 — Sender membership:**
```
MerkleVerify(
    root  = compliance_merkle_root,
    leaf  = Poseidon(sender_addr),
    path  = merkle_path[0..depth]
) = 1
```

**C2 — Receiver membership:**
```
MerkleVerify(
    root  = compliance_merkle_root,
    leaf  = Poseidon(receiver_addr),
    path  = merkle_path[0..depth]
) = 1
```

**C3 — Transaction hash binding:**
```
Poseidon(sender_addr ‖ receiver_addr ‖ amount) = tx_hash
```

C3 is critical: it prevents a prover from substituting compliant addresses for
the actual non-compliant sender/receiver while reusing a valid `tx_hash`.

### 2.4 Gate Architecture

| Gate | Constraint | Max degree |
|---|---|---|
| Poseidon hash gate | C3 hash binding | 3 |
| Merkle path gate | C1 and C2 membership (one level per row) | 4 |
| Range check (lookup) | `amount` fits in u64; path elements are 32-byte field elements | 2 |

Target maximum gate degree: **4** (leaves headroom under the PLONK degree bound
of 8 used by the PSE fork).

### 2.5 Rust Struct Layout

```rust
pub struct ComplianceCircuit {
    // Public — committed on-chain
    pub tx_hash:                [u8; 32],
    pub compliance_merkle_root: [u8; 32],
    pub block_height:           u64,

    // Private — witness only
    pub sender_addr:   Value<[u8; 20]>,
    pub receiver_addr: Value<[u8; 20]>,
    pub amount:        Value<u64>,
    pub merkle_path:   Value<Vec<[u8; 32]>>,
}
```

`Value<T>` is Halo2's wrapper for witness data that is `unknown()` at key
generation time and `known(x)` at proving time.

---

## 3. Validator ↔ Sidecar Integration

### 3.1 Process Architecture

The compliance sidecar runs as a **separate OS process** on the same machine as
the validator daemon. This isolation means:
- A sidecar crash does not crash the validator
- Proof generation (CPU-heavy) does not block the validator event loop
- The sidecar can be restarted independently, upgraded, or swapped

Communication is via a **Unix domain socket** (Linux/macOS) or **named pipe**
(Windows) using a newline-delimited JSON protocol (one JSON object per line).

### 3.2 IPC Message Schema

**Request — Validator → Sidecar**

Sent once per transaction that needs compliance verification.

```json
{
  "version": 1,
  "tx_hash":                "0xabcd...ef",
  "sender_addr":            "0x1234...56",
  "receiver_addr":          "0x7890...ab",
  "amount":                 1000000,
  "compliance_merkle_root": "0xdeadbeef...",
  "block_height":           99999,
  "merkle_path": [
    "0xaabbcc...",
    "0xddeeff..."
  ]
}
```

**Response — Sidecar → Validator**

```json
{
  "version":      1,
  "tx_hash":      "0xabcd...ef",
  "status":       "compliant",
  "proof_bytes":  "<base64-encoded Halo2 proof>",
  "public_inputs": ["0xabcd...ef", "0xdeadbeef...", "0x000186a0"],
  "proof_time_ms": 430
}
```

`status` is one of:
- `"compliant"` — valid proof generated; `proof_bytes` is populated
- `"non_compliant"` — proof generation failed (witness does not satisfy constraints); `proof_bytes` is empty
- `"error"` — internal sidecar error or timeout; `proof_bytes` is empty

### 3.3 Timeout Contract

| Parameter | Default | Description |
|---|---|---|
| `PROOF_TIMEOUT_MS` | 2000 ms | Sidecar must respond within this window |
| `QUARANTINE_BLOCKS` | 3 blocks | Timeout txs are held this long before BFT vote |

If the sidecar does not respond within `PROOF_TIMEOUT_MS`, the validator treats
the transaction as `status: "error"` and begins the quarantine flow (§4).

### 3.4 Proof Verification on the Validator Side

The validator does **not** trust the sidecar's `"compliant"` claim — it
re-verifies the proof locally using `halo2_proofs::plonk::verify_proof` with the
same verifying key and the public inputs from the response. This means a
compromised sidecar cannot forge compliance.

```
validator receives response
  → decode proof_bytes (base64 → Vec<u8>)
  → decode public_inputs (hex → field elements)
  → verify_proof(vk, proof, public_inputs)
  → if Err(_): treat as non_compliant
  → if Ok(()): forward tx to consensus
```

---

## 4. Consensus Fallback & Rejection Logic

### 4.1 Transaction State Machine

```
                    ┌─────────┐
                    │ PENDING │
                    └────┬────┘
                         │ sidecar request sent
                    ┌────▼──────────┐
                    │PROOF_REQUESTED│
                    └──┬────────┬───┘
                       │        │
              compliant│        │non-compliant
                       │        │
               ┌───────▼─┐  ┌───▼──────────┐
               │COMPLIANT│  │NON_COMPLIANT │
               └───┬─────┘  └──────┬───────┘
                   │               │
          ┌────────▼──┐     ┌──────▼───┐
          │ ACCEPTED  │     │ REJECTED │
          │(consensus)│     │(dropped) │
          └───────────┘     └──────────┘

              timeout│
               ┌─────▼──────┐
               │ QUARANTINED│
               └─────┬──────┘
                     │ BFT quorum vote
              ┌──────┴──────┐
              │             │
         accepted        rejected
```

### 4.2 Non-Compliant Path

1. Validator verifies proof → fails (or sidecar returned `non_compliant`)
2. Validator signs a **rejection receipt**: `sign(tx_hash ‖ "REJECT" ‖ block_height)`
3. Receipt is gossiped to peers via the existing P2P layer
4. Once **2f+1** validators have published rejection receipts for the same `tx_hash`,
   the transaction is permanently banned from this epoch's mempool

### 4.3 Timeout / Quarantine Path

If the sidecar times out or returns `"error"`:

1. Transaction enters **QUARANTINE** for `QUARANTINE_BLOCKS` blocks
2. Validator solicits compliance opinions from **f+1** peers:
   - Peers that have a valid proof for this `tx_hash` respond with `"compliant"`
   - Peers that have a rejection receipt respond with `"non_compliant"`
3. After the quarantine window:
   - Quorum `"compliant"` → accept, forward to consensus
   - Quorum `"non_compliant"` → reject, emit rejection receipt
   - No quorum → drop tx silently, log for operator review

### 4.4 Sidecar Crash Recovery

If the sidecar process disappears (no response on socket for >5 seconds):

1. Validator enters **pessimistic mode**: all new transactions are quarantined
   immediately without waiting for proof
2. Validator attempts sidecar restart (via systemd/supervisor or equivalent)
3. Once sidecar reconnects and passes a health-check ping, validator exits
   pessimistic mode and re-processes the quarantine queue

This prevents a crashed sidecar from becoming a DoS vector (an attacker cannot
trigger validator stalls by crashing the sidecar; txs queue, not block).

### 4.5 BFT Safety Property

The fallback logic preserves the validator's Byzantine Fault Tolerance guarantee:

> A transaction is accepted by the network only if at least **f+1** validators
> have either (a) independently verified a valid compliance proof for that
> `tx_hash`, or (b) participated in a quorum vote explicitly accepting it.

This means up to **f** validators can be compromised (sidecar injected with a
false proof) without causing the network to accept a non-compliant transaction.

---

## 5. Security Analysis

### 5.1 Soundness

The circuit is **sound** if the Halo2 proof system is sound under the discrete
log assumption over the Pasta curve (Pallas/Vesta). Concretely:

- An adversary cannot produce a valid proof for a `(sender, receiver)` pair that
  is NOT in the compliance Merkle tree, except with negligible probability
- The Poseidon hash binding (C3) prevents replay attacks where a valid proof is
  reused for a different transaction

### 5.2 Completeness

The circuit is **complete**: any honest prover holding a valid witness
(sender and receiver genuinely in the tree, correct merkle path, correct amount)
can always generate an accepted proof.

### 5.3 Zero-Knowledge Property

The proof reveals nothing about `sender_addr`, `receiver_addr`, `amount`, or
`merkle_path` beyond what is already public (the Merkle root and tx hash). This
holds under the zero-knowledge property of PLONK:

- The proof transcript is computationally indistinguishable from a simulated
  transcript produced without a witness
- The validator and peers see only: `(tx_hash, compliance_merkle_root,
  block_height, proof_bytes)` — the private fields are never transmitted

### 5.4 Threat Model

| Threat | Mitigation |
|---|---|
| Compromised sidecar returning false `"compliant"` | Validator independently re-verifies proof with `verify_proof`; forgery is computationally infeasible |
| Sidecar DoS (crash loop) | Pessimistic mode + quarantine queue; no transaction loss, no validator stall |
| Merkle root manipulation (stale/forged root) | `block_height` is a public input; validators cross-check root against on-chain state at that height |
| Replay of a valid proof for a different tx | C3 (hash binding) ties proof to specific `tx_hash`; reuse fails verification |
| Prover equivocation (two valid proofs for conflicting txs) | Not possible with a deterministic circuit; same inputs always produce the same public outputs |

---

## 6. Performance Budget

### 6.1 Proof Generation Time

Halo2 PLONK proof generation time scales with the number of circuit rows
(roughly `O(n log n)` for the FFT-based prover). For this circuit:

| Parameter | Value |
|---|---|
| Merkle depth | 20 levels |
| Poseidon rounds per hash | ~60 constraints |
| Estimated total rows | ~4,000 |
| Estimated proof time (laptop CPU, 2024) | 400–800 ms |
| Estimated proof time (server, AVX2) | 150–350 ms |

Post Fiat target block time: **~1 second**. With a `PROOF_TIMEOUT_MS` of 2000 ms
and server-class hardware, proof generation fits comfortably within the block
window for the common case. Quarantine handles the tail.

### 6.2 Proof Size

| Metric | Value |
|---|---|
| Halo2 proof size (IPA backend) | ~3–5 KB |
| Public inputs | 65 field elements × 32 bytes = 2 KB |
| Total IPC response payload | ~7–10 KB per transaction |

This is well within typical Unix socket and network MTU budgets.

### 6.3 Verification Time

Halo2 proof verification is fast:

| Metric | Value |
|---|---|
| Estimated verify time (single proof) | 5–20 ms |
| Verifier key size | ~50 KB (stored in memory) |

Validators can verify at least 50 proofs/second per core, well above expected
transaction throughput for a Post Fiat L1.

---

## 7. Deployment Guide

### 7.1 Prerequisites

- Rust toolchain (stable, ≥ 1.75)
- `halo2_proofs` (PSE fork): `privacy-scaling-explorations/halo2`
- Tokio async runtime (for sidecar daemon)
- systemd or equivalent process supervisor

### 7.2 Key Generation (One-Time Setup)

Before deployment, generate the proving and verifying keys for the compliance
circuit at a fixed `k` parameter (circuit size = 2^k rows):

```bash
# Run once per deployment; store outputs in /etc/pf-compliance/
compliance-sidecar keygen --k 12 \
  --pk-out /etc/pf-compliance/compliance.pk \
  --vk-out /etc/pf-compliance/compliance.vk
```

The verifying key (`compliance.vk`) must be distributed to all validators. It is
a ~50 KB file that can be committed to the validator config repo.

### 7.3 Sidecar Configuration

```toml
# /etc/pf-compliance/sidecar.toml
socket_path       = "/run/pf-compliance/sidecar.sock"
proving_key_path  = "/etc/pf-compliance/compliance.pk"
proof_timeout_ms  = 2000
log_level         = "info"
```

### 7.4 Validator Configuration

```toml
# In validator daemon config
[compliance]
enabled               = true
sidecar_socket        = "/run/pf-compliance/sidecar.sock"
verifying_key_path    = "/etc/pf-compliance/compliance.vk"
proof_timeout_ms      = 2000
quarantine_blocks     = 3
pessimistic_on_crash  = true
```

### 7.5 systemd Unit (Sidecar)

```ini
[Unit]
Description=Post Fiat Compliance Sidecar
After=network.target
Requires=pf-validator.service

[Service]
ExecStart=/usr/local/bin/compliance-sidecar --config /etc/pf-compliance/sidecar.toml
Restart=on-failure
RestartSec=2
RuntimeDirectory=pf-compliance
RuntimeDirectoryMode=0750
User=pf-validator

[Install]
WantedBy=multi-user.target
```

### 7.6 Compliance List Updates

The compliance Merkle tree is rebuilt off-chain and the new root is published
on-chain at a known contract address. Validators:

1. Observe the on-chain root update event
2. Fetch the new Merkle tree from a designated data availability layer
3. Restart the sidecar with `--reload-tree` to pick up the new tree
4. Continue using the new `compliance_merkle_root` for all subsequent proofs

No validator downtime is required during tree updates.

### 7.7 Monitoring

Key metrics to expose (Prometheus-compatible):

| Metric | Type | Description |
|---|---|---|
| `compliance_proof_duration_ms` | Histogram | Proof generation time per tx |
| `compliance_status_total{status}` | Counter | Count of compliant/non_compliant/error/timeout |
| `compliance_quarantine_queue_len` | Gauge | Current quarantine backlog |
| `compliance_sidecar_up` | Gauge | 1 if sidecar is reachable, 0 if in pessimistic mode |

---

## References

- [PSE Halo2 repo](https://github.com/privacy-scaling-explorations/halo2)
- [Halo2 book](https://zcash.github.io/halo2/)
- [Poseidon hash paper](https://eprint.iacr.org/2019/458)
- [PLONK paper](https://eprint.iacr.org/2019/953)
- Post Fiat validator spec (internal)
