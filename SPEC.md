# Compliance-Aware Transaction Filter: Architecture Specification

**Project:** Post Fiat Validator Stack — ZK Compliance Layer (Design Proposal)
**Date:** 2026-03-04
**Status:** v1.1 — Design Proposal
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
>
> **v1.1 changes:** Circuit inputs updated to use XRPL ed25519 sender pubkeys
> (not Ethereum-style addresses). Compliance oracle signature added as a private
> witness input — the Post Fiat LLM-based OFAC oracle signs off on pubkeys, and
> the ZK circuit proves possession of a valid oracle signature without revealing
> which entity was screened. Proof propagation flow across the validator network
> added in §3.5.

---

## Table of Contents

1. [Overview](#1-overview)
2. [ZK Circuit: Public & Private Inputs](#2-zk-circuit-public--private-inputs)
3. [Validator ↔ Sidecar Integration](#3-validator--sidecar-integration)
4. [Consensus Fallback & Rejection Logic](#4-consensus-fallback--rejection-logic)
5. [Security Analysis](#5-security-analysis)
6. [Performance Budget](#6-performance-budget)
7. [Deployment Guide](#7-deployment-guide)
8. [References](#references)

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
| `tx_hash` | `[u8; 32]` | 32 × `Instance` | Poseidon hash of `(sender_pubkey ‖ receiver_pubkey ‖ amount)` |
| `compliance_merkle_root` | `[u8; 32]` | 32 × `Instance` | Root of the oracle-signed compliance pubkey Merkle tree at `block_height` |
| `oracle_pubkey_hash` | `[u8; 32]` | 32 × `Instance` | Poseidon hash of the compliance oracle's ed25519 public key |
| `block_height` | `u64` | 1 × `Instance` | Block at which the compliance snapshot was taken |

Total public instance cells: **97**

`oracle_pubkey_hash` anchors the proof to a specific oracle identity without
revealing which keys the oracle signed. Rotating the oracle key produces a
new `oracle_pubkey_hash`, invalidating all old proofs automatically.

### 2.2 Private Inputs (Witness / Advice Columns)

These values are loaded by the prover and never appear in the proof transcript.
They constitute the zero-knowledge witness.

| Field | Type | Description |
|---|---|---|
| `sender_pubkey` | `[u8; 32]` | Sender XRPL ed25519 public key (32 bytes) |
| `receiver_pubkey` | `[u8; 32]` | Receiver XRPL ed25519 public key |
| `amount` | `u64` | Transaction amount in drops |
| `sender_oracle_sig` | `[u8; 64]` | Ed25519 signature from compliance oracle over `Poseidon(sender_pubkey)` |
| `receiver_oracle_sig` | `[u8; 64]` | Ed25519 signature from compliance oracle over `Poseidon(receiver_pubkey)` |
| `merkle_path` | `Vec<[u8; 32]>` | Sibling hashes confirming oracle-signed pubkeys are in the compliance tree (depth 20) |

**Oracle signature model:** The Post Fiat compliance oracle (currently the
LLM-based OFAC screener) signs each pubkey it has cleared: `sig = oracle_sign(Poseidon(pubkey))`.
The ZK circuit proves the prover holds valid oracle signatures for both sender
and receiver — without revealing the pubkeys, the signatures, or the Merkle path
to any verifier.

Merkle tree depth 20 supports up to **~1M cleared pubkeys**.

### 2.3 Circuit Constraints

The circuit enforces four constraints simultaneously:

**C1 — Sender oracle signature valid:**
```
Ed25519Verify(
    pk  = oracle_pubkey,
    msg = Poseidon(sender_pubkey),
    sig = sender_oracle_sig
) = 1
```

**C2 — Receiver oracle signature valid:**
```
Ed25519Verify(
    pk  = oracle_pubkey,
    msg = Poseidon(receiver_pubkey),
    sig = receiver_oracle_sig
) = 1
```

**C3 — Both pubkeys present in compliance Merkle tree:**
```
MerkleVerify(
    root = compliance_merkle_root,
    leaf = Poseidon(sender_pubkey ‖ receiver_pubkey),
    path = merkle_path[0..depth]
) = 1
```

**C4 — Transaction hash binding:**
```
Poseidon(sender_pubkey ‖ receiver_pubkey ‖ amount) = tx_hash
```

C4 prevents reusing a valid proof for a different transaction.
C1+C2 ensure the oracle actually cleared both parties — Merkle membership
alone (C3) is insufficient because the Merkle tree could be stale; the oracle
signature carries a freshness guarantee via oracle key rotation.

### 2.4 Gate Architecture

| Gate | Constraints | Max degree |
|---|---|---|
| Poseidon hash gate | C3 leaf hash, C4 tx binding | 3 |
| Ed25519 verify gate | C1, C2 oracle sig verification | 5 |
| Merkle path gate | C3 membership (one level per row) | 4 |
| Range check (lookup) | `amount` fits in u64 | 2 |

Target maximum gate degree: **5** (within the PLONK degree bound of 8).
Ed25519 in-circuit is the most expensive gate — its degree-5 constraint is
dominated by the scalar multiplication check.

### 2.5 Rust Struct Layout

```rust
pub struct ComplianceCircuit {
    // Public — committed on-chain
    pub tx_hash:                [u8; 32],
    pub compliance_merkle_root: [u8; 32],
    pub oracle_pubkey_hash:     [u8; 32],
    pub block_height:           u64,

    // Private — witness only
    pub sender_pubkey:      Value<[u8; 32]>,
    pub receiver_pubkey:    Value<[u8; 32]>,
    pub amount:             Value<u64>,
    pub sender_oracle_sig:  Value<[u8; 64]>,
    pub receiver_oracle_sig: Value<[u8; 64]>,
    pub merkle_path:        Value<Vec<[u8; 32]>>,
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
  "tx_hash":                  "0xabcd...ef",
  "sender_pubkey":            "0xed1234...56",
  "receiver_pubkey":          "0xed7890...ab",
  "amount":                   1000000,
  "sender_oracle_sig":        "0xsig1...",
  "receiver_oracle_sig":      "0xsig2...",
  "compliance_merkle_root":   "0xdeadbeef...",
  "oracle_pubkey_hash":       "0xoraclehash...",
  "block_height":             99999,
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
  → if Ok(()): attach proof to tx, forward to consensus
```

### 3.5 Proof Propagation Across the Validator Network

Once a validator locally verifies a compliance proof, it does not re-generate
the proof — it propagates it. This is critical for network consensus on
compliance without each validator running a sidecar for the same transaction.

**Propagation flow:**

```
Validator A                    Validator B                    Validator C
    │                               │                               │
    │── generates proof ────────────►                               │
    │   (via own sidecar)           │── re-verifies proof ─────────►│
    │                               │   (local verify_proof)       │── re-verifies
    │                               │                               │   (local)
    │◄─ RPCA consensus vote ────────┤◄──────────────────────────────┤
    │   (proof attached to tx)      │                               │
```

**What propagates:** The `(tx_hash, proof_bytes, public_inputs)` tuple is
attached to the transaction as it moves through the RPCA gossip layer. Any
validator receiving it can verify the proof in ~10ms using only the shared
verifying key — no sidecar required for verification.

**Verifying key distribution:** The `compliance.vk` file (~50 KB) is distributed
out-of-band at validator setup time (committed to the validator config repo).
All validators on the network share the same verifying key for a given circuit
version. Key rotation (e.g. after a circuit upgrade) requires a coordinated
network upgrade, same as any consensus parameter change.

**No double-proving:** Once a proof for `tx_hash` exists on the network, any
validator that receives it just runs `verify_proof` locally. This means proof
generation cost is paid once (by whichever validator first processes the tx),
and verification cost (5–20ms) is paid by every other validator — an asymmetry
that strongly favors network scalability.

**Oracle key consistency:** All validators independently check that
`oracle_pubkey_hash` in the proof's public inputs matches the currently active
oracle pubkey registered on-chain. A proof using an expired oracle key is
rejected even if the Halo2 proof itself is mathematically valid.

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
| Compromised sidecar returning false `"compliant"` | Validator independently re-verifies proof with `verify_proof`; forgery is computationally infeasible under discrete log assumption |
| Sidecar DoS (crash loop) | Pessimistic mode + quarantine queue; no transaction loss, no validator stall |
| Stale/forged Merkle root | `block_height` is a public input; validators cross-check root against on-chain state at that height |
| Replay of a valid proof for a different tx | C4 (hash binding) ties proof to specific `tx_hash`; reuse fails verification |
| Prover equivocation (two valid proofs for conflicting txs) | Not possible with a deterministic circuit; same inputs always produce the same public outputs |
| Forged oracle signature in witness | C1+C2 verify ed25519 sig inside the circuit against `oracle_pubkey_hash` (public); cannot forge without oracle private key |
| Expired oracle key reuse | Validators reject proofs whose `oracle_pubkey_hash` doesn't match the current on-chain oracle key registration |
| Oracle compromise (oracle signs non-compliant pubkeys) | Oracle key rotation invalidates all existing proofs; network upgrade required to accept new oracle key |

---

## 6. Performance Budget

### 6.1 Proof Generation Time

Halo2 PLONK proof generation time scales with the number of circuit rows
(roughly `O(n log n)` for the FFT-based prover). For this circuit:

| Parameter | Value |
|---|---|
| Merkle depth | 20 levels |
| Poseidon rounds per hash | ~60 constraints |
| Ed25519 verify gate (×2, sender + receiver) | ~3,000 constraints each |
| Estimated total rows | ~8,000 |
| Estimated proof time (laptop CPU) | 800–1,500 ms |
| Estimated proof time (server, AVX2) | 300–600 ms |

The ed25519 in-circuit verification (C1+C2) roughly doubles circuit size vs the
v1.0 Merkle-only design. This is the cost of oracle signature verification —
it's justified by the stronger compliance guarantee. If proof time is a concern,
the ed25519 gate can be replaced with a cheaper Schnorr-over-Pasta construction
using native field arithmetic, reducing the gate to degree 3 and cutting proof
time back to v1.0 levels. This is tracked as a future optimisation.

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

- [postfiatd — Post Fiat validator daemon (rippled fork)](https://github.com/postfiatorg/postfiatd)
- [Post Fiat whitepaper](https://postfiat.org/whitepaper/)
- [PSE Halo2 repo](https://github.com/privacy-scaling-explorations/halo2)
- [Halo2 book](https://zcash.github.io/halo2/)
- [Poseidon hash paper](https://eprint.iacr.org/2019/458)
- [PLONK paper](https://eprint.iacr.org/2019/953)
- [Ed25519 spec (RFC 8032)](https://www.rfc-editor.org/rfc/rfc8032)
