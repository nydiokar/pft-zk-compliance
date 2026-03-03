# SPEC.md — Compliance-Aware Transaction Filter: Architecture Specification

**Status:** Draft (evolving)
**Project:** `pf-zk-compliance`
**Target:** Post Fiat validator stack, Halo2 ZK compliance layer

---

## Overview

A compliance-aware transaction filter sits between the mempool and consensus in
a Post Fiat validator node. For each incoming transaction, it:

1. Dispatches the transaction to a compliance sidecar daemon
2. The sidecar generates a Halo2 ZK proof that (sender, receiver) ∈ compliance_list
3. The proof is verified by the validator; compliant txs are forwarded to consensus
4. Non-compliant or proof-timeout txs enter the consensus fallback flow

The ZK approach ensures that compliance checks are verifiable without revealing
private transaction data to the consensus layer.

---

## §1 — Circuit I/O (Step 1)

See also: `docs/circuit_io.md` for the full input table.

### Public Inputs (on-chain verifiable)
| Field | Type | Description |
|---|---|---|
| `tx_hash` | `[u8; 32]` | Pedersen hash of the transaction (commitment) |
| `compliance_merkle_root` | `[u8; 32]` | Root of the compliance address Merkle tree |
| `block_height` | `u64` | Block at which the compliance set snapshot was taken |

### Private Inputs (witness — never revealed)
| Field | Type | Description |
|---|---|---|
| `sender_addr` | `[u8; 20]` | Sender Ethereum-style address |
| `receiver_addr` | `[u8; 20]` | Receiver address |
| `amount` | `u64` | Transaction amount |
| `merkle_path` | `Vec<[u8; 32]>` | Sibling hashes proving membership in compliance tree |

### Core Constraint
The circuit proves:
```
MerkleVerify(compliance_merkle_root, sender_addr, merkle_path) = true
∧ MerkleVerify(compliance_merkle_root, receiver_addr, merkle_path) = true
∧ Pedersen(sender_addr ‖ receiver_addr ‖ amount) = tx_hash
```

### Circuit Design Notes
- Gate structure: custom gate for Merkle path verification + Poseidon hash gate
- Lookup tables: range check on `amount` field
- Degree bound: target ≤ 8 (PLONK standard for PSE fork)

---

## §2 — Integration Points (Step 2)

### Sidecar Architecture
The compliance sidecar runs as a separate OS process alongside the validator
daemon. Communication is via Unix domain socket (or named pipe on Windows) using
a JSON-over-newline protocol.

### IPC Message Schema

**Request (validator → sidecar):**
```json
{
  "version": 1,
  "tx_hash": "<hex>",
  "sender_addr": "<hex>",
  "receiver_addr": "<hex>",
  "amount": 12345,
  "compliance_merkle_root": "<hex>",
  "block_height": 99999,
  "merkle_path": ["<hex>", "..."]
}
```

**Response (sidecar → validator):**
```json
{
  "version": 1,
  "tx_hash": "<hex>",
  "status": "compliant" | "non_compliant" | "error",
  "proof_bytes": "<base64>",
  "public_inputs": ["<hex>", "..."],
  "proof_time_ms": 450
}
```

### Timeout Contract
- Sidecar must respond within `PROOF_TIMEOUT_MS` (default: 2000ms)
- Validator treats timeout as `status: "error"` → triggers consensus fallback
- Sidecar logs timeout events for operator alerting

---

## §3 — Consensus Fallback (Step 3)

Derived from Paxos/BFT quorum logic studied in shards repo
(`PAXOS_WITNESS_PROTOCOL.md`, `QUORUM_CONSENSUS.md`).

### Transaction States
```
PENDING → PROOF_REQUESTED → COMPLIANT → ACCEPTED (to consensus)
                          → NON_COMPLIANT → REJECTED
                          → TIMEOUT → QUARANTINED → (BFT vote)
```

### Quarantine/Rejection Logic
1. **Non-compliant proof**: Immediate reject. Validator signs a rejection receipt
   and gossips it to peers. 2f+1 rejection receipts = tx permanently banned from
   this epoch's mempool.

2. **Timeout (proof not returned in time)**:
   - Transaction enters QUARANTINE for `QUARANTINE_BLOCKS` (default: 3 blocks)
   - During quarantine, validator solicits compliance opinions from `f+1` peers
   - If quorum agrees on non-compliance: reject
   - If quorum agrees on compliance (e.g., sidecar was temporarily down): accept
   - No quorum after quarantine window: drop tx, log for operator review

3. **Sidecar crash/restart**: Validator falls back to "pessimistic mode" —
   all transactions are quarantined until sidecar comes back online. This prevents
   a crashed sidecar from becoming a DoS vector.

### BFT Safety Property
The fallback preserves the validator's BFT safety guarantee: a transaction is
only accepted if at least `f+1` validators in the quorum have either:
- Verified a valid compliance proof, OR
- Participated in the quarantine quorum vote accepting the transaction

---

## §4 — Publishable Specification (Step 4)

*This section will be filled in once Steps 1–3 are implemented and tested.*

Planned content:
- Full circuit constraint equations (LaTeX)
- Formal IPC protocol specification
- Security analysis: soundness, completeness, zero-knowledge property
- Performance benchmarks: proof generation time vs. block time budget
- Deployment guide for Post Fiat validator operators

---

## §5 — GitHub & Distribution (Step 5)

*User-confirmed push. Not automated.*

- Repo: `github.com/<org>/pf-zk-compliance`
- License: TBD (Apache-2.0 or MIT)
- Gist: circuit_io.md will be published as a public Gist for community review
