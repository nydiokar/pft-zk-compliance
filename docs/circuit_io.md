# Circuit I/O — ComplianceCircuit Input Table

This document specifies the full public/private input split for `ComplianceCircuit`.

## Public Inputs

These are committed on-chain and visible to verifiers.

| Field | Rust type | Halo2 cell type | Description |
|---|---|---|---|
| `tx_hash` | `[u8; 32]` | `[Column<Instance>; 32]` | Pedersen/Poseidon hash of (sender ‖ receiver ‖ amount) |
| `compliance_merkle_root` | `[u8; 32]` | `[Column<Instance>; 32]` | Root of the compliance address set Merkle tree |
| `block_height` | `u64` | `Column<Instance>` | Block height of the compliance snapshot |

Total public instance cells: 65

## Private Inputs (Witness)

These are loaded by the prover and never revealed to the verifier.

| Field | Rust type | Halo2 region | Description |
|---|---|---|---|
| `sender_addr` | `[u8; 20]` | `advice` | Sender's address (20-byte Ethereum format) |
| `receiver_addr` | `[u8; 20]` | `advice` | Receiver's address |
| `amount` | `u64` | `advice` | Transaction amount |
| `merkle_path` | `Vec<[u8; 32]>` | `advice` | Sibling hashes for Merkle membership proof |

Merkle tree depth: configurable, default 20 (supports ~1M addresses).
Path length: 20 × 32 bytes = 640 bytes of witness data.

## Constraints

### C1: Sender membership
```
MerkleVerify(
    root = compliance_merkle_root,
    leaf = Poseidon(sender_addr),
    path = merkle_path[..depth/2]
) = 1
```

### C2: Receiver membership
```
MerkleVerify(
    root = compliance_merkle_root,
    leaf = Poseidon(receiver_addr),
    path = merkle_path[depth/2..]
) = 1
```

### C3: Transaction hash binding
```
Poseidon(sender_addr ‖ receiver_addr ‖ amount) = tx_hash
```

C3 prevents the prover from substituting compliant addresses for non-compliant ones
while reusing a valid tx_hash.

## Gate Design

| Gate | Purpose | Degree |
|---|---|---|
| Poseidon hash gate | Hash sender, receiver, tx commitment | 3 |
| Merkle path gate | Verify Merkle path at each level | 4 |
| Range check (lookup) | Constrain `amount` to u64 range | 2 |

Target maximum gate degree: 4 (leaves headroom under PLONK degree bound of 8).

## Soundness Note

The circuit is sound if the Merkle tree collision resistance holds under the
Poseidon hash assumption. The zero-knowledge property holds because the witness
(sender, receiver, amount, path) is never revealed — only the Halo2 proof
transcript is transmitted.

## References
- PSE Halo2 book: https://zcash.github.io/halo2/
- Poseidon paper: https://eprint.iacr.org/2019/458
- Concept lineage: shards/MONSTER_HARMONIC_ZKSNARK.md (public/private input discipline)
