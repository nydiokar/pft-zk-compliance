# Circuit I/O — ComplianceCircuit Input Table

This document specifies the current target public/private input split for
`ComplianceCircuit`.

## Public Inputs

These are committed on-chain and visible to verifiers.

| Field | Rust type | Halo2 cell type | Description |
|---|---|---|---|
| `tx_hash` | `[u8; 32]` | `[Column<Instance>; 32]` | Poseidon hash of (sender_pubkey ‖ receiver_pubkey ‖ amount) |
| `compliance_merkle_root` | `[u8; 32]` | `[Column<Instance>; 32]` | Root of the compliance address set Merkle tree |
| `oracle_pubkey_hash` | `[u8; 32]` | `[Column<Instance>; 32]` | Poseidon hash of the active compliance oracle public key |
| `block_height` | `u64` | `Column<Instance>` | Block height of the compliance snapshot |

Total public instance cells: 97

## Private Inputs (Witness)

These are loaded by the prover and never revealed to the verifier.

| Field | Rust type | Halo2 region | Description |
|---|---|---|---|
| `sender_pubkey` | `[u8; 32]` | `advice` | Sender XRPL ed25519 public key |
| `receiver_pubkey` | `[u8; 32]` | `advice` | Receiver XRPL ed25519 public key |
| `oracle_pubkey` | `[u8; 32]` | `advice` | Compliance oracle public key for the circuit-friendly authorization scheme |
| `amount` | `u64` | `advice` | Transaction amount |
| `sender_oracle_sig` | `[u8; 64]` | `advice` | Oracle authorization signature over `Poseidon(sender_pubkey)` |
| `receiver_oracle_sig` | `[u8; 64]` | `advice` | Oracle authorization signature over `Poseidon(receiver_pubkey)` |
| `sender_merkle_siblings` | `Vec<[u8; 32]>` | `advice` | Sender Merkle sibling nodes |
| `sender_merkle_directions` | `Vec<bool>` | `advice` | Sender left/right direction bits |
| `receiver_merkle_siblings` | `Vec<[u8; 32]>` | `advice` | Receiver Merkle sibling nodes |
| `receiver_merkle_directions` | `Vec<bool>` | `advice` | Receiver left/right direction bits |

Merkle tree depth: configurable, default 20 (supports ~1M addresses).
Each path carries 20 sibling nodes plus 20 direction bits.

## Approved Direction

The approved production direction for this repo is:

- two independent pubkey membership proofs, one for sender and one for receiver
- one shared public `compliance_merkle_root`
- binary Poseidon parent hashing at every Merkle level
- fixed-depth witnesses that include both siblings and direction bits

The pre-ZK-13 Rust circuit may still temporarily expose a flattened
concatenated-sibling `merkle_path` witness. Treat that as an implementation
staging artifact, not the long-term circuit I/O model.

## Constraints

### C1: Sender oracle authorization
```
SchnorrVerify(
    pk  = oracle_pubkey,
    msg = Poseidon(sender_pubkey),
    sig = sender_oracle_sig
) = 1
```

Witness interpretation for the frozen Rust-side contract:

- `P = DecodePallasPoint(oracle_pubkey)`
- `R = DecodePallasPoint(sender_oracle_sig[0..32])`
- `s = DecodePallasScalar(sender_oracle_sig[32..64])`
- `m = little_endian_repr(Poseidon(sender_pubkey))`
- `e = HashToScalar("pft-zk-compliance:oracle-schnorr:v1" || oracle_pubkey || sender_oracle_sig[0..32] || m)`
- enforce `s·G = R + e·P`

### C2: Receiver oracle authorization
```
SchnorrVerify(
    pk  = oracle_pubkey,
    msg = Poseidon(receiver_pubkey),
    sig = receiver_oracle_sig
) = 1
```

Receiver authorization uses the same transcript and verifier statement with
`receiver_pubkey` and `receiver_oracle_sig`.

### C3: Sender membership
```
MerkleVerify(
    root = compliance_merkle_root,
    leaf = Poseidon(sender_pubkey),
    siblings = sender_merkle_siblings,
    directions = sender_merkle_directions
) = 1
```

### C4: Receiver membership
```
MerkleVerify(
    root = compliance_merkle_root,
    leaf = Poseidon(receiver_pubkey),
    siblings = receiver_merkle_siblings,
    directions = receiver_merkle_directions
) = 1
```

### C5: Transaction hash binding
```
Poseidon(sender_pubkey ‖ receiver_pubkey ‖ amount) = tx_hash
```

C5 prevents the prover from substituting compliant pubkeys for non-compliant ones
while reusing a valid tx_hash.

## Gate Design

| Gate | Purpose | Degree |
|---|---|---|
| Poseidon hash gate | Hash sender/receiver leaves, Merkle parents, tx commitment | 3 |
| Oracle auth gate | Verify Schnorr-style oracle authorization for sender and receiver | 5 |
| Merkle path gate | Verify binary Merkle path at each level | 4 |
| Range check (lookup) | Constrain `amount` to u64 range | 2 |

Target maximum gate degree: 5 (within the PLONK degree bound of 8).

## ADR

The oracle authorization scheme is no longer specified as Ed25519. The project
controls the compliance oracle, so the canonical production direction is now a
circuit-friendly Schnorr-style signature scheme over a proving-system-friendly
curve. XRPL transaction parties remain Ed25519 pubkeys; only the oracle's own
authorization primitive changes.

Current implementation status:

- The Rust sidecar/circuit boundary now uses canonical compressed Pallas oracle
  pubkeys and canonical Schnorr `(R,s)` bytes.
- Boundary validation rejects malformed encodings, the identity point, and
  oracle values that cannot be represented safely by the current staged BN254
  witness path.
- The production Rust-side Schnorr transcript is now frozen so later non-native
  gates have a fixed contract to target.
- The non-native verifier witness ABI is now fixed as decoded affine Pallas
  coordinates and scalars split into four 64-bit little-endian limbs:
  `P.x`, `P.y`, `R.x`, `R.y`, `s`, and `e`. Limb 0 carries bits 0..63.
  Reconstruction rejects any limb set with the wrong length, any limb wider
  than 64 bits, any non-canonical Pallas base/scalar value, and any affine
  coordinate pair that is not on the Pallas curve.
- The circuit has not yet reached the final verifier shape. It still uses a
  temporary staged scalar relation internally, and the full non-native
  Schnorr-over-Pasta equation remains future work.

## Soundness Note

The circuit is sound if the Merkle tree collision resistance holds under the
Poseidon hash assumption. The zero-knowledge property holds because the witness
(sender/receiver pubkeys, signatures, amount, siblings, direction bits) is
never revealed — only the Halo2 proof
transcript is transmitted.

## References
- PSE Halo2 book: https://zcash.github.io/halo2/
- Poseidon paper: https://eprint.iacr.org/2019/458
- Concept lineage: shards/MONSTER_HARMONIC_ZKSNARK.md (public/private input discipline)
