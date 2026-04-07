# ADR 0001: Schnorr-Over-Pasta Oracle Authorization

## Status

Accepted

## Context

The sidecar previously carried oracle-authorization fields through the Rust request and witness boundary, but actual authorization checking still happened in a sidecar-only `ed25519-dalek` preflight path. That split the trust model in two places:

- the circuit proved Merkle membership, transaction binding, and oracle-key hash binding
- the sidecar separately enforced oracle authorization outside the proof

That was acceptable as a staging step, but it is the wrong steady state. The proof system should enforce the authorization statement itself so validators only need to trust the proof plus the public `oracle_pubkey_hash`.

## Decision

Use a staged Schnorr-style authorization migration carried in the existing
Rust-side witness fields:

- `oracle_pubkey`: 32-byte oracle authorization key material
- `sender_oracle_sig`: 64-byte `nonce || response`
- `receiver_oracle_sig`: 64-byte `nonce || response`

For each authorized party, the current staged circuit still uses this temporary
relation:

1. hashes the private oracle key material to the existing public `oracle_pubkey_hash`
2. hashes the transaction party pubkey with the existing Poseidon leaf function
3. derives a challenge as `Poseidon(oracle_pubkey_hash, authorized_pubkey_hash, nonce)`
4. enforces the Schnorr-style response relation `response = nonce + challenge * oracle_key`

This keeps the migration Rust-only:

- no validator or wire-format expansion is required
- public inputs stay unchanged
- the sidecar and circuit crates can transition together without reopening the blocked validator/oracle-registration redesign

The migration is intentionally split into phases:

1. remove the sidecar-only Ed25519 path
2. harden the Rust witness boundary with canonical compressed Pallas pubkeys and
   canonical Schnorr `(R,s)` parsing
3. replace the temporary scalar relation with the full non-native
   Schnorr-over-Pasta verifier equation inside the circuit

Only the first two phases are complete today.

The production Schnorr contract for the later non-native verifier patch is now
frozen at the Rust boundary:

- witness public key `P`: canonical compressed Pallas `oracle_pubkey` bytes
- witness nonce point `R`: canonical compressed Pallas `R` bytes from the
  first 32 bytes of `sender_oracle_sig` / `receiver_oracle_sig`
- witness response scalar `s`: canonical Pallas scalar bytes from the final
  32 bytes of the signature
- message bytes `m`: the little-endian 32-byte `Bn254Fr` representation of
  `Poseidon(pubkey)` using the current canonical Rust encoding helper
- challenge scalar `e`: `HashToScalar(domain || P || R || m)` where
  `domain = "pft-zk-compliance:oracle-schnorr:v1"` and `HashToScalar` means
  `pallas::Scalar::from_uniform_bytes(SHA256(x || 0) || SHA256(x || 1))`
- verifier equation: `s·G = R + e·P`

`oracle_pubkey_hash` remains a separate circuit binding to the active oracle
key. It is not part of the final Schnorr transcript.

## Replaces

- Sidecar-only Ed25519 verification via `ed25519-dalek`
- The previous prototype state where oracle signatures were present in the witness but unconstrained in-circuit

## Consequences

- Oracle authorization is now enforced by the proof, not by sidecar-only preflight code.
- The sidecar no longer needs the Ed25519 dependency path.
- The migration remains intentionally scoped to the Rust circuit/sidecar
  boundary; wider protocol work such as validator-managed oracle key
  registration or a different on-chain encoding can happen later without
  reintroducing split authorization logic.
- The current implementation is still a staged verifier path, not the final
  non-native Schnorr-over-Pasta arithmetic design.
