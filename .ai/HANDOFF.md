# LLM Handoff — Oracle Auth Workstream

This file is for the next model working on `pf-zk-compliance`.

It is not the canonical architecture spec. That remains:

- `docs/SPEC.md`
- `docs/circuit_io.md`
- `docs/adr/0001-schnorr-over-pasta-oracle-authorization.md`
- `.ai/CONTEXT.md`

Use this file for mindset, hygiene, and practical execution standards.

## Core Attitude

Do not treat the task text as canonical.

Treat the task as:

- one proposed slice
- potentially under-scoped
- potentially over-scoped
- sometimes stale relative to the spec and actual code

Your job is not to box-check the task. Your job is to advance the project on the right architectural path.

That means:

- verify the task against `docs/SPEC.md`, `docs/circuit_io.md`, ADR 0001, and `.ai/CONTEXT.md`
- look for where the task is falling short of the real design need
- if the task is directionally right but insufficient, do the minimum extra work needed to keep the project coherent
- if the task would push the repo off-path, do not silently comply; correct the path in code/docs/tests and say why

## What This Repo Is Actually Doing

This repo is not "build random ZK plumbing." The hard architectural path is:

1. harden the Rust witness/request boundary
2. remove split trust between sidecar and proof
3. freeze the oracle-authorization Schnorr contract
4. implement the actual non-native verifier in-circuit
5. only then remove staging leftovers

The common failure mode is endless staging: helpers, vectors, prep patches, bridge code, but no actual verifier.

Resist that.

## Current Reality

As of the latest context:

- ZK-15a done: split-trust Ed25519 side path removed
- ZK-15b done: canonical compressed Pallas pubkeys and canonical Schnorr `(R,s)` boundary checks
- ZK-15c done: fixed valid/tampered equation vectors tied to canonical Rust witness/request encoding
- ZK-15d done: production Rust-side Schnorr transcript and verifier statement frozen
- Highest-priority next step: implement the real non-native Schnorr-over-Pasta verifier equation in the circuit

The codebase now intentionally contains both:

- the old staged scalar relation
- the frozen final Schnorr contract

Do not confuse them.

## What Is Canonical Right Now

For oracle authorization, the frozen Rust-side Schnorr contract is:

- `P = oracle_pubkey` decoded as canonical non-identity compressed Pallas point
- `R = sig[0..32]` decoded as canonical non-identity compressed Pallas point
- `s = sig[32..64]` decoded as canonical Pallas scalar
- `m = little_endian_repr(Poseidon(pubkey))` using the current Rust helper
- `e = HashToScalar(domain || oracle_pubkey || R || m)`
- `domain = "pft-zk-compliance:oracle-schnorr:v1"`
- `HashToScalar(x) = pallas::Scalar::from_uniform_bytes(SHA256(x || 0) || SHA256(x || 1))`
- verifier target: `s·G = R + e·P`

This contract is now frozen in code/docs.

The old staged scalar relation still exists only because the circuit has not yet landed the real non-native gate.

## What To Be Proactive About

If a task is given and it misses one of these, raise it in the implementation itself:

- stale naming that makes staged code sound canonical
- tests that prove a local helper but not the actual normalized request/witness path
- vectors that are "deterministic by search" instead of fixed and auditable
- docs that still describe provisional behavior after the contract has been frozen
- helper reuse drift between `compliance-circuit` and `compliance-sidecar`
- tasks that over-focus on cleanup while the real verifier is still missing

Do not wait to be asked if the issue is directly on the critical path.

## What Not To Do

Do not:

- add more bridge tasks unless they directly unblock the non-native verifier patch
- silently invent protocol choices that are not documented
- treat the current BN254 byte-packing path as elegant or permanent
- refactor widely for style when the real issue is missing arithmetic
- call something "production-complete" before the proof enforces the real Schnorr equation in-circuit

## Secondary Sweep Standard

Before finishing, do a second look for:

- logical mismatches between docs and code
- places where old staged helpers still look canonical
- fixtures that are not actually using the same bytes as the real normalized path
- hidden assumptions in tests
- naming that will confuse the next person
- "technically passes but architecturally misleading" code

This sweep matters.

The right question is not just "does it pass tests?"

The right question is:

"If the next model lands the non-native gate patch on top of this, will this code help it or mislead it?"

## Preferred Execution Style

When taking a new task:

1. read the relevant spec/ADR/context first
2. inspect actual code before assuming task wording is right
3. identify whether the task is:
   - contract-defining
   - implementation
   - cleanup
   - accidental churn
4. if the task is cleanup, keep it narrow
5. if the task is implementation, bias toward end-to-end proof of correctness, not helper-only work
6. verify with targeted tests and include the exact commands/output

## What The User Cares About

The user does not want sycophantic compliance.

They want:

- directness
- technical honesty
- proactive correction when the task is off-path
- high standards
- real progress, not fake progress

If a task is wrong, say so and adjust.
If a task is incomplete but still useful, do the useful part and close the coherence gap.
If a task would create churn, resist it.

## Best Next Task

The right next material task is:

- implement the actual non-native Schnorr-over-Pasta verifier equation in-circuit against the frozen ZK-15d contract and the fixed ZK-15c vectors

The wrong next task is:

- another preparatory bridge
- broad cleanup unrelated to the verifier
- byte/limb migration before the verifier lands

## If You Need A Rule Of Thumb

When in doubt:

- prefer architectural coherence over task literalism
- prefer fixed auditable artifacts over generated magic
- prefer shared helpers over duplicated transcript logic
- prefer one decisive patch over three preparatory ones
