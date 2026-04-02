# Dependency Pins

This workspace pins the Halo2 git dependency used by the sidecar build graph to an exact commit for reproducible operator builds.

## Pinned repositories

| Repository | Crates using it | Commit SHA | Reason |
| --- | --- | --- | --- |
| `https://github.com/privacy-scaling-explorations/halo2` | `crates/compliance-sidecar`, `crates/compliance-circuit` via `halo2_proofs` | `198e9ae30d322cd0ad003b6955f91ec095b1490d` | The sidecar binary depends on `compliance-circuit`, so both manifests must pin the same Halo2 revision to keep the sidecar build graph deterministic and auditable. |

## Safe upgrade path

1. Pick the target Halo2 commit from `privacy-scaling-explorations/halo2`.
2. Update the `rev` for `halo2_proofs` in both `crates/compliance-sidecar/Cargo.toml` and `crates/compliance-circuit/Cargo.toml`.
3. Regenerate the lockfile with `cargo update -p halo2_proofs`.
4. Re-run `cargo test -p compliance-sidecar --locked`.
5. Record the new commit SHA, lockfile diff, and verification command in this file.

## Verification run

- Command: `cargo test -p compliance-sidecar --locked`

## Lockfile note

The local `Cargo.lock` now resolves Halo2 crates to `https://github.com/privacy-scaling-explorations/halo2?rev=198e9ae30d322cd0ad003b6955f91ec095b1490d`, which matches the explicit manifest pins.

This repository currently ignores `Cargo.lock` in `.gitignore`, so there is no tracked lockfile diff to submit unless the project first decides to version the lockfile.
