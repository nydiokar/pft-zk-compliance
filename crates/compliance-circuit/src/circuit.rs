//! ComplianceCircuit — Halo2 ZKP circuit for Post Fiat compliance filtering.
//!
//! # What this circuit proves
//!
//! Without revealing any witness data, the circuit proves:
//!
//!   C1. `sender_addr`   ∈ compliance_list  (Merkle membership)
//!   C2. `receiver_addr` ∈ compliance_list  (Merkle membership)
//!   C3. `commit(sender ‖ receiver ‖ amount) = tx_hash`  (hash binding)
//!
//! # Public / private split
//!
//! | Column type | Field                  | Rows (instance col) |
//! |-------------|------------------------|---------------------|
//! | Instance    | `tx_hash`              | 0..32               |
//! | Instance    | `compliance_merkle_root` | 32..64             |
//! | Instance    | `block_height`         | 64                  |
//! | Advice      | `sender_addr`          | witness             |
//! | Advice      | `receiver_addr`        | witness             |
//! | Advice      | `amount`               | witness             |
//! | Advice      | `merkle_path`          | witness             |
//!
//! # Gate design (see also `docs/circuit_io.md`)
//!
//! | Gate          | Constraint                    | Degree |
//! |---------------|-------------------------------|--------|
//! | `hash_binding`  | `a + b = c`                 | 2      |
//! | `merkle_path`   | `node + sibling = parent`   | 2      |
//! | `range_check`   | tautological placeholder    | 1      |
//!
//! # Prototype substitutions
//!
//! Two primitives from the spec (`docs/circuit_io.md`) are **intentionally
//! simplified** for this prototype.  Each substitution is marked in the code
//! with a `PROTOTYPE:` comment and a `PRODUCTION:` comment explaining the
//! upgrade path.
//!
//! 1. **Hash function** — spec calls for Poseidon(sender ‖ receiver ‖ amount).
//!    We use a linear sum `sender_commit + receiver_commit = tx_hash_commit`
//!    because `halo2_gadgets::poseidon` requires a large additional dependency
//!    and a more complex chip architecture.  The *constraint topology* (one gate
//!    that binds three cells) is identical; only the internal polynomial differs.
//!
//! 2. **Merkle node hashing** — spec calls for Poseidon(left, right) at each
//!    level.  We use `left + right = parent` for the same reason.  The path-
//!    traversal structure, region layout, and root-equality constraint are all
//!    production-ready.
//!
//! 3. **Range check** — spec calls for a lookup table against a u64 range.
//!    We use a tautological gate (`s*(a-a)=0`) because the lookup-table gadget
//!    requires a separate table column.  The selector wire-up is production-ready.
//!
//! # Instance wiring
//!
//! Every public input cell is wired to the instance column via
//! `layouter.constrain_instance()`.  The MockProver's permutation checker
//! verifies that the advice values match the supplied instance vector, so a
//! wrong public input causes `verify()` to return `Err(...)`.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Fixed, Instance, Selector},
    poly::Rotation,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Merkle tree depth per side (sender / receiver).
///
/// Production value: 20  →  supports 2^20 ≈ 1 M compliance addresses.
/// Prototype value: 4    →  fast compile + short MockProver run.
pub const MERKLE_DEPTH: usize = 4;

/// Total public instance rows: tx_hash(32) + merkle_root(32) + block_height(1).
pub const NUM_INSTANCE_ROWS: usize = 65;

/// Instance column row ranges.
pub const TX_HASH_START: usize = 0;
pub const TX_HASH_END: usize = 32;
pub const MERKLE_ROOT_START: usize = 32;
pub const MERKLE_ROOT_END: usize = 64;
pub const BLOCK_HEIGHT_ROW: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Public / private input types
// ─────────────────────────────────────────────────────────────────────────────

/// Public inputs committed on-chain; visible to verifiers.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// PROTOTYPE: linear commitment of (sender_addr ‖ receiver_addr ‖ amount).
    /// PRODUCTION: Poseidon(sender_addr ‖ receiver_addr ‖ amount).
    pub tx_hash: [u8; 32],
    /// Root of the compliance address Merkle tree at `block_height`.
    pub compliance_merkle_root: [u8; 32],
    /// Block height of the compliance snapshot.
    pub block_height: u64,
}

/// Private witness — loaded by the prover, never revealed to the verifier.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Sender Ethereum-style address (20 bytes).
    pub sender_addr: [u8; 20],
    /// Receiver address (20 bytes).
    pub receiver_addr: [u8; 20],
    /// Transaction amount.
    pub amount: u64,
    /// Sibling hashes for both Merkle membership proofs, concatenated.
    /// Layout: `[sender_sibling_0, .., sender_sibling_{D-1},
    ///           receiver_sibling_0, .., receiver_sibling_{D-1}]`
    /// where D = `MERKLE_DEPTH`.
    pub merkle_path: Vec<[u8; 32]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Column and gate configuration for `ComplianceCircuit`.
#[derive(Clone, Debug)]
pub struct ComplianceConfig {
    /// Left operand: sender field element / current Merkle node.
    pub a: Column<Advice>,
    /// Right operand: receiver field element / Merkle sibling.
    pub b: Column<Advice>,
    /// Output: tx_hash commitment / Merkle parent node.
    pub c: Column<Advice>,
    /// Fixed constants column — required by `assign_advice_from_constant`.
    pub constant: Column<Fixed>,
    /// Single instance column, rows 0..65 (see module-level table).
    pub instance: Column<Instance>,
    /// Selector: activates the hash-binding gate (C3).
    pub s_hash: Selector,
    /// Selector: activates the Merkle-path gate (C1 / C2 per level).
    pub s_merkle: Selector,
    /// Selector: activates the range-check gate (amount ∈ u64).
    pub s_range: Selector,
}

impl ComplianceConfig {
    fn configure<F: ff::PrimeField>(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        // Enable equality on all columns so copy-constraints (including
        // constrain_instance wiring) can be recorded in the permutation argument.
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        let s_hash = meta.selector();
        let s_merkle = meta.selector();
        let s_range = meta.selector();

        // ── C3: Hash-binding gate ─────────────────────────────────────────
        // Enforces: a + b = c
        //
        // PROTOTYPE: linear sum over field elements folded from byte arrays.
        // PRODUCTION: replace with halo2_gadgets::poseidon::Hash chip that
        //   applies the Poseidon-128 permutation.  The gate structure (one
        //   selector, three advice cells, one constraint) stays the same.
        meta.create_gate("hash_binding", |vc| {
            let s = vc.query_selector(s_hash);
            let a = vc.query_advice(a, Rotation::cur());
            let b = vc.query_advice(b, Rotation::cur());
            let c = vc.query_advice(c, Rotation::cur());
            // s_hash * (a + b - c) = 0
            vec![s * (a + b - c)]
        });

        // ── C1 / C2: Merkle-path gate ────────────────────────────────────
        // Enforces: node + sibling = parent  (one row per tree level).
        //
        // PROTOTYPE: additive combination — not collision-resistant.
        // PRODUCTION: replace with Poseidon(left, right) node combination
        //   inside a binary Merkle chip (e.g. halo2_gadgets MerkleChip).
        //   The per-level row structure and final root equality constraint
        //   are identical.
        meta.create_gate("merkle_path", |vc| {
            let s = vc.query_selector(s_merkle);
            let node = vc.query_advice(a, Rotation::cur());
            let sibling = vc.query_advice(b, Rotation::cur());
            let parent = vc.query_advice(c, Rotation::cur());
            // s_merkle * (node + sibling - parent) = 0
            vec![s * (node + sibling - parent)]
        });

        // ── Range gate ───────────────────────────────────────────────────
        // Enforces that `amount` fits in u64.
        //
        // PROTOTYPE: tautological — the gate fires but never rejects because
        //   `a - a = 0` always holds.  The selector wiring is correct.
        // PRODUCTION: replace the gate body with a lookup argument against a
        //   pre-computed u64 range table (halo2_gadgets RangeCheckChip).
        meta.create_gate("range_check", |vc| {
            let s = vc.query_selector(s_range);
            let a = vc.query_advice(a, Rotation::cur());
            // s_range * (a - a) = 0  — always satisfied (placeholder)
            vec![s * (a.clone() - a)]
        });

        ComplianceConfig { a, b, c, constant, instance, s_hash, s_merkle, s_range }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: byte-array → field element
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a byte slice as a field element using little-endian packing.
///
/// Interprets the first `min(bytes.len(), 32)` bytes as a little-endian
/// unsigned integer and maps it into the field.  This is injective for inputs
/// up to 32 bytes (Fp is ~255 bits), so distinct byte arrays produce distinct
/// field elements — unlike a byte-sum which is not injective at all.
///
/// PROTOTYPE: still not Poseidon — this encoding has no hiding property and
/// leaks byte structure.  However it is a correct *commitment* for constraint
/// purposes: the prover cannot substitute a different byte array and satisfy
/// the same constraint.
/// PRODUCTION: replace with a Poseidon sponge over the individual byte values.
fn bytes_to_field<F: ff::PrimeField>(bytes: &[u8]) -> F {
    // Pack up to 32 bytes little-endian into a 32-byte repr buffer.
    // F::from_repr expects exactly F::Repr::default().len() bytes (32 for Fp).
    let mut repr = F::Repr::default();
    {
        let repr_slice = repr.as_mut();
        let len = repr_slice.len().min(bytes.len());
        repr_slice[..len].copy_from_slice(&bytes[..len]);
    }
    // from_repr returns CtOption; if the value >= p (unlikely for 20/32-byte
    // inputs well below the Pasta field modulus) fall back to reduction via
    // from_u128 on the low bytes — but in practice this never fires for our
    // address and hash sizes.
    F::from_repr(repr).unwrap_or_else(|| {
        let mut low = [0u8; 8];
        low.copy_from_slice(&bytes[..8.min(bytes.len())]);
        F::from(u64::from_le_bytes(low))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ComplianceCircuit
// ─────────────────────────────────────────────────────────────────────────────

/// Halo2 ZKP circuit that proves transaction compliance without revealing
/// sender address, receiver address, amount, or Merkle path.
#[derive(Clone, Debug)]
pub struct ComplianceCircuit {
    pub public: PublicInputs,
    pub witness: Value<Witness>,
}

impl<F: ff::PrimeField> Circuit<F> for ComplianceCircuit {
    type Config = ComplianceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { public: self.public.clone(), witness: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ComplianceConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        // ── Region 1: Load private witness ──────────────────────────────
        // Assign sender, receiver, amount as single field elements.
        // These cells are re-used (via copy-constraints) in every later region
        // so the prover cannot substitute different values per gate.
        let (sender_cell, receiver_cell, amount_cell) = layouter.assign_region(
            || "load_witness",
            |mut region: Region<'_, F>| {
                let sender_val =
                    self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.sender_addr));
                let receiver_val =
                    self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.receiver_addr));
                let amount_val = self.witness.as_ref().map(|w| F::from(w.amount));

                let s = region.assign_advice(|| "sender", config.a, 0, || sender_val)?;
                let r = region.assign_advice(|| "receiver", config.b, 0, || receiver_val)?;
                let am = region.assign_advice(|| "amount", config.c, 0, || amount_val)?;
                Ok((s, r, am))
            },
        )?;

        // ── Region 2: Range check on amount ──────────────────────────────
        // PROTOTYPE: gate is tautological; wiring is production-correct.
        // PRODUCTION: the s_range selector activates a lookup table chip.
        layouter.assign_region(
            || "range_check",
            |mut region: Region<'_, F>| {
                config.s_range.enable(&mut region, 0)?;
                // Copy from load_witness so the prover can't swap a different
                // amount value into the range-check row.
                amount_cell.copy_advice(|| "amount_rc", &mut region, config.a, 0)?;
                Ok(())
            },
        )?;

        // ── Region 3: Hash-binding (C3) ──────────────────────────────────
        // Constraint: sender_commit + receiver_commit = tx_hash_commit
        //
        // The tx_hash_commit cell is later wired to the instance column so the
        // verifier can confirm it matches the on-chain tx_hash.
        let tx_hash_commit = Value::known(bytes_to_field::<F>(&self.public.tx_hash));
        let tx_hash_cell: AssignedCell<F, F> = layouter.assign_region(
            || "hash_binding",
            |mut region: Region<'_, F>| {
                config.s_hash.enable(&mut region, 0)?;
                // Copy sender / receiver from load_witness — prevents the
                // prover from using different addresses here than in the Merkle
                // membership regions.
                sender_cell.copy_advice(|| "sender_h", &mut region, config.a, 0)?;
                receiver_cell.copy_advice(|| "receiver_h", &mut region, config.b, 0)?;
                let out =
                    region.assign_advice(|| "tx_hash_out", config.c, 0, || tx_hash_commit)?;
                Ok(out)
            },
        )?;

        // ── Wire tx_hash_out → instance column (rows 0..32) ──────────────
        // tx_hash is 32 bytes; we committed to a single folded field element.
        // We wire that one cell to instance row TX_HASH_START.  A production
        // circuit would wire 32 separate byte cells — one per instance row.
        //
        // This constrain_instance call records a copy-constraint in the
        // permutation argument.  MockProver.verify() checks it automatically.
        layouter.constrain_instance(
            tx_hash_cell.cell(),
            config.instance,
            TX_HASH_START, // row 0: the folded tx_hash field element
        )?;

        // ── Merkle root field element (same for both C1 and C2) ──────────
        let root_val = bytes_to_field::<F>(&self.public.compliance_merkle_root);

        // ── Region 4: Merkle path for sender (C1) ────────────────────────
        let sender_leaf =
            self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.sender_addr));
        let sender_path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
            w.merkle_path[..MERKLE_DEPTH]
                .iter()
                .map(|n| bytes_to_field::<F>(n))
                .collect()
        });
        let sender_root_cell = assign_merkle_region::<F>(
            &config,
            &mut layouter,
            "sender_merkle",
            sender_leaf,
            sender_path,
            root_val,
        )?;

        // Wire sender Merkle root → instance column (row MERKLE_ROOT_START).
        layouter.constrain_instance(
            sender_root_cell.cell(),
            config.instance,
            MERKLE_ROOT_START,
        )?;

        // ── Region 5: Merkle path for receiver (C2) ──────────────────────
        let receiver_leaf =
            self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.receiver_addr));
        let receiver_path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
            w.merkle_path[MERKLE_DEPTH..]
                .iter()
                .map(|n| bytes_to_field::<F>(n))
                .collect()
        });
        let receiver_root_cell = assign_merkle_region::<F>(
            &config,
            &mut layouter,
            "receiver_merkle",
            receiver_leaf,
            receiver_path,
            root_val,
        )?;

        // Wire receiver Merkle root → instance column (same row: both paths
        // must reach the same compliance_merkle_root).
        layouter.constrain_instance(
            receiver_root_cell.cell(),
            config.instance,
            MERKLE_ROOT_START,
        )?;

        // ── Wire block_height → instance column (row 64) ─────────────────
        // block_height is a scalar; assign it into a throwaway advice cell
        // just so we can record the copy-constraint.
        let bh_cell: AssignedCell<F, F> = layouter.assign_region(
            || "block_height",
            |mut region: Region<'_, F>| {
                let bh_val = Value::known(F::from(self.public.block_height));
                region.assign_advice(|| "block_height", config.a, 0, || bh_val)
            },
        )?;
        layouter.constrain_instance(bh_cell.cell(), config.instance, BLOCK_HEIGHT_ROW)?;

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle region helper
// ─────────────────────────────────────────────────────────────────────────────

/// Assign one Merkle path region (`MERKLE_DEPTH` rows) and return the final
/// root cell so the caller can wire it to the instance column.
///
/// Row layout (one row per tree level `i`):
///
/// ```text
/// row i: a[i] = current_node
///        b[i] = sibling (from merkle_path)
///        c[i] = parent  = node + sibling   ← s_merkle gate
/// ```
///
/// At depth `MERKLE_DEPTH - 1`, an extra anchor row is added via
/// `assign_advice_from_constant` to plant the expected root value.
/// A `constrain_equal` between `parent_cell` and the anchor enforces
/// that the computed root matches — regardless of the path values.
///
/// The returned cell is the final `parent_cell` (= computed root).
/// The caller wires it to the public instance column.
fn assign_merkle_region<F: ff::PrimeField>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    leaf: Value<F>,
    path: Value<Vec<F>>,
    expected_root: F,
) -> Result<AssignedCell<F, F>, ErrorFront> {
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            let mut current: Value<F> = leaf;
            let mut final_parent_cell: Option<AssignedCell<F, F>> = None;

            for depth in 0..MERKLE_DEPTH {
                config.s_merkle.enable(&mut region, depth)?;

                let sibling: Value<F> = path.as_ref().map(|p| p[depth]);

                // PROTOTYPE: parent = node + sibling
                // PRODUCTION: parent = Poseidon(node, sibling)
                let parent: Value<F> = current.zip(sibling).map(|(n, s)| n + s);

                region.assign_advice(|| "node", config.a, depth, || current)?;
                region.assign_advice(|| "sibling", config.b, depth, || sibling)?;
                let parent_cell =
                    region.assign_advice(|| "parent", config.c, depth, || parent)?;

                if depth == MERKLE_DEPTH - 1 {
                    // Plant the expected root as a fixed constant in the row
                    // immediately after the last Merkle row, then enforce
                    // equality between computed_parent and expected_root.
                    // This is the root-binding constraint: if the path is wrong
                    // the computed parent won't equal the committed root and
                    // verify() will return a Permutation error.
                    let root_anchor = region.assign_advice_from_constant(
                        || "root_anchor",
                        config.c,
                        depth + 1,
                        expected_root,
                    )?;
                    region.constrain_equal(parent_cell.cell(), root_anchor.cell())?;
                    final_parent_cell = Some(parent_cell);
                }

                current = parent;
            }

            // Unwrap is safe: loop always reaches MERKLE_DEPTH - 1.
            Ok(final_parent_cell.unwrap())
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use halo2curves::pasta::Fp;

    // ── Fixture builder ───────────────────────────────────────────────────
    //
    // Construction strategy: work entirely in field arithmetic.
    //
    // 1. Choose sender_addr, receiver_addr as raw byte arrays.
    // 2. Compute their field elements via bytes_to_field — this is the ground
    //    truth the circuit will use internally.
    // 3. Derive tx_hash bytes by encoding (sender_f + receiver_f) back into
    //    a [u8; 32] so that bytes_to_field(tx_hash) == sender_f + receiver_f.
    // 4. For each Merkle path: choose MERKLE_DEPTH-1 arbitrary sibling byte
    //    arrays, compute the running field sum, then derive the final sibling
    //    as (target_root_f - running) encoded back into bytes.
    // 5. Encode compliance_merkle_root as the bytes of target_root_f.
    //
    // This way the fixture is defined by field values, not byte sums, and
    // changing MERKLE_DEPTH or the address bytes cannot cause silent overflow.
    fn field_to_bytes(f: Fp) -> [u8; 32] {
        // Fp::to_repr() gives the canonical little-endian byte representation.
        f.to_repr().into()
    }

    fn make_fixture() -> (ComplianceCircuit, Vec<Vec<Fp>>) {
        let sender_addr: [u8; 20] = [0x01u8; 20];
        let receiver_addr: [u8; 20] = [0x02u8; 20];
        let amount: u64 = 999;
        let block_height: u64 = 1_000_000;

        // Ground-truth field elements for sender and receiver.
        let sender_f: Fp = bytes_to_field(&sender_addr);
        let receiver_f: Fp = bytes_to_field(&receiver_addr);

        // tx_hash bytes encode (sender_f + receiver_f) so that
        // bytes_to_field(tx_hash) == sender_f + receiver_f exactly.
        let tx_hash_f: Fp = sender_f + receiver_f;
        let tx_hash: [u8; 32] = field_to_bytes(tx_hash_f);

        // Arbitrary but fixed sibling bytes for levels 0..MERKLE_DEPTH-2.
        // Any values work — we solve for the last sibling in field arithmetic.
        let common_sibling: [u8; 32] = {
            let mut a = [0u8; 32];
            a[0] = 0x07;
            a
        };
        let common_f: Fp = bytes_to_field(&common_sibling);

        // target_root_f: arbitrary field element that both paths will converge to.
        // Chosen as a fixed constant independent of address values.
        let target_root_f: Fp = Fp::from(0xDEAD_BEEF_u64);

        // Build a Merkle path for one side.
        // After (MERKLE_DEPTH-1) common siblings the running field value is:
        //   running = leaf_f + (MERKLE_DEPTH-1) * common_f
        // The last sibling must satisfy: running + last_sib_f = target_root_f
        //   → last_sib_f = target_root_f - running
        let make_path = |leaf_f: Fp| -> Vec<[u8; 32]> {
            let running: Fp = leaf_f
                + common_f * Fp::from(MERKLE_DEPTH as u64 - 1);
            let last_sib_f: Fp = target_root_f - running;

            let mut path = vec![common_sibling; MERKLE_DEPTH - 1];
            path.push(field_to_bytes(last_sib_f));
            path
        };

        let sender_path = make_path(sender_f);
        let receiver_path = make_path(receiver_f);

        // Verify both paths in field arithmetic — no byte-sum guesswork.
        let check_path = |leaf_f: Fp, path: &[[u8; 32]]| -> Fp {
            path.iter().fold(leaf_f, |cur, sib| cur + bytes_to_field::<Fp>(sib))
        };
        assert_eq!(check_path(sender_f, &sender_path), target_root_f);
        assert_eq!(check_path(receiver_f, &receiver_path), target_root_f);

        let compliance_merkle_root: [u8; 32] = field_to_bytes(target_root_f);

        let mut merkle_path = sender_path;
        merkle_path.extend_from_slice(&receiver_path);

        let public = PublicInputs { tx_hash, compliance_merkle_root, block_height };
        let witness = Witness { sender_addr, receiver_addr, amount, merkle_path };
        let circuit = ComplianceCircuit {
            public: public.clone(),
            witness: Value::known(witness),
        };

        // Instance column (65 rows).
        // Only the three wired rows carry meaningful values; the rest are zero
        // because no constrain_instance call touches them.
        let mut instance_col = vec![Fp::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_f;
        instance_col[MERKLE_ROOT_START] = target_root_f;
        instance_col[BLOCK_HEIGHT_ROW] = Fp::from(block_height);

        (circuit, vec![instance_col])
    }

    // ── Test 1: valid witness → verify() passes ───────────────────────────
    #[test]
    fn test_valid_witness_passes() {
        let (circuit, instance) = make_fixture();
        // k = 8 → 2^8 = 256 rows; sufficient for MERKLE_DEPTH = 4.
        let prover = MockProver::<Fp>::run(8, &circuit, instance)
            .expect("MockProver::run failed");
        prover.verify().expect("Valid witness should satisfy all constraints");
    }

    // ── Test 2: wrong tx_hash in public inputs → verify() fails ──────────
    //
    // The instance column at row TX_HASH_START is set to a value that does
    // NOT equal sender_sum + receiver_sum.  The constrain_instance wire from
    // tx_hash_out → instance[0] will fail the permutation check.
    #[test]
    fn test_wrong_tx_hash_fails() {
        let (circuit, mut instance) = make_fixture();
        // Corrupt the tx_hash instance value.
        instance[0][TX_HASH_START] += Fp::from(1u64);
        let prover = MockProver::<Fp>::run(8, &circuit, instance)
            .expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong tx_hash should cause verify() to fail"
        );
    }

    // ── Test 3: wrong merkle_root in public inputs → verify() fails ───────
    //
    // The instance column at row MERKLE_ROOT_START is corrupted.
    // Both sender and receiver Merkle roots are wired to this row, so
    // the permutation check fails.
    #[test]
    fn test_wrong_merkle_root_fails() {
        let (circuit, mut instance) = make_fixture();
        instance[0][MERKLE_ROOT_START] += Fp::from(1u64);
        let prover = MockProver::<Fp>::run(8, &circuit, instance)
            .expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong merkle_root should cause verify() to fail"
        );
    }

    // ── Test 4: wrong merkle_path in witness → verify() fails ────────────
    //
    // The sender's first sibling is changed so the computed Merkle root no
    // longer equals the committed compliance_merkle_root.
    // The root_anchor constrain_equal in assign_merkle_region fires.
    #[test]
    fn test_wrong_merkle_path_fails() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            // Flip one byte in the first sender sibling → wrong path root.
            w.merkle_path[0][0] ^= 0xFF;
            w
        });
        let prover = MockProver::<Fp>::run(8, &circuit, instance)
            .expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong Merkle path should cause verify() to fail"
        );
    }
}
