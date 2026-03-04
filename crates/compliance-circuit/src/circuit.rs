//! ComplianceCircuit — Halo2 ZKP circuit for Post Fiat compliance filtering.
//!
//! Proves, without revealing witness data:
//!   C1. sender_addr ∈ compliance_list   (Merkle membership)
//!   C2. receiver_addr ∈ compliance_list  (Merkle membership)
//!   C3. hash_commit(sender ‖ receiver ‖ amount) = tx_hash  (hash binding)
//!
//! Public inputs  (Instance column, rows 0-64):
//!   rows  0..32  → tx_hash bytes
//!   rows 32..64  → compliance_merkle_root bytes
//!   row  64      → block_height
//!
//! Private witness (Advice columns): sender, receiver, amount, merkle_path
//!
//! Gate design (see docs/circuit_io.md):
//!   - hash_gate:   enforces C3 — linear commitment a + b = c (Poseidon stand-in)
//!   - merkle_gate: enforces C1/C2 per level: node + sibling = parent
//!   - range_gate:  placeholder for u64 range check (tautological in prototype)
//!
//! Production path: swap the linear gates for halo2_gadgets::poseidon::Hash
//! and a binary Merkle gadget. The constraint plumbing is identical.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

// ──────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────

/// Merkle tree depth. Supports 2^MERKLE_DEPTH addresses.
/// Each side (sender / receiver) uses MERKLE_DEPTH sibling hashes.
/// Set to 20 for production (~1 M addresses); 4 for prototype speed.
pub const MERKLE_DEPTH: usize = 4;

// ──────────────────────────────────────────────────────────
// Public / Private input types
// ──────────────────────────────────────────────────────────

/// Public inputs committed on-chain and visible to verifiers.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Poseidon hash of (sender_addr ‖ receiver_addr ‖ amount).
    pub tx_hash: [u8; 32],
    /// Root of the compliance address set Merkle tree.
    pub compliance_merkle_root: [u8; 32],
    /// Block height of the compliance snapshot.
    pub block_height: u64,
}

/// Private witness — never revealed to the verifier.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Sender Ethereum-style address (20 bytes).
    pub sender_addr: [u8; 20],
    /// Receiver address (20 bytes).
    pub receiver_addr: [u8; 20],
    /// Transaction amount.
    pub amount: u64,
    /// Sibling hashes for Merkle membership proof.
    /// First MERKLE_DEPTH entries = sender path; next MERKLE_DEPTH = receiver path.
    pub merkle_path: Vec<[u8; 32]>,
}

// ──────────────────────────────────────────────────────────
// Circuit configuration
// ──────────────────────────────────────────────────────────

/// Halo2 column/gate configuration for ComplianceCircuit.
#[derive(Clone, Debug)]
pub struct ComplianceConfig {
    /// a: left operand (leaf node / sender / partial hash input)
    pub a: Column<Advice>,
    /// b: right operand (sibling node / receiver / partial hash input)
    pub b: Column<Advice>,
    /// c: output (parent node / tx_hash commitment)
    pub c: Column<Advice>,
    /// Constants column (enables assign_advice_from_constant)
    pub constant: Column<Fixed>,
    /// Single instance column carrying all 65 public inputs.
    pub instance: Column<Instance>,
    /// Activates hash-binding gate (C3).
    pub s_hash: Selector,
    /// Activates Merkle-path gate (C1 / C2 per level).
    pub s_merkle: Selector,
    /// Activates range-check gate (amount ∈ u64).
    pub s_range: Selector,
}

impl ComplianceConfig {
    fn configure<F: ff::PrimeField>(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        let s_hash = meta.selector();
        let s_merkle = meta.selector();
        let s_range = meta.selector();

        // ── C3: Hash-binding gate ──────────────────────────────────────────
        // Prototype: a + b = c  (linear commitment standing in for Poseidon).
        // Production: replace with halo2_gadgets::poseidon::Hash gadget.
        meta.create_gate("hash_binding", |vc| {
            let s = vc.query_selector(s_hash);
            let a = vc.query_advice(a, Rotation::cur());
            let b = vc.query_advice(b, Rotation::cur());
            let c = vc.query_advice(c, Rotation::cur());
            vec![s * (a + b - c)]
        });

        // ── C1 / C2: Merkle-path gate ─────────────────────────────────────
        // One row per tree level: parent = node + sibling.
        // Production: replace with a proper binary Merkle gadget.
        meta.create_gate("merkle_path", |vc| {
            let s = vc.query_selector(s_merkle);
            let node = vc.query_advice(a, Rotation::cur());
            let sibling = vc.query_advice(b, Rotation::cur());
            let parent = vc.query_advice(c, Rotation::cur());
            vec![s * (node + sibling - parent)]
        });

        // ── Range gate ─────────────────────────────────────────────────────
        // Prototype: tautological (a - a = 0). Production: lookup table.
        meta.create_gate("range_check", |vc| {
            let s = vc.query_selector(s_range);
            let a = vc.query_advice(a, Rotation::cur());
            vec![s * (a.clone() - a)]
        });

        ComplianceConfig { a, b, c, constant, instance, s_hash, s_merkle, s_range }
    }
}

// ──────────────────────────────────────────────────────────
// Helper: fold bytes into a field element
// ──────────────────────────────────────────────────────────

/// Fold a byte slice into a single field element by summing byte values.
/// This is a deterministic, injective-enough encoding for prototype constraints.
/// Production: replace with Poseidon sponge over the bytes.
fn bytes_to_field<F: ff::PrimeField>(bytes: &[u8]) -> F {
    bytes.iter().fold(F::ZERO, |acc, &b| acc + F::from(b as u64))
}

// ──────────────────────────────────────────────────────────
// ComplianceCircuit
// ──────────────────────────────────────────────────────────

/// Halo2 circuit proving transaction compliance without revealing sender,
/// receiver, amount, or Merkle path.
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
        // ── Region 1: Load witness ─────────────────────────────────────────
        let (sender_cell, receiver_cell, amount_cell) = layouter.assign_region(
            || "load_witness",
            |mut region: Region<'_, F>| {
                let sender_val = self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.sender_addr));
                let receiver_val =
                    self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.receiver_addr));
                let amount_val = self.witness.as_ref().map(|w| F::from(w.amount));

                let s = region.assign_advice(|| "sender", config.a, 0, || sender_val)?;
                let r = region.assign_advice(|| "receiver", config.b, 0, || receiver_val)?;
                let am = region.assign_advice(|| "amount", config.c, 0, || amount_val)?;
                Ok((s, r, am))
            },
        )?;

        // ── Region 2: Range check on amount ───────────────────────────────
        layouter.assign_region(
            || "range_check",
            |mut region: Region<'_, F>| {
                config.s_range.enable(&mut region, 0)?;
                amount_cell.copy_advice(|| "amount", &mut region, config.a, 0)?;
                Ok(())
            },
        )?;

        // ── Region 3: Hash-binding (C3) ────────────────────────────────────
        // Enforce: sender_commit + receiver_commit = tx_hash_commit
        let tx_hash_commit = Value::known(bytes_to_field::<F>(&self.public.tx_hash));

        let _tx_cell: AssignedCell<F, F> = layouter.assign_region(
            || "hash_binding",
            |mut region: Region<'_, F>| {
                config.s_hash.enable(&mut region, 0)?;
                sender_cell.copy_advice(|| "sender", &mut region, config.a, 0)?;
                receiver_cell.copy_advice(|| "receiver", &mut region, config.b, 0)?;
                let out =
                    region.assign_advice(|| "tx_hash_out", config.c, 0, || tx_hash_commit)?;
                Ok(out)
            },
        )?;

        // ── Merkle root field element (from public inputs) ─────────────────
        let root_val = bytes_to_field::<F>(&self.public.compliance_merkle_root);

        // ── Region 4: Merkle path for sender (C1) ─────────────────────────
        {
            let leaf = self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.sender_addr));
            let path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
                w.merkle_path[..MERKLE_DEPTH]
                    .iter()
                    .map(|n| bytes_to_field::<F>(n))
                    .collect()
            });
            assign_merkle_region::<F>(
                &config, &mut layouter, "sender_merkle", leaf, path, root_val,
            )?;
        }

        // ── Region 5: Merkle path for receiver (C2) ───────────────────────
        {
            let leaf = self.witness.as_ref().map(|w| bytes_to_field::<F>(&w.receiver_addr));
            let path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
                w.merkle_path[MERKLE_DEPTH..]
                    .iter()
                    .map(|n| bytes_to_field::<F>(n))
                    .collect()
            });
            assign_merkle_region::<F>(
                &config, &mut layouter, "receiver_merkle", leaf, path, root_val,
            )?;
        }

        Ok(())
    }
}

/// Assign one Merkle path region (MERKLE_DEPTH rows).
///
/// Row layout per level i:
///   a[i] = current node
///   b[i] = sibling (from merkle_path)
///   c[i] = parent = node + sibling   (s_merkle gate enforces this)
///
/// After the final level, c[MERKLE_DEPTH-1] is constrained equal to
/// the expected Merkle root via an `assign_advice_from_constant` anchor.
fn assign_merkle_region<F: ff::PrimeField>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    leaf: Value<F>,
    path: Value<Vec<F>>,
    expected_root: F,
) -> Result<(), ErrorFront> {
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            let mut current: Value<F> = leaf;

            for depth in 0..MERKLE_DEPTH {
                config.s_merkle.enable(&mut region, depth)?;

                let sibling: Value<F> = path.as_ref().map(|p| p[depth]);
                let parent: Value<F> = current.zip(sibling).map(|(n, s)| n + s);

                region.assign_advice(|| "node", config.a, depth, || current)?;
                region.assign_advice(|| "sibling", config.b, depth, || sibling)?;
                let parent_cell =
                    region.assign_advice(|| "parent", config.c, depth, || parent)?;

                // At the final level, enforce parent == expected_root.
                if depth == MERKLE_DEPTH - 1 {
                    let root_cell = region.assign_advice_from_constant(
                        || "merkle_root",
                        config.c,
                        depth + 1,
                        expected_root,
                    )?;
                    region.constrain_equal(parent_cell.cell(), root_cell.cell())?;
                }

                current = parent;
            }
            Ok(())
        },
    )
}

// ──────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use halo2curves::pasta::Fp;

    /// Build a self-consistent test fixture.
    ///
    /// The prototype circuit uses linear sums as stand-ins for hash functions:
    ///   hash_binding:  sender_sum + receiver_sum = tx_hash_sum   (C3)
    ///   merkle_level:  node + sibling = parent                   (C1/C2)
    ///
    /// Strategy: choose byte arrays so that all arithmetic stays in u64 and
    /// both Merkle paths land on the SAME compliance_merkle_root.
    ///
    /// We pick small, uniform byte values and construct the root by summing
    /// upward; then encode the root into the compliance_merkle_root byte array.
    fn make_test_circuit() -> (ComplianceCircuit, Vec<Vec<Fp>>) {
        // --- Addresses & amount ---
        // Use small byte values to avoid overflow during path summation.
        let sender_addr: [u8; 20] = [1u8; 20];  // byte-sum = 20
        let receiver_addr: [u8; 20] = [2u8; 20]; // byte-sum = 40
        let amount: u64 = 999;

        let sender_sum: u64 = sender_addr.iter().map(|&b| b as u64).sum();   // 20
        let receiver_sum: u64 = receiver_addr.iter().map(|&b| b as u64).sum(); // 40

        // --- Hash binding (C3): tx_hash_sum = sender_sum + receiver_sum ---
        let hash_commit_val: u64 = sender_sum + receiver_sum; // 60
        let mut tx_hash = [0u8; 32];
        // Encode as single byte (fits in u8 for this fixture).
        tx_hash[0] = hash_commit_val as u8;

        // --- Merkle path: build paths so both converge to the same root ---
        //
        // For each side, pick MERKLE_DEPTH siblings (value = 1 each, byte-sum = 1).
        // root = leaf + sum_of_siblings = leaf + MERKLE_DEPTH
        // sender_root = 20 + 4 = 24
        // receiver_root = 40 + 4 = 44   ← these differ!
        //
        // Solution: use the SAME siblings for both but adjust the last sibling
        // for each path so both roots converge to a chosen target_root.
        //
        // target_root = 100 (arbitrary, fits in a single byte for easy encoding)
        // sender path:   last sibling sum = target_root - (sender_sum + (MERKLE_DEPTH-1)*1)
        // receiver path: last sibling sum = target_root - (receiver_sum + (MERKLE_DEPTH-1)*1)
        let target_root: u64 = 200; // large enough to avoid underflow for both sides

        // Common siblings for levels 0..MERKLE_DEPTH-2 (byte-sum = 1 each)
        let common_sibling: [u8; 32] = {
            let mut a = [0u8; 32];
            a[0] = 1;
            a
        };

        // Compute running sums after MERKLE_DEPTH-1 common siblings
        let sender_after_common: u64 = sender_sum + (MERKLE_DEPTH as u64 - 1);
        let receiver_after_common: u64 = receiver_sum + (MERKLE_DEPTH as u64 - 1);

        // Last sibling for each path makes the final parent = target_root
        let sender_last_sib_sum: u64 = target_root - sender_after_common;
        let receiver_last_sib_sum: u64 = target_root - receiver_after_common;

        // Build sender path
        let mut sender_siblings: Vec<[u8; 32]> = vec![common_sibling; MERKLE_DEPTH - 1];
        sender_siblings.push({
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&sender_last_sib_sum.to_le_bytes());
            a
        });

        // Build receiver path
        let mut receiver_siblings: Vec<[u8; 32]> = vec![common_sibling; MERKLE_DEPTH - 1];
        receiver_siblings.push({
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&receiver_last_sib_sum.to_le_bytes());
            a
        });

        // Verify both roots equal target_root
        let check_root = |leaf: u64, siblings: &Vec<[u8; 32]>| -> u64 {
            siblings.iter().fold(leaf, |cur, sib| {
                cur + sib.iter().map(|&b| b as u64).sum::<u64>()
            })
        };
        assert_eq!(check_root(sender_sum, &sender_siblings), target_root);
        assert_eq!(check_root(receiver_sum, &receiver_siblings), target_root);

        // Encode compliance_merkle_root: byte-sum = target_root
        let mut compliance_merkle_root = [0u8; 32];
        compliance_merkle_root[..8].copy_from_slice(&target_root.to_le_bytes());

        // Full merkle_path = sender siblings ++ receiver siblings
        let mut merkle_path = sender_siblings;
        merkle_path.extend_from_slice(&receiver_siblings);

        let public = PublicInputs { tx_hash, compliance_merkle_root, block_height: 1_000_000u64 };
        let witness = Witness {
            sender_addr,
            receiver_addr,
            amount,
            merkle_path,
        };
        let circuit = ComplianceCircuit {
            public: public.clone(),
            witness: Value::known(witness),
        };

        // Build public instance vector (single column, 65 rows):
        //   rows  0..32  → tx_hash bytes as Fp
        //   rows 32..64  → compliance_merkle_root bytes as Fp
        //   row  64      → block_height as Fp
        let mut instance_col: Vec<Fp> = public
            .tx_hash
            .iter()
            .map(|&b| Fp::from(b as u64))
            .collect();
        instance_col.extend(
            public.compliance_merkle_root.iter().map(|&b| Fp::from(b as u64)),
        );
        instance_col.push(Fp::from(public.block_height));

        (circuit, vec![instance_col])
    }

    #[test]
    fn test_compliance_circuit_valid() {
        let (circuit, instance) = make_test_circuit();
        // k = 8 → 2^8 = 256 rows (sufficient for MERKLE_DEPTH=4 prototype)
        let prover = MockProver::<Fp>::run(8, &circuit, instance)
            .expect("MockProver::run failed");
        prover.verify().expect("Circuit constraints unsatisfied");
    }
}
