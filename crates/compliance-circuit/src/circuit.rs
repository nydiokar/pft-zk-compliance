use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};

/// Public inputs committed on-chain and visible to verifiers.
/// Layout: [tx_hash(32), compliance_merkle_root(32), block_height(1)] = 65 cells.
pub struct PublicInputs {
    /// Poseidon hash of (sender_addr ‖ receiver_addr ‖ amount).
    pub tx_hash: [u8; 32],
    /// Root of the compliance address set Merkle tree (snapshot at block_height).
    pub compliance_merkle_root: [u8; 32],
    /// Block height of the compliance snapshot.
    pub block_height: u64,
}

/// Private witness — never revealed to the verifier.
pub struct Witness {
    /// Sender Ethereum-style address (20 bytes).
    pub sender_addr: [u8; 20],
    /// Receiver address (20 bytes).
    pub receiver_addr: [u8; 20],
    /// Transaction amount.
    pub amount: u64,
    /// Sibling hashes for Merkle membership proof.
    /// Length = 2 * MERKLE_DEPTH (one path for sender, one for receiver).
    pub merkle_path: Vec<[u8; 32]>,
}

/// Halo2 circuit configuration.
/// TODO(Step 1): add custom gate columns and lookup tables here.
#[derive(Clone, Debug)]
pub struct ComplianceConfig {
    /// Public instance columns: tx_hash bytes, merkle_root bytes, block_height.
    pub instance: Column<Instance>,
    // TODO: add Advice columns for witness, Selector columns for gates
}

/// ComplianceCircuit proves:
///   1. sender_addr ∈ compliance_list  (Merkle membership)
///   2. receiver_addr ∈ compliance_list (Merkle membership)
///   3. Poseidon(sender ‖ receiver ‖ amount) = tx_hash  (hash binding)
///
/// Public inputs: tx_hash, compliance_merkle_root, block_height
/// Private witness: sender_addr, receiver_addr, amount, merkle_path
pub struct ComplianceCircuit {
    pub public: PublicInputs,
    pub witness: Value<Witness>,
}

impl<F: halo2_proofs::arithmetic::Field> Circuit<F> for ComplianceCircuit {
    type Config = ComplianceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            public: PublicInputs {
                tx_hash: self.public.tx_hash,
                compliance_merkle_root: self.public.compliance_merkle_root,
                block_height: self.public.block_height,
            },
            witness: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // TODO(Step 1): configure advice columns, selectors, custom gates
        // - Poseidon hash gate for tx_hash binding
        // - Merkle path verification gate
        // - Range check lookup for amount

        ComplianceConfig { instance }
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        mut _layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        // TODO(Step 1): implement circuit synthesis
        // Region 1: load witness values into advice columns
        // Region 2: apply Poseidon hash gate (C3 constraint)
        // Region 3: Merkle path verification for sender (C1)
        // Region 4: Merkle path verification for receiver (C2)
        Ok(())
    }
}
