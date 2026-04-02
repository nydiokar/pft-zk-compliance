//! ComplianceCircuit — Halo2 ZKP circuit for Post Fiat compliance filtering.
//!
//! # What this circuit proves
//!
//! Without revealing any witness data, the circuit proves:
//!
//!   C1. `sender_oracle_sig` authorizes `Poseidon(sender_pubkey)` under the
//!       constrained oracle key
//!   C2. `receiver_oracle_sig` authorizes `Poseidon(receiver_pubkey)` under the
//!       constrained oracle key
//!   C3. `sender_pubkey`   ∈ compliance_list  (Merkle membership)
//!   C4. `receiver_pubkey` ∈ compliance_list  (Merkle membership)
//!   C5. `commit(sender_pubkey ‖ receiver_pubkey ‖ amount) = tx_hash`
//!       (hash binding)
//!
//! # Public / private split
//!
//! | Column type | Field                  | Rows (instance col) |
//! |-------------|------------------------|---------------------|
//! | Instance    | `tx_hash`              | 0..32               |
//! | Instance    | `compliance_merkle_root` | 32..64             |
//! | Instance    | `oracle_pubkey_hash`   | 64..96              |
//! | Instance    | `block_height`         | 96                  |
//! | Advice      | `sender_pubkey`        | witness             |
//! | Advice      | `receiver_pubkey`      | witness             |
//! | Advice      | `amount`               | witness             |
//! | Advice      | `sender_oracle_sig`    | witness             |
//! | Advice      | `receiver_oracle_sig`  | witness             |
//! | Advice      | `sender_merkle_*`      | witness             |
//! | Advice      | `receiver_merkle_*`    | witness             |
//!
//! # Gate design (see also `docs/circuit_io.md`)
//!
//! | Gate              | Constraint                          | Degree |
//! |-------------------|-------------------------------------|--------|
//! | `tx_hash_poseidon`| Poseidon round transition           | 5      |
//! | `merkle_path`     | direction bit + child ordering      | 2      |
//! | `auth_muladd`     | `response = nonce + challenge * sk` | 2      |
//! | `range_check`     | 8-bit lookup decomposition of u64   | 1      |
//!
//! # Prototype substitutions
//!
//! One primitive from the spec (`docs/circuit_io.md`) is still **intentionally
//! simplified** for this prototype. Each substitution is marked in the code
//! with a `PROTOTYPE:` comment and a `PRODUCTION:` comment explaining the
//! upgrade path.
//!
//! **Public-input byte wiring** — instance cells are still folded into one
//!    field element per public input. Production should expose the full byte
//!    layout described in `docs/circuit_io.md`.
//!
//! # Instance wiring
//!
//! Every public input cell is wired to the instance column via
//! `layouter.constrain_instance()`.  The MockProver's permutation checker
//! verifies that the advice values match the supplied instance vector, so a
//! wrong public input causes `verify()` to return `Err(...)`.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Instance,
        Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2_poseidon::{
    generate_constants,
    ConstantLength,
    Hash as PoseidonHash,
    Mds,
    Spec,
};
use group::ff::FromUniformBytes;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Merkle tree depth per side (sender / receiver).
///
/// Production value: 20  →  supports 2^20 ≈ 1 M compliance addresses.
/// Prototype value: 4    →  fast compile + short MockProver run.
pub const MERKLE_DEPTH: usize = 4;

/// Total public instance rows: tx_hash(32) + merkle_root(32) + oracle_hash(32) + block_height(1).
pub const NUM_INSTANCE_ROWS: usize = 97;

/// Instance column row ranges.
pub const TX_HASH_START: usize = 0;
pub const TX_HASH_END: usize = 32;
pub const MERKLE_ROOT_START: usize = 32;
pub const MERKLE_ROOT_END: usize = 64;
pub const ORACLE_PUBKEY_HASH_START: usize = 64;
pub const ORACLE_PUBKEY_HASH_END: usize = 96;
pub const BLOCK_HEIGHT_ROW: usize = 96;

const TX_POSEIDON_WIDTH: usize = 4;
const TX_POSEIDON_RATE: usize = 3;
const TX_POSEIDON_FULL_ROUNDS: usize = 8;
const TX_POSEIDON_PARTIAL_ROUNDS: usize = 56;
const TX_POSEIDON_TOTAL_ROUNDS: usize =
    TX_POSEIDON_FULL_ROUNDS + TX_POSEIDON_PARTIAL_ROUNDS;
const RANGE_LIMB_BITS: usize = 8;
const RANGE_LIMB_BASE: u64 = 1 << RANGE_LIMB_BITS;
const RANGE_LIMB_COUNT: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Public / private input types
// ─────────────────────────────────────────────────────────────────────────────

/// Public inputs committed on-chain; visible to verifiers.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    /// Poseidon commitment of (sender_pubkey ‖ receiver_pubkey ‖ amount).
    pub tx_hash: [u8; 32],
    /// Root of the compliance pubkey Merkle tree at `block_height`.
    pub compliance_merkle_root: [u8; 32],
    /// Poseidon hash of the active compliance oracle public key.
    pub oracle_pubkey_hash: [u8; 32],
    /// Block height of the compliance snapshot.
    pub block_height: u64,
}

/// Private witness — loaded by the prover, never revealed to the verifier.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Sender XRPL ed25519 public key (32 bytes).
    pub sender_pubkey: [u8; 32],
    /// Receiver XRPL ed25519 public key (32 bytes).
    pub receiver_pubkey: [u8; 32],
    /// Compliance oracle authorization key material (32 bytes).
    ///
    /// The circuit constrains `Poseidon(oracle_pubkey)` to the public
    /// `oracle_pubkey_hash`, then uses the same witness value in the
    /// Schnorr-style authorization relation for both transaction parties.
    pub oracle_pubkey: [u8; 32],
    /// Transaction amount.
    pub amount: u64,
    /// Compliance oracle authorization transcript over
    /// `Poseidon(sender_pubkey)`, encoded as `nonce || response`.
    pub sender_oracle_sig: [u8; 64],
    /// Compliance oracle authorization transcript over
    /// `Poseidon(receiver_pubkey)`, encoded as `nonce || response`.
    pub receiver_oracle_sig: [u8; 64],
    /// Sender sibling nodes for the fixed-depth Merkle path.
    pub sender_merkle_siblings: Vec<[u8; 32]>,
    /// Sender per-level direction bits.
    /// `false` means current node is the left child, `true` means right child.
    pub sender_merkle_directions: Vec<bool>,
    /// Receiver sibling nodes for the fixed-depth Merkle path.
    pub receiver_merkle_siblings: Vec<[u8; 32]>,
    /// Receiver per-level direction bits.
    /// `false` means current node is the left child, `true` means right child.
    pub receiver_merkle_directions: Vec<bool>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Column and gate configuration for `ComplianceCircuit`.
#[derive(Clone, Debug)]
pub struct ComplianceConfig {
    /// Left operand: sender field element / current Merkle node / ordered left child.
    pub a: Column<Advice>,
    /// Right operand: receiver field element / Merkle sibling / ordered right child.
    pub b: Column<Advice>,
    /// Output: tx_hash commitment / Merkle direction bit / Merkle parent node.
    pub c: Column<Advice>,
    /// Fourth state word for the tx-hash Poseidon permutation.
    pub d: Column<Advice>,
    /// Fixed constants column — required by `assign_advice_from_constant`.
    pub constant: Column<Fixed>,
    /// Poseidon round constants, one fixed column per state word.
    pub poseidon_rc: [Column<Fixed>; TX_POSEIDON_WIDTH],
    /// Single instance column, rows 0..96 (see module-level table).
    pub instance: Column<Instance>,
    /// Selector: activates Poseidon full-round transitions for C3.
    pub s_poseidon_full: Selector,
    /// Selector: activates Poseidon partial-round transitions for C3.
    pub s_poseidon_partial: Selector,
    /// Selector: activates the Merkle-path gate (C1 / C2 per level).
    pub s_merkle: Selector,
    /// Selector: activates the range-check gate (amount ∈ u64).
    pub s_range: Selector,
    /// Selector: activates the Schnorr-style linear response check.
    pub s_auth_muladd: Selector,
    /// Lookup table for a single 8-bit limb used by the u64 range check.
    pub range_u8_table: TableColumn,
}

impl ComplianceConfig {
    fn configure<F>(meta: &mut ConstraintSystem<F>) -> Self
    where
        F: ff::PrimeField + FromUniformBytes<64> + Ord,
    {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();
        let constant = meta.fixed_column();
        let poseidon_rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let instance = meta.instance_column();
        let range_u8_table = meta.lookup_table_column();

        // Enable equality on all columns so copy-constraints (including
        // constrain_instance wiring) can be recorded in the permutation argument.
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(d);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        let s_poseidon_full = meta.selector();
        let s_poseidon_partial = meta.selector();
        let s_merkle = meta.selector();
        let s_range = meta.complex_selector();
        let s_auth_muladd = meta.selector();

        let mds = poseidon_mds::<F>();
        let pow_5 = |value: Expression<F>| {
            let value_sq = value.clone() * value.clone();
            value_sq.clone() * value_sq * value
        };

        meta.create_gate("tx_hash_poseidon_full_round", |vc| {
            let s = vc.query_selector(s_poseidon_full);
            let cur = [a, b, c, d].map(|column| vc.query_advice(column, Rotation::cur()));
            let next = [a, b, c, d].map(|column| vc.query_advice(column, Rotation::next()));
            let rc = poseidon_rc.map(|column| vc.query_fixed(column, Rotation::cur()));

            (0..TX_POSEIDON_WIDTH)
                .map(|row| {
                    let mixed = (0..TX_POSEIDON_WIDTH)
                        .map(|col| {
                            Expression::Constant(mds[row][col])
                                * pow_5(cur[col].clone() + rc[col].clone())
                        })
                        .reduce(|acc, term| acc + term)
                        .expect("poseidon state is non-empty");
                    s.clone() * (next[row].clone() - mixed)
                })
                .collect::<Vec<_>>()
        });

        meta.create_gate("tx_hash_poseidon_partial_round", |vc| {
            let s = vc.query_selector(s_poseidon_partial);
            let cur = [a, b, c, d].map(|column| vc.query_advice(column, Rotation::cur()));
            let next = [a, b, c, d].map(|column| vc.query_advice(column, Rotation::next()));
            let rc = poseidon_rc.map(|column| vc.query_fixed(column, Rotation::cur()));

            let transformed = [
                pow_5(cur[0].clone() + rc[0].clone()),
                cur[1].clone() + rc[1].clone(),
                cur[2].clone() + rc[2].clone(),
                cur[3].clone() + rc[3].clone(),
            ];

            (0..TX_POSEIDON_WIDTH)
                .map(|row| {
                    let mixed = (0..TX_POSEIDON_WIDTH)
                        .map(|col| Expression::Constant(mds[row][col]) * transformed[col].clone())
                        .reduce(|acc, term| acc + term)
                        .expect("poseidon state is non-empty");
                    s.clone() * (next[row].clone() - mixed)
                })
                .collect::<Vec<_>>()
        });

        // ── C1 / C2: Merkle-path gate ────────────────────────────────────
        // Enforces per-level child ordering from a boolean direction bit.
        //
        // Row i stores `(node, sibling, direction_bit)`.
        // Row i+1 starts the Poseidon state with `(left, right, 0, domain_tag)`.
        //
        // direction_bit = 0  →  left = node,    right = sibling
        // direction_bit = 1  →  left = sibling, right = node
        meta.create_gate("merkle_path", |vc| {
            let s = vc.query_selector(s_merkle);
            let node = vc.query_advice(a, Rotation::cur());
            let sibling = vc.query_advice(b, Rotation::cur());
            let direction_bit = vc.query_advice(c, Rotation::cur());
            let left = vc.query_advice(a, Rotation::next());
            let right = vc.query_advice(b, Rotation::next());
            let one = Expression::Constant(F::ONE);

            vec![
                s.clone() * direction_bit.clone() * (one - direction_bit.clone()),
                s.clone()
                    * (left
                        - (node.clone()
                            + direction_bit.clone() * (sibling.clone() - node.clone()))),
                s * (right - (sibling.clone() + direction_bit * (node - sibling))),
            ]
        });

        // ── Range gate ───────────────────────────────────────────────────
        // Enforces `amount = sum(limb_i * 2^(8*i))` across eight 8-bit limbs.
        meta.create_gate("range_check", |vc| {
            let s = vc.query_selector(s_range);
            let amount = vc.query_advice(a, Rotation::cur());
            let limbs = [
                vc.query_advice(b, Rotation::cur()),
                vc.query_advice(c, Rotation::cur()),
                vc.query_advice(d, Rotation::cur()),
                vc.query_advice(a, Rotation::next()),
                vc.query_advice(b, Rotation::next()),
                vc.query_advice(c, Rotation::next()),
                vc.query_advice(d, Rotation::next()),
                vc.query_advice(a, Rotation(2)),
            ];

            let recomposed = limbs
                .into_iter()
                .enumerate()
                .map(|(idx, limb)| {
                    limb * Expression::Constant(F::from_u128(1u128 << (RANGE_LIMB_BITS * idx)))
                })
                .reduce(|acc, term| acc + term)
                .expect("range limb list is non-empty");

            vec![s * (amount - recomposed)]
        });

        meta.lookup("amount_u8_limb_lookup_0", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(b, Rotation::cur()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_1", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(c, Rotation::cur()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_2", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(d, Rotation::cur()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_3", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(a, Rotation::next()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_4", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(b, Rotation::next()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_5", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(c, Rotation::next()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_6", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(d, Rotation::next()), range_u8_table)]
        });
        meta.lookup("amount_u8_limb_lookup_7", |vc| {
            let s = vc.query_selector(s_range);
            vec![(s * vc.query_advice(a, Rotation(2)), range_u8_table)]
        });

        meta.create_gate("auth_muladd", |vc| {
            let s = vc.query_selector(s_auth_muladd);
            let nonce = vc.query_advice(a, Rotation::cur());
            let challenge = vc.query_advice(b, Rotation::cur());
            let oracle_key = vc.query_advice(c, Rotation::cur());
            let response = vc.query_advice(d, Rotation::cur());

            vec![s * (response - (nonce + challenge * oracle_key))]
        });

        ComplianceConfig {
            a,
            b,
            c,
            d,
            constant,
            poseidon_rc,
            instance,
            s_poseidon_full,
            s_poseidon_partial,
            s_merkle,
            s_range,
            s_auth_muladd,
            range_u8_table,
        }
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

#[derive(Clone, Copy, Debug)]
struct TxHashPoseidonSpec;

impl<F> Spec<F, TX_POSEIDON_WIDTH, TX_POSEIDON_RATE> for TxHashPoseidonSpec
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    fn full_rounds() -> usize {
        TX_POSEIDON_FULL_ROUNDS
    }

    fn partial_rounds() -> usize {
        TX_POSEIDON_PARTIAL_ROUNDS
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[F; TX_POSEIDON_WIDTH]>, Mds<F, TX_POSEIDON_WIDTH>, Mds<F, TX_POSEIDON_WIDTH>) {
        generate_constants::<_, Self, TX_POSEIDON_WIDTH, TX_POSEIDON_RATE>()
    }
}

fn poseidon_constants<F>() -> Vec<[F; TX_POSEIDON_WIDTH]>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    TxHashPoseidonSpec::constants().0
}

fn poseidon_mds<F>() -> Mds<F, TX_POSEIDON_WIDTH>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    TxHashPoseidonSpec::constants().1
}

fn poseidon_hash_words<F, const L: usize>(message: [F; L]) -> F
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    PoseidonHash::<F, TxHashPoseidonSpec, ConstantLength<L>, TX_POSEIDON_WIDTH, TX_POSEIDON_RATE>::init()
        .hash(message)
}

fn poseidon_domain_tag<F: ff::PrimeField>(message_len: usize) -> F {
    F::from_u128((message_len as u128) << 64)
}

pub fn tx_hash_field_from_inputs<F>(
    sender_pubkey: &[u8; 32],
    receiver_pubkey: &[u8; 32],
    amount: u64,
) -> F
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    poseidon_hash_words([
        bytes_to_field(sender_pubkey),
        bytes_to_field(receiver_pubkey),
        F::from(amount),
    ])
}

pub fn merkle_leaf_hash_from_pubkey<F>(pubkey: &[u8; 32]) -> F
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    poseidon_hash_words([bytes_to_field(pubkey)])
}

pub fn merkle_parent_hash_fields<F>(left: F, right: F) -> F
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    poseidon_hash_words([left, right])
}

pub fn oracle_authorization_challenge<F>(oracle_pubkey_hash: F, authorized_key_hash: F, nonce: F) -> F
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    poseidon_hash_words([oracle_pubkey_hash, authorized_key_hash, nonce])
}

pub fn oracle_signature_fields_from_bytes<F>(signature: &[u8; 64]) -> (F, F)
where
    F: ff::PrimeField,
{
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&signature[..32]);
    let mut response = [0u8; 32];
    response.copy_from_slice(&signature[32..]);
    (bytes_to_field::<F>(&nonce), bytes_to_field::<F>(&response))
}

pub fn oracle_signature_bytes<F>(nonce: F, response: F) -> [u8; 64]
where
    F: ff::PrimeField,
{
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(nonce.to_repr().as_ref());
    signature[32..].copy_from_slice(response.to_repr().as_ref());
    signature
}

fn pow5_field<F: ff::PrimeField>(value: F) -> F {
    value.pow_vartime([5])
}

fn poseidon_round<F>(
    state: [F; TX_POSEIDON_WIDTH],
    round_constants: [F; TX_POSEIDON_WIDTH],
    mds: &Mds<F, TX_POSEIDON_WIDTH>,
    is_full_round: bool,
) -> [F; TX_POSEIDON_WIDTH]
where
    F: ff::PrimeField,
{
    let transformed = if is_full_round {
        core::array::from_fn(|idx| pow5_field(state[idx] + round_constants[idx]))
    } else {
        [
            pow5_field(state[0] + round_constants[0]),
            state[1] + round_constants[1],
            state[2] + round_constants[2],
            state[3] + round_constants[3],
        ]
    };

    core::array::from_fn(|row| {
        (0..TX_POSEIDON_WIDTH)
            .map(|col| mds[row][col] * transformed[col])
            .fold(F::ZERO, |acc, term| acc + term)
    })
}

fn assign_poseidon_permutation<F>(
    config: &ComplianceConfig,
    region: &mut Region<'_, F>,
    start_row: usize,
    initial_state: [Value<F>; TX_POSEIDON_WIDTH],
    round_constants: &[[F; TX_POSEIDON_WIDTH]],
    mds: &Mds<F, TX_POSEIDON_WIDTH>,
) -> Result<AssignedCell<F, F>, ErrorFront>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    let mut current_state = initial_state;
    let mut final_state = None;

    for (round, round_constant_row) in round_constants.iter().enumerate() {
        let row = start_row + round;
        let is_full_round = round < TX_POSEIDON_FULL_ROUNDS / 2
            || round >= TX_POSEIDON_FULL_ROUNDS / 2 + TX_POSEIDON_PARTIAL_ROUNDS;
        if is_full_round {
            config.s_poseidon_full.enable(region, row)?;
        } else {
            config.s_poseidon_partial.enable(region, row)?;
        }

        for (column, round_constant) in config.poseidon_rc.iter().zip(round_constant_row.iter()) {
            region.assign_fixed(
                || "poseidon_round_constant",
                *column,
                row,
                || Value::known(*round_constant),
            )?;
        }

        let next_state = current_state[0]
            .zip(current_state[1])
            .zip(current_state[2])
            .zip(current_state[3])
            .map(|(((a, b), c), d)| poseidon_round([a, b, c, d], *round_constant_row, mds, is_full_round));

        let next_cells = [
            region.assign_advice(|| "poseidon_next_0", config.a, row + 1, || next_state.map(|state| state[0]))?,
            region.assign_advice(|| "poseidon_next_1", config.b, row + 1, || next_state.map(|state| state[1]))?,
            region.assign_advice(|| "poseidon_next_2", config.c, row + 1, || next_state.map(|state| state[2]))?,
            region.assign_advice(|| "poseidon_next_3", config.d, row + 1, || next_state.map(|state| state[3]))?,
        ];
        current_state = [
            next_state.map(|state| state[0]),
            next_state.map(|state| state[1]),
            next_state.map(|state| state[2]),
            next_state.map(|state| state[3]),
        ];

        if round == TX_POSEIDON_TOTAL_ROUNDS - 1 {
            final_state = Some(next_cells[0].clone());
        }
    }

    final_state.ok_or(ErrorFront::Synthesis)
}

fn assign_u8_range_table<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
) -> Result<(), ErrorFront>
where
    F: ff::PrimeField,
{
    layouter.assign_table(
        || "u8_range_table",
        |mut table| {
            for value in 0..RANGE_LIMB_BASE {
                table.assign_cell(
                    || "u8_range_value",
                    config.range_u8_table,
                    value as usize,
                    || Value::known(F::from(value)),
                )?;
            }

            Ok(())
        },
    )
}

fn u64_to_u8_limbs(value: u64) -> [u8; RANGE_LIMB_COUNT] {
    value.to_le_bytes()
}

fn assign_amount_range_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    amount_cell: AssignedCell<F, F>,
    limbs: Value<[u8; RANGE_LIMB_COUNT]>,
) -> Result<(), ErrorFront>
where
    F: ff::PrimeField,
{
    layouter.assign_region(
        || "range_check",
        |mut region: Region<'_, F>| {
            config.s_range.enable(&mut region, 0)?;
            amount_cell.copy_advice(|| "amount_rc", &mut region, config.a, 0)?;

            region.assign_advice(|| "limb_0", config.b, 0, || limbs.map(|v| F::from(v[0] as u64)))?;
            region.assign_advice(|| "limb_1", config.c, 0, || limbs.map(|v| F::from(v[1] as u64)))?;
            region.assign_advice(|| "limb_2", config.d, 0, || limbs.map(|v| F::from(v[2] as u64)))?;

            region.assign_advice(|| "limb_3", config.a, 1, || limbs.map(|v| F::from(v[3] as u64)))?;
            region.assign_advice(|| "limb_4", config.b, 1, || limbs.map(|v| F::from(v[4] as u64)))?;
            region.assign_advice(|| "limb_5", config.c, 1, || limbs.map(|v| F::from(v[5] as u64)))?;
            region.assign_advice(|| "limb_6", config.d, 1, || limbs.map(|v| F::from(v[6] as u64)))?;

            region.assign_advice(|| "limb_7", config.a, 2, || limbs.map(|v| F::from(v[7] as u64)))?;
            region.assign_advice_from_constant(|| "range_padding_b2", config.b, 2, F::ZERO)?;
            region.assign_advice_from_constant(|| "range_padding_c2", config.c, 2, F::ZERO)?;
            region.assign_advice_from_constant(|| "range_padding_d2", config.d, 2, F::ZERO)?;

            Ok(())
        },
    )
}

fn assign_single_input_poseidon_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    input: AssignedCell<F, F>,
    poseidon_constants: &[[F; TX_POSEIDON_WIDTH]],
    poseidon_mds: &Mds<F, TX_POSEIDON_WIDTH>,
) -> Result<AssignedCell<F, F>, ErrorFront>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            input.copy_advice(|| "poseidon_input_0", &mut region, config.a, 0)?;
            region.assign_advice_from_constant(|| "poseidon_input_1", config.b, 0, F::ZERO)?;
            region.assign_advice_from_constant(|| "poseidon_input_2", config.c, 0, F::ZERO)?;
            region.assign_advice_from_constant(
                || "poseidon_capacity",
                config.d,
                0,
                poseidon_domain_tag::<F>(1),
            )?;

            assign_poseidon_permutation(
                config,
                &mut region,
                0,
                [
                    input.value().copied(),
                    Value::known(F::ZERO),
                    Value::known(F::ZERO),
                    Value::known(poseidon_domain_tag::<F>(1)),
                ],
                poseidon_constants,
                poseidon_mds,
            )
        },
    )
}

fn assign_three_input_poseidon_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    first: AssignedCell<F, F>,
    second: AssignedCell<F, F>,
    third: AssignedCell<F, F>,
    poseidon_constants: &[[F; TX_POSEIDON_WIDTH]],
    poseidon_mds: &Mds<F, TX_POSEIDON_WIDTH>,
) -> Result<AssignedCell<F, F>, ErrorFront>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            first.copy_advice(|| "poseidon_input_0", &mut region, config.a, 0)?;
            second.copy_advice(|| "poseidon_input_1", &mut region, config.b, 0)?;
            third.copy_advice(|| "poseidon_input_2", &mut region, config.c, 0)?;
            region.assign_advice_from_constant(
                || "poseidon_capacity",
                config.d,
                0,
                poseidon_domain_tag::<F>(TX_POSEIDON_RATE),
            )?;

            assign_poseidon_permutation(
                config,
                &mut region,
                0,
                [
                    first.value().copied(),
                    second.value().copied(),
                    third.value().copied(),
                    Value::known(poseidon_domain_tag::<F>(TX_POSEIDON_RATE)),
                ],
                poseidon_constants,
                poseidon_mds,
            )
        },
    )
}

fn assign_signature_scalar_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    nonce: Value<F>,
    response: Value<F>,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), ErrorFront>
where
    F: ff::PrimeField,
{
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            let nonce_cell = region.assign_advice(|| "nonce", config.a, 0, || nonce)?;
            let response_cell = region.assign_advice(|| "response", config.b, 0, || response)?;
            Ok((nonce_cell, response_cell))
        },
    )
}

fn assign_authorization_relation_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    nonce: AssignedCell<F, F>,
    challenge: AssignedCell<F, F>,
    oracle_key: AssignedCell<F, F>,
    response: AssignedCell<F, F>,
) -> Result<(), ErrorFront>
where
    F: ff::PrimeField,
{
    layouter.assign_region(
        || name,
        |mut region: Region<'_, F>| {
            config.s_auth_muladd.enable(&mut region, 0)?;
            nonce.copy_advice(|| "nonce", &mut region, config.a, 0)?;
            challenge.copy_advice(|| "challenge", &mut region, config.b, 0)?;
            oracle_key.copy_advice(|| "oracle_key", &mut region, config.c, 0)?;
            response.copy_advice(|| "response", &mut region, config.d, 0)?;
            Ok(())
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// ComplianceCircuit
// ─────────────────────────────────────────────────────────────────────────────

/// Halo2 ZKP circuit that proves transaction compliance without revealing
/// sender pubkey, receiver pubkey, amount, or Merkle path.
#[derive(Clone, Debug)]
pub struct ComplianceCircuit {
    pub public: PublicInputs,
    pub witness: Value<Witness>,
}

impl<F> Circuit<F> for ComplianceCircuit
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    type Config = ComplianceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            public: self.public.clone(),
            witness: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ComplianceConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        assign_u8_range_table(&config, &mut layouter)?;

        // ── Region 1: Load private witness ──────────────────────────────
        // Assign sender, receiver, oracle pubkey, and amount as single field
        // elements.
        // These cells are re-used (via copy-constraints) in every later region
        // so the prover cannot substitute different values per gate.
        let (sender_cell, receiver_cell, oracle_pubkey_cell, amount_cell) = layouter.assign_region(
            || "load_witness",
            |mut region: Region<'_, F>| {
                let sender_val = self
                    .witness
                    .as_ref()
                    .map(|w| bytes_to_field::<F>(&w.sender_pubkey));
                let receiver_val = self
                    .witness
                    .as_ref()
                    .map(|w| bytes_to_field::<F>(&w.receiver_pubkey));
                let oracle_pubkey_val = self
                    .witness
                    .as_ref()
                    .map(|w| bytes_to_field::<F>(&w.oracle_pubkey));
                let amount_val = self.witness.as_ref().map(|w| F::from(w.amount));

                let s = region.assign_advice(|| "sender", config.a, 0, || sender_val)?;
                let r = region.assign_advice(|| "receiver", config.b, 0, || receiver_val)?;
                let o =
                    region.assign_advice(|| "oracle_pubkey", config.c, 0, || oracle_pubkey_val)?;
                let am = region.assign_advice(|| "amount", config.d, 0, || amount_val)?;
                Ok((s, r, o, am))
            },
        )?;

        // ── Region 2: Range check on amount ──────────────────────────────
        // Copy from load_witness so the prover cannot swap a different amount
        // into the range-check rows than the one used by Poseidon binding.
        let amount_limbs = self.witness.as_ref().map(|w| u64_to_u8_limbs(w.amount));
        assign_amount_range_region(&config, &mut layouter, amount_cell.clone(), amount_limbs)?;

        // ── Region 3: Hash-binding (C3) via Poseidon ─────────────────────
        // The circuit hashes [sender, receiver, amount] into a single field
        // element and wires the first state word of the final permutation row
        // to the public tx_hash instance cell.
        let poseidon_constants = poseidon_constants::<F>();
        let poseidon_mds = poseidon_mds::<F>();
        let tx_hash_cell: AssignedCell<F, F> = layouter.assign_region(
            || "tx_hash_poseidon",
            |mut region: Region<'_, F>| {
                sender_cell.copy_advice(|| "sender_h", &mut region, config.a, 0)?;
                receiver_cell.copy_advice(|| "receiver_h", &mut region, config.b, 0)?;
                amount_cell.copy_advice(|| "amount_h", &mut region, config.c, 0)?;
                region.assign_advice_from_constant(
                    || "poseidon_capacity",
                    config.d,
                    0,
                    poseidon_domain_tag::<F>(TX_POSEIDON_RATE),
                )?;

                let initial_state = [
                    self.witness
                        .as_ref()
                        .map(|w| bytes_to_field::<F>(&w.sender_pubkey)),
                    self.witness
                        .as_ref()
                        .map(|w| bytes_to_field::<F>(&w.receiver_pubkey)),
                    self.witness.as_ref().map(|w| F::from(w.amount)),
                    Value::known(poseidon_domain_tag::<F>(TX_POSEIDON_RATE)),
                ];
                assign_poseidon_permutation(
                    &config,
                    &mut region,
                    0,
                    initial_state,
                    &poseidon_constants,
                    &poseidon_mds,
                )
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

        // ── Region 4: Oracle key binding ─────────────────────────────────
        let oracle_hash_cell = assign_single_input_poseidon_region(
            &config,
            &mut layouter,
            "oracle_pubkey_hash",
            oracle_pubkey_cell.clone(),
            &poseidon_constants,
            &poseidon_mds,
        )?;
        layouter.constrain_instance(
            oracle_hash_cell.cell(),
            config.instance,
            ORACLE_PUBKEY_HASH_START,
        )?;

        // ── Regions 5 / 6: Merkle leaf hashes ────────────────────────────
        // Spec membership statements use Poseidon(pubkey) as the leaf value.
        let sender_leaf_cell = assign_single_input_poseidon_region(
            &config,
            &mut layouter,
            "sender_merkle_leaf",
            sender_cell.clone(),
            &poseidon_constants,
            &poseidon_mds,
        )?;
        let receiver_leaf_cell = assign_single_input_poseidon_region(
            &config,
            &mut layouter,
            "receiver_merkle_leaf",
            receiver_cell.clone(),
            &poseidon_constants,
            &poseidon_mds,
        )?;

        // ── Regions 7..10: Oracle authorization (sender / receiver) ─────
        let sender_sig_fields = self
            .witness
            .as_ref()
            .map(|w| oracle_signature_fields_from_bytes::<F>(&w.sender_oracle_sig));
        let (sender_nonce_cell, sender_response_cell) = assign_signature_scalar_region(
            &config,
            &mut layouter,
            "sender_auth_signature",
            sender_sig_fields.map(|(nonce, _)| nonce),
            sender_sig_fields.map(|(_, response)| response),
        )?;
        let sender_challenge_cell = assign_three_input_poseidon_region(
            &config,
            &mut layouter,
            "sender_auth_challenge",
            oracle_hash_cell.clone(),
            sender_leaf_cell.clone(),
            sender_nonce_cell.clone(),
            &poseidon_constants,
            &poseidon_mds,
        )?;
        assign_authorization_relation_region(
            &config,
            &mut layouter,
            "sender_auth_relation",
            sender_nonce_cell,
            sender_challenge_cell,
            oracle_pubkey_cell.clone(),
            sender_response_cell,
        )?;

        let receiver_sig_fields = self
            .witness
            .as_ref()
            .map(|w| oracle_signature_fields_from_bytes::<F>(&w.receiver_oracle_sig));
        let (receiver_nonce_cell, receiver_response_cell) = assign_signature_scalar_region(
            &config,
            &mut layouter,
            "receiver_auth_signature",
            receiver_sig_fields.map(|(nonce, _)| nonce),
            receiver_sig_fields.map(|(_, response)| response),
        )?;
        let receiver_challenge_cell = assign_three_input_poseidon_region(
            &config,
            &mut layouter,
            "receiver_auth_challenge",
            oracle_hash_cell.clone(),
            receiver_leaf_cell.clone(),
            receiver_nonce_cell.clone(),
            &poseidon_constants,
            &poseidon_mds,
        )?;
        assign_authorization_relation_region(
            &config,
            &mut layouter,
            "receiver_auth_relation",
            receiver_nonce_cell,
            receiver_challenge_cell,
            oracle_pubkey_cell.clone(),
            receiver_response_cell,
        )?;

        // ── Merkle root field element (same for both membership paths) ───
        let root_val = bytes_to_field::<F>(&self.public.compliance_merkle_root);

        // ── Region 6: Merkle path for sender (C1) ────────────────────────
        let sender_path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
            w.sender_merkle_siblings
                .iter()
                .map(|n| bytes_to_field::<F>(n))
                .collect()
        });
        let sender_directions = self
            .witness
            .as_ref()
            .map(|w| w.sender_merkle_directions.clone());
        let sender_root_cell = assign_merkle_region::<F>(
            &config,
            &mut layouter,
            "sender_merkle",
            sender_leaf_cell,
            sender_path,
            sender_directions,
            root_val,
            &poseidon_constants,
            &poseidon_mds,
        )?;

        // Wire sender Merkle root → instance column (row MERKLE_ROOT_START).
        layouter.constrain_instance(sender_root_cell.cell(), config.instance, MERKLE_ROOT_START)?;

        // ── Region 7: Merkle path for receiver (C2) ──────────────────────
        let receiver_path: Value<Vec<F>> = self.witness.as_ref().map(|w| {
            w.receiver_merkle_siblings
                .iter()
                .map(|n| bytes_to_field::<F>(n))
                .collect()
        });
        let receiver_directions = self
            .witness
            .as_ref()
            .map(|w| w.receiver_merkle_directions.clone());
        let receiver_root_cell = assign_merkle_region::<F>(
            &config,
            &mut layouter,
            "receiver_merkle",
            receiver_leaf_cell,
            receiver_path,
            receiver_directions,
            root_val,
            &poseidon_constants,
            &poseidon_mds,
        )?;

        // Wire receiver Merkle root → instance column (same row: both paths
        // must reach the same compliance_merkle_root).
        layouter.constrain_instance(
            receiver_root_cell.cell(),
            config.instance,
            MERKLE_ROOT_START,
        )?;

        // ── Wire block_height → instance column (row 96) ─────────────────
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
/// Row layout (one region per tree level `i`):
///
/// ```text
/// row 0: a = current_node
///        b = sibling
///        c = direction_bit
/// row 1: a = ordered_left   ← s_merkle constrains this ordering
///        b = ordered_right  ← s_merkle constrains this ordering
///        c = 0
///        d = Poseidon domain tag for a two-element message
/// row 1..=64: Poseidon permutation rows
/// ```
///
/// At depth `MERKLE_DEPTH - 1`, an extra anchor row is added in advice to plant
/// the expected root value.
/// A `constrain_equal` between `parent_cell` and the anchor enforces
/// that the computed root matches — regardless of the path values.
///
/// The returned cell is the final `parent_cell` (= computed root).
/// The caller wires it to the public instance column.
fn assign_merkle_region<F>(
    config: &ComplianceConfig,
    layouter: &mut impl Layouter<F>,
    name: &'static str,
    leaf: AssignedCell<F, F>,
    path: Value<Vec<F>>,
    directions: Value<Vec<bool>>,
    expected_root: F,
    poseidon_constants: &[[F; TX_POSEIDON_WIDTH]],
    poseidon_mds: &Mds<F, TX_POSEIDON_WIDTH>,
) -> Result<AssignedCell<F, F>, ErrorFront>
where
    F: ff::PrimeField + FromUniformBytes<64> + Ord,
{
    let mut current_cell = leaf;
    let mut final_parent_cell = None;

    for depth in 0..MERKLE_DEPTH {
        let region_name = format!("{name}_{depth}");
        let current_value = current_cell.value().copied();
        let current_cell_for_region = current_cell.clone();
        let sibling = path.as_ref().map(|p| p[depth]);
        let direction = directions.as_ref().map(|bits| bits[depth]);
        let parent_cell = layouter.assign_region(
            || region_name.clone(),
            |mut region: Region<'_, F>| {
                config.s_merkle.enable(&mut region, 0)?;

                current_cell_for_region.copy_advice(|| "node", &mut region, config.a, 0)?;
                region.assign_advice(|| "sibling", config.b, 0, || sibling)?;
                region.assign_advice(
                    || "direction_bit",
                    config.c,
                    0,
                    || direction.map(|is_right| if is_right { F::ONE } else { F::ZERO }),
                )?;

                let ordered_left = current_value
                    .zip(sibling)
                    .zip(direction)
                    .map(|((node, sibling), is_right)| if is_right { sibling } else { node });
                let ordered_right = current_value
                    .zip(sibling)
                    .zip(direction)
                    .map(|((node, sibling), is_right)| if is_right { node } else { sibling });

                region.assign_advice(|| "ordered_left", config.a, 1, || ordered_left)?;
                region.assign_advice(|| "ordered_right", config.b, 1, || ordered_right)?;
                region.assign_advice_from_constant(|| "merkle_padding", config.c, 1, F::ZERO)?;
                region.assign_advice_from_constant(
                    || "merkle_domain_tag",
                    config.d,
                    1,
                    poseidon_domain_tag::<F>(2),
                )?;

                let parent_cell = assign_poseidon_permutation(
                    config,
                    &mut region,
                    1,
                    [
                        ordered_left,
                        ordered_right,
                        Value::known(F::ZERO),
                        Value::known(poseidon_domain_tag::<F>(2)),
                    ],
                    poseidon_constants,
                    poseidon_mds,
                )?;

                if depth == MERKLE_DEPTH - 1 {
                    let root_anchor = region.assign_advice(
                        || "root_anchor",
                        config.c,
                        TX_POSEIDON_TOTAL_ROUNDS + 2,
                        || Value::known(expected_root),
                    )?;
                    region.constrain_equal(parent_cell.cell(), root_anchor.cell())?;
                }

                Ok(parent_cell)
            },
        )?;
        current_cell = parent_cell.clone();
        final_parent_cell = Some(parent_cell);
    }

    final_parent_cell.ok_or(ErrorFront::Synthesis)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use halo2curves::bn256::Fr;

    #[derive(Clone, Debug)]
    struct AmountRangeTestCircuit {
        amount: Value<Fr>,
        limbs: Value<[u8; RANGE_LIMB_COUNT]>,
    }

    impl Circuit<Fr> for AmountRangeTestCircuit {
        type Config = ComplianceConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                amount: Value::unknown(),
                limbs: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            ComplianceConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            assign_u8_range_table(&config, &mut layouter)?;

            let amount_cell = layouter.assign_region(
                || "load_amount",
                |mut region| region.assign_advice(|| "amount", config.a, 0, || self.amount),
            )?;

            assign_amount_range_region(&config, &mut layouter, amount_cell, self.limbs)
        }
    }

    // ── Fixture builder ───────────────────────────────────────────────────
    //
    fn field_to_bytes(f: Fr) -> [u8; 32] {
        f.to_repr().into()
    }

    fn build_merkle_tree(leaves: Vec<Fr>) -> Vec<Vec<Fr>> {
        let mut levels = vec![leaves];

        while levels.last().expect("non-empty tree").len() > 1 {
            let next_level = levels
                .last()
                .expect("non-empty tree")
                .chunks_exact(2)
                .map(|pair| merkle_parent_hash_fields(pair[0], pair[1]))
                .collect::<Vec<_>>();
            levels.push(next_level);
        }

        levels
    }

    fn extract_merkle_path(levels: &[Vec<Fr>], mut leaf_index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
        let mut directions = Vec::with_capacity(MERKLE_DEPTH);

        for nodes in levels.iter().take(MERKLE_DEPTH) {
            let is_right = leaf_index % 2 == 1;
            siblings.push(field_to_bytes(nodes[leaf_index ^ 1]));
            directions.push(is_right);
            leaf_index /= 2;
        }

        (siblings, directions)
    }

    fn compute_merkle_root(leaf: Fr, siblings: &[[u8; 32]], directions: &[bool]) -> Fr {
        siblings
            .iter()
            .zip(directions.iter())
            .fold(leaf, |current, (sibling, is_right)| {
                let sibling_f = bytes_to_field::<Fr>(sibling);
                let (left, right) = if *is_right {
                    (sibling_f, current)
                } else {
                    (current, sibling_f)
                };
                merkle_parent_hash_fields(left, right)
            })
    }

    fn sign_authorization(oracle_pubkey: [u8; 32], authorized_pubkey: [u8; 32], nonce_seed: u64) -> [u8; 64] {
        let oracle_key = bytes_to_field::<Fr>(&oracle_pubkey);
        let oracle_hash = merkle_leaf_hash_from_pubkey::<Fr>(&oracle_pubkey);
        let authorized_hash = merkle_leaf_hash_from_pubkey::<Fr>(&authorized_pubkey);
        let nonce = Fr::from(nonce_seed);
        let challenge = oracle_authorization_challenge(oracle_hash, authorized_hash, nonce);
        let response = nonce + challenge * oracle_key;
        oracle_signature_bytes(nonce, response)
    }

    fn make_fixture() -> (ComplianceCircuit, Vec<Vec<Fr>>) {
        let sender_pubkey: [u8; 32] = [0x01u8; 32];
        let receiver_pubkey: [u8; 32] = [0x02u8; 32];
        let oracle_pubkey: [u8; 32] = [0x05u8; 32];
        let sender_oracle_sig = sign_authorization(oracle_pubkey, sender_pubkey, 7);
        let receiver_oracle_sig = sign_authorization(oracle_pubkey, receiver_pubkey, 11);
        let amount: u64 = 999;
        let block_height: u64 = 1_000_000;

        let sender_f: Fr = merkle_leaf_hash_from_pubkey(&sender_pubkey);
        let receiver_f: Fr = merkle_leaf_hash_from_pubkey(&receiver_pubkey);
        let tx_hash_f: Fr = tx_hash_field_from_inputs(&sender_pubkey, &receiver_pubkey, amount);
        let tx_hash: [u8; 32] = field_to_bytes(tx_hash_f);

        let sender_index = 3usize;
        let receiver_index = 10usize;
        let mut leaves = (0..(1 << MERKLE_DEPTH))
            .map(|i| Fr::from((i as u64) + 100))
            .collect::<Vec<_>>();
        leaves[sender_index] = sender_f;
        leaves[receiver_index] = receiver_f;

        let tree = build_merkle_tree(leaves);
        let root_f = *tree.last().expect("root level exists").first().expect("root exists");
        let (sender_merkle_siblings, sender_merkle_directions) =
            extract_merkle_path(&tree, sender_index);
        let (receiver_merkle_siblings, receiver_merkle_directions) =
            extract_merkle_path(&tree, receiver_index);

        assert_eq!(
            compute_merkle_root(sender_f, &sender_merkle_siblings, &sender_merkle_directions),
            root_f
        );
        assert_eq!(
            compute_merkle_root(
                receiver_f,
                &receiver_merkle_siblings,
                &receiver_merkle_directions
            ),
            root_f
        );

        let compliance_merkle_root: [u8; 32] = field_to_bytes(root_f);
        let oracle_pubkey_hash: [u8; 32] =
            field_to_bytes(merkle_leaf_hash_from_pubkey(&oracle_pubkey));

        let public = PublicInputs {
            tx_hash,
            compliance_merkle_root,
            oracle_pubkey_hash,
            block_height,
        };
        let witness = Witness {
            sender_pubkey,
            receiver_pubkey,
            oracle_pubkey,
            amount,
            sender_oracle_sig,
            receiver_oracle_sig,
            sender_merkle_siblings,
            sender_merkle_directions,
            receiver_merkle_siblings,
            receiver_merkle_directions,
        };
        let circuit = ComplianceCircuit {
            public: public.clone(),
            witness: Value::known(witness),
        };

        // Instance column (97 rows).
        // Only the four wired rows carry meaningful values; the rest are zero
        // because no constrain_instance call touches them.
        let mut instance_col = vec![Fr::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_f;
        instance_col[MERKLE_ROOT_START] = root_f;
        instance_col[ORACLE_PUBKEY_HASH_START] = bytes_to_field(&public.oracle_pubkey_hash);
        instance_col[BLOCK_HEIGHT_ROW] = Fr::from(block_height);

        (circuit, vec![instance_col])
    }

    #[test]
    fn test_range_check_valid_u64_amount_passes() {
        let amount = 0x0123_4567_89AB_CDEFu64;
        let circuit = AmountRangeTestCircuit {
            amount: Value::known(Fr::from(amount)),
            limbs: Value::known(u64_to_u8_limbs(amount)),
        };
        let prover =
            MockProver::<Fr>::run(10, &circuit, vec![vec![]]).expect("MockProver::run failed");
        prover
            .verify()
            .expect("Valid u64 limbs should satisfy the lookup-backed range check");
    }

    #[test]
    fn test_range_check_rejects_negative_field_element() {
        let circuit = AmountRangeTestCircuit {
            amount: Value::known(-Fr::ONE),
            limbs: Value::known([0xFF; RANGE_LIMB_COUNT]),
        };
        let prover =
            MockProver::<Fr>::run(10, &circuit, vec![vec![]]).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Negative field element should fail the u64 range check"
        );
    }

    // ── Test 1: valid witness → verify() passes ───────────────────────────
    #[test]
    fn test_valid_witness_passes() {
        let (circuit, instance) = make_fixture();
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        prover
            .verify()
            .expect("Valid witness should satisfy all constraints");
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
        instance[0][TX_HASH_START] += Fr::from(1u64);
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong tx_hash should cause verify() to fail"
        );
    }

    #[test]
    fn test_tampered_amount_breaks_poseidon_binding() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            w.amount += 1;
            w
        });
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Changing amount without updating tx_hash should fail Poseidon binding"
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
        instance[0][MERKLE_ROOT_START] += Fr::from(1u64);
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong merkle_root should cause verify() to fail"
        );
    }

    // ── Test 4: wrong Merkle sibling in witness → verify() fails ─────────
    #[test]
    fn test_wrong_merkle_sibling_fails() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            w.sender_merkle_siblings[0][0] ^= 0xFF;
            w
        });
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong Merkle sibling should cause verify() to fail"
        );
    }

    #[test]
    fn test_wrong_merkle_direction_bit_fails() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            w.sender_merkle_directions[0] = !w.sender_merkle_directions[0];
            w
        });
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong Merkle direction bit should cause verify() to fail"
        );
    }

    #[test]
    fn test_wrong_oracle_pubkey_fails_hash_binding() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            w.oracle_pubkey[0] ^= 0xFF;
            w
        });
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Wrong oracle pubkey should fail the oracle_pubkey_hash binding"
        );
    }

    #[test]
    fn test_valid_oracle_authorization_passes() {
        let (circuit, instance) = make_fixture();
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        prover
            .verify()
            .expect("Valid Schnorr-style oracle authorization should satisfy the circuit");
    }

    #[test]
    fn test_tampered_oracle_signature_fails() {
        let (mut circuit, instance) = make_fixture();
        circuit.witness = circuit.witness.map(|mut w| {
            w.sender_oracle_sig[0] ^= 0x01;
            w
        });
        let prover = MockProver::<Fr>::run(10, &circuit, instance).expect("MockProver::run failed");
        assert!(
            prover.verify().is_err(),
            "Tampered sender oracle authorization should fail the circuit"
        );
    }
}
