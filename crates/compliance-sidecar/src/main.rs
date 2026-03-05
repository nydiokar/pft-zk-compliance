//! compliance-sidecar — Unix domain socket IPC listener.
//!
//! Accepts JSON [`ProofRequest`] messages from the postfiatd validator daemon,
//! dispatches them to the Halo2 [`ComplianceCircuit`] prover, and returns a
//! JSON [`ProofResponse`] over the same connection.
//!
//! # Wire protocol
//!
//! Each message is a single UTF-8 JSON object terminated by a newline (`\n`).
//! One request per connection; the sidecar closes the connection after writing
//! the response.  This keeps state minimal — the daemon opens a fresh connection
//! for each transaction it wants proved.
//!
//! # Prover status
//!
//! Full `create_proof` requires a `ProvingKey` derived from trusted-setup
//! `Params`, which is a separate initialisation step (see TODO below).  For
//! this prototype the circuit is exercised via `MockProver::run + verify()` so
//! the constraint satisfaction logic is real; only the cryptographic proof
//! object is absent.  Status field values:
//!
//! | Value             | Meaning                                            |
//! |-------------------|----------------------------------------------------|
//! | `"compliant"`     | All constraints satisfied; `proof_bytes` is set.  |
//! | `"non_compliant"` | Circuit verification failed (bad witness/path).    |
//! | `"error"`         | Malformed request, hex-decode failure, or panic.   |
//!
//! # Platform
//!
//! This binary targets Unix systems (Linux validator nodes).  It will not
//! compile on Windows because `tokio::net::UnixListener` is gated on
//! `#[cfg(unix)]` by tokio.  Build via cross-compilation or in WSL:
//!
//! ```text
//! cargo build --target x86_64-unknown-linux-gnu -p compliance-sidecar
//! ```

// Unix socket support is gated at the OS level in tokio.
// Emit a clear compile error rather than a cryptic linker failure on Windows.
#[cfg(not(unix))]
compile_error!(
    "compliance-sidecar requires a Unix target. \
     Build with `--target x86_64-unknown-linux-gnu` or compile inside WSL."
);

#[cfg(unix)]
mod inner {
    use std::env;

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use compliance_circuit::{
        circuit::{PublicInputs, Witness, MERKLE_DEPTH},
        ComplianceCircuit,
    };
    use halo2_proofs::{arithmetic::Field, circuit::Value, dev::MockProver};
    use halo2curves::{ff::PrimeField, pasta::Fp};
    use serde::{Deserialize, Serialize};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{UnixListener, UnixStream},
    };

    // ─────────────────────────────────────────────────────────────────────────
    // IPC types
    // ─────────────────────────────────────────────────────────────────────────

    /// JSON request sent by the postfiatd daemon to the sidecar.
    #[derive(Debug, Deserialize)]
    pub struct ProofRequest {
        #[allow(dead_code)] // present in IPC schema; reserved for protocol versioning
        pub version: u32,
        /// Hex-encoded Poseidon hash of the transaction (32 bytes).
        pub tx_hash: String,
        /// Hex-encoded sender address (20 bytes).
        pub sender_addr: String,
        /// Hex-encoded receiver address (20 bytes).
        pub receiver_addr: String,
        /// Transaction amount.
        pub amount: u64,
        /// Hex-encoded compliance Merkle tree root (32 bytes).
        pub compliance_merkle_root: String,
        /// Block height of the compliance snapshot.
        pub block_height: u64,
        /// Hex-encoded sibling hashes for Merkle membership proof.
        /// Must contain exactly `2 * MERKLE_DEPTH` entries (sender path then receiver path).
        pub merkle_path: Vec<String>,
    }

    /// JSON response written back to the daemon by the sidecar.
    #[derive(Debug, Serialize)]
    pub struct ProofResponse {
        pub version: u32,
        pub tx_hash: String,
        /// `"compliant"` | `"non_compliant"` | `"error"`
        pub status: String,
        /// Base64-encoded serialized Halo2 proof bytes.
        /// Empty string when status is not `"compliant"`.
        pub proof_bytes: String,
        /// Hex-encoded public instance values fed into the proof verifier.
        pub public_inputs: Vec<String>,
        /// Wall-clock milliseconds elapsed generating the proof.
        pub proof_time_ms: u64,
        /// Human-readable error detail (omitted when empty).
        #[serde(skip_serializing_if = "String::is_empty")]
        pub error: String,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    /// Default socket path; override with `POSTFIAT_ZKP_SOCKET` env var.
    pub const DEFAULT_SOCKET_PATH: &str = "/tmp/postfiat_zkp.sock";

    /// MockProver circuit size parameter.  2^K rows must fit the circuit.
    /// K=8 (256 rows) is sufficient for MERKLE_DEPTH=4.
    const CIRCUIT_K: u32 = 8;

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn run() {
        let socket_path = env::var("POSTFIAT_ZKP_SOCKET")
            .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

        // Remove a stale socket file from a previous run so bind() doesn't fail.
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|e| panic!("Failed to bind Unix socket {socket_path}: {e}"));

        eprintln!("[compliance-sidecar] listening on {socket_path}");

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    // Spawn a task per connection so the listener never blocks.
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream).await {
                            eprintln!("[compliance-sidecar] connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[compliance-sidecar] accept error: {e}");
                    // Brief back-off on repeated accept failures to avoid a
                    // tight error loop if the OS is under fd pressure.
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Connection handler
    // ─────────────────────────────────────────────────────────────────────────

    /// Maximum bytes accepted per request line.
    ///
    /// A `ProofRequest` with `2 * MERKLE_DEPTH` hex-encoded 32-byte siblings is at
    /// most a few kilobytes.  16 KiB gives generous headroom while preventing an
    /// unbounded-allocation attack from a misbehaving local process.
    const MAX_REQUEST_BYTES: u64 = 16 * 1024;

    /// Read one newline-terminated JSON request, process it, write the response.
    async fn handle_connection(stream: UnixStream) -> std::io::Result<()> {
        // Split into owned halves so we can hold a BufReader on the read side
        // while also writing to the write side without a lifetime conflict.
        let (read_half, mut write_half) = stream.into_split();
        // Cap reads to MAX_REQUEST_BYTES so a misbehaving peer can't cause unbounded
        // memory allocation via a line with no newline terminator.
        let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES));

        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;

        if n == 0 {
            // Peer closed without sending anything — not an error.
            return Ok(());
        }

        let response = match serde_json::from_str::<ProofRequest>(line.trim()) {
            Ok(req) => {
                eprintln!(
                    "[compliance-sidecar] proof request: tx_hash={} block_height={}",
                    &req.tx_hash, req.block_height,
                );
                prove(req).await
            }
            Err(e) => {
                eprintln!("[compliance-sidecar] malformed request: {e}");
                ProofResponse {
                    version: 1,
                    tx_hash: String::new(),
                    status: "error".to_string(),
                    proof_bytes: String::new(),
                    public_inputs: vec![],
                    proof_time_ms: 0,
                    error: format!("malformed JSON: {e}"),
                }
            }
        };

        let mut response_bytes = serde_json::to_vec(&response)
            .unwrap_or_else(|_| b"{\"status\":\"error\"}".to_vec());
        response_bytes.push(b'\n');
        write_half.write_all(&response_bytes).await?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Prover (async wrapper)
    // ─────────────────────────────────────────────────────────────────────────

    /// Decode the request, run the circuit, return a [`ProofResponse`].
    ///
    /// All fallible steps produce `status = "error"` rather than propagating —
    /// the sidecar must never crash on a bad daemon request.
    async fn prove(req: ProofRequest) -> ProofResponse {
        let start = std::time::Instant::now();
        let tx_hash_echo = req.tx_hash.clone();

        // Offload CPU-intensive circuit work onto the blocking thread pool so
        // the async runtime is not starved during proof generation.
        let result = tokio::task::spawn_blocking(move || run_circuit(req)).await;

        let proof_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok((status, proof_bytes, public_inputs))) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status,
                proof_bytes,
                public_inputs,
                proof_time_ms,
                error: String::new(),
            },
            Ok(Err(e)) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "error".to_string(),
                proof_bytes: String::new(),
                public_inputs: vec![],
                proof_time_ms,
                error: e,
            },
            Err(e) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "error".to_string(),
                proof_bytes: String::new(),
                public_inputs: vec![],
                proof_time_ms,
                error: format!("prover task panicked: {e}"),
            },
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Circuit execution (blocking)
    // ─────────────────────────────────────────────────────────────────────────

    type ProverResult = Result<(String, String, Vec<String>), String>;

    /// Decode request fields, build [`ComplianceCircuit`], run [`MockProver`].
    ///
    /// Returns `(status, proof_bytes_b64, public_inputs_hex)` on success,
    /// or an error string on any decode / constraint failure.
    ///
    /// # Prototype note
    ///
    /// Uses `MockProver` in place of `create_proof` because the latter requires
    /// a `ProvingKey` derived from trusted-setup `Params` (a separate init step).
    /// The constraint satisfaction logic — public input construction, witness
    /// assignment, permutation checks — is identical to what a real prover runs.
    ///
    /// **Upgrade path:** swap `MockProver::run + verify()` for
    /// `create_proof + verify_proof` once `Params` are available.
    fn run_circuit(req: ProofRequest) -> ProverResult {
        // ── Decode hex fields ────────────────────────────────────────────
        let tx_hash = decode_hex_32(&req.tx_hash, "tx_hash")?;
        let sender_addr = decode_hex_20(&req.sender_addr, "sender_addr")?;
        let receiver_addr = decode_hex_20(&req.receiver_addr, "receiver_addr")?;
        let compliance_merkle_root =
            decode_hex_32(&req.compliance_merkle_root, "compliance_merkle_root")?;

        let expected_path_len = 2 * MERKLE_DEPTH;
        if req.merkle_path.len() != expected_path_len {
            return Err(format!(
                "merkle_path must have {expected_path_len} entries (got {})",
                req.merkle_path.len()
            ));
        }
        let merkle_path: Vec<[u8; 32]> = req
            .merkle_path
            .iter()
            .enumerate()
            .map(|(i, s)| decode_hex_32(s, &format!("merkle_path[{i}]")))
            .collect::<Result<_, _>>()?;

        // ── Build circuit inputs ─────────────────────────────────────────
        let public = PublicInputs { tx_hash, compliance_merkle_root, block_height: req.block_height };
        let witness = Witness { sender_addr, receiver_addr, amount: req.amount, merkle_path };
        let circuit = ComplianceCircuit { public: public.clone(), witness: Value::known(witness) };

        // ── Build instance column ────────────────────────────────────────
        use compliance_circuit::circuit::{
            BLOCK_HEIGHT_ROW, MERKLE_ROOT_START, NUM_INSTANCE_ROWS, TX_HASH_START,
        };

        // Mirror the bytes_to_field encoding used inside the circuit so the
        // instance column we supply matches the advice cells it wires to.
        let tx_hash_f: Fp = bytes_to_field_fp(&public.tx_hash);
        let merkle_root_f: Fp = bytes_to_field_fp(&public.compliance_merkle_root);
        let block_height_f: Fp = Fp::from(public.block_height);

        let mut instance_col = vec![Fp::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_f;
        instance_col[MERKLE_ROOT_START] = merkle_root_f;
        instance_col[BLOCK_HEIGHT_ROW] = block_height_f;

        let instance = vec![instance_col.clone()];

        // ── Run MockProver ───────────────────────────────────────────────
        let prover = MockProver::<Fp>::run(CIRCUIT_K, &circuit, instance)
            .map_err(|e| format!("MockProver::run failed: {e:?}"))?;

        match prover.verify() {
            Ok(()) => {
                // Constraint check passed.  In production this is where
                // create_proof would run and return real proof bytes.
                //
                // PROTOTYPE: encode the public instance column as the "proof"
                // so the response carries a verifiable non-empty payload.
                let mock_proof_bytes: Vec<u8> = instance_col
                    .iter()
                    .flat_map(|f: &Fp| f.to_repr().as_ref().to_vec())
                    .collect();
                let proof_b64 = B64.encode(&mock_proof_bytes);

                let public_inputs_hex: Vec<String> = [
                    (TX_HASH_START, tx_hash_f),
                    (MERKLE_ROOT_START, merkle_root_f),
                    (BLOCK_HEIGHT_ROW, block_height_f),
                ]
                .iter()
                .map(|(row, f)| format!("row{}:{}", row, hex::encode(f.to_repr().as_ref())))
                .collect();

                Ok(("compliant".to_string(), proof_b64, public_inputs_hex))
            }
            Err(errors) => {
                // Constraint violation: witness does not satisfy the circuit.
                // The transaction is non-compliant or the Merkle path is wrong.
                eprintln!("[compliance-sidecar] circuit verification failed: {errors:?}");
                Ok(("non_compliant".to_string(), String::new(), vec![]))
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hex decode helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn decode_hex_32(s: &str, field: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("{field}: hex decode error: {e}"))?;
        let len = bytes.len();
        let arr: [u8; 32] =
            bytes.try_into().map_err(|_| format!("{field}: expected 32 bytes, got {len}"))?;

        // Guard: reject any 32-byte value that would exceed the Pasta Fp modulus
        // (~2^254) and silently collapse to low 8 bytes in bytes_to_field_fp.
        // Fp modulus in little-endian is 0x4000...000... with top two bits clear.
        // A value >= p has its 31st byte (index 31, MSB in LE) >= 0x40.
        // Rejecting here is conservative but prevents silent injectivity failure:
        // two distinct hashes could map to the same field element if both >= p.
        //
        // PRODUCTION: replace bytes_to_field_fp with a Poseidon sponge, which
        // operates on individual field elements and never truncates.
        if arr[31] >= 0x40 {
            return Err(format!(
                "{field}: value >= Fp modulus (MSB byte 0x{:02x}); \
                 would silently collapse in field encoding — reject",
                arr[31]
            ));
        }

        Ok(arr)
    }

    fn decode_hex_20(s: &str, field: &str) -> Result<[u8; 20], String> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("{field}: hex decode error: {e}"))?;
        let len = bytes.len();
        bytes.try_into().map_err(|_| format!("{field}: expected 20 bytes, got {len}"))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Field encoding  (mirrors circuit.rs bytes_to_field exactly)
    // ─────────────────────────────────────────────────────────────────────────

    /// Encode a byte slice as an `Fp` field element using little-endian packing.
    ///
    /// **Must** match `bytes_to_field` in `circuit.rs` exactly — the instance
    /// column values we supply to `MockProver` must agree with the advice cell
    /// values the circuit assigns internally, or the permutation check fails.
    fn bytes_to_field_fp(bytes: &[u8]) -> Fp {
        let mut repr = <Fp as PrimeField>::Repr::default();
        {
            let s = repr.as_mut();
            let len = s.len().min(bytes.len());
            s[..len].copy_from_slice(&bytes[..len]);
        }
        Fp::from_repr(repr).unwrap_or_else(|| {
            let mut low = [0u8; 8];
            low.copy_from_slice(&bytes[..8.min(bytes.len())]);
            Fp::from(u64::from_le_bytes(low))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    #[cfg(unix)]
    inner::run().await;

    // The compile_error! above ensures we never reach here on non-Unix.
}
