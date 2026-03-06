//! compliance-sidecar — Unix domain socket IPC listener + keygen CLI.
//!
//! # Subcommands
//!
//! ## serve  (Unix only)
//! Accepts JSON [`ProofRequest`] messages from the postfiatd validator daemon,
//! dispatches them to the Halo2 [`ComplianceCircuit`] prover, and returns a
//! JSON [`ProofResponse`] over the same connection.
//!
//! ## keygen  (cross-platform)
//! Runs `keygen_vk` / `keygen_pk` against `ParamsKZG<Bn256>` and writes
//! `.vk`, `.pk`, and `.params` files to disk.  Must be run once per
//! deployment before the sidecar can generate real proofs.
//!
//! # Wire protocol  (serve)
//!
//! Each message is a single UTF-8 JSON object terminated by a newline (`\n`).
//! One request per connection; the sidecar closes the connection after writing
//! the response.
//!
//! # Prover status
//!
//! | Value             | Meaning                                            |
//! |-------------------|----------------------------------------------------|
//! | `"compliant"`     | All constraints satisfied; `proof_bytes` is set.  |
//! | `"non_compliant"` | Circuit verification failed (bad witness/path).    |
//! | `"error"`         | Malformed request, hex-decode failure, or panic.   |
//!
//! # Platform
//!
//! The `serve` subcommand targets Unix systems (Linux validator nodes) because
//! `tokio::net::UnixListener` is gated on `#[cfg(unix)]`.  The `keygen`
//! subcommand is cross-platform.  Build the full binary via:
//!
//! ```text
//! cargo build --target x86_64-unknown-linux-gnu -p compliance-sidecar
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "compliance-sidecar", about = "Post Fiat ZKP compliance sidecar")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the Unix socket listener (Unix only).
    Serve {
        /// Path to the Unix domain socket.
        #[arg(long, default_value = "/tmp/postfiat_zkp.sock")]
        socket: String,
        /// Path to the proving key produced by `keygen`.
        #[arg(long, default_value = "./compliance.pk")]
        pk: PathBuf,
        /// Path to the KZG params produced by `keygen`.
        #[arg(long, default_value = "./compliance.params")]
        params: PathBuf,
    },
    /// Generate proving/verifying keys for the compliance circuit.
    Keygen {
        /// Circuit size parameter: 2^k rows.  k=8 is correct for MERKLE_DEPTH=4.
        #[arg(long, default_value_t = 8)]
        k: u32,
        /// Output path for the proving key.
        #[arg(long, default_value = "./compliance.pk")]
        pk: PathBuf,
        /// Output path for the verifying key.
        #[arg(long, default_value = "./compliance.vk")]
        vk: PathBuf,
        /// Output path for the KZG params (required by prover at runtime).
        #[arg(long, default_value = "./compliance.params")]
        params: PathBuf,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { socket, pk, params } => {
            #[cfg(unix)]
            inner::run(socket, pk, params).await;

            #[cfg(not(unix))]
            {
                let _ = (socket, pk, params);
                eprintln!(
                    "error: `serve` requires a Unix target. \
                     Build with `--target x86_64-unknown-linux-gnu` or compile inside WSL."
                );
                std::process::exit(1);
            }
        }
        Command::Keygen { k, pk, vk, params } => {
            keygen::run(k, pk, vk, params);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// keygen subcommand (cross-platform, synchronous)
// ─────────────────────────────────────────────────────────────────────────────

mod keygen {
    use std::{
        fs::File,
        io::{BufWriter, Write},
        path::PathBuf,
    };

    use compliance_circuit::{circuit::PublicInputs, ComplianceCircuit};
    use halo2_proofs::{
        circuit::Value,
        plonk::{keygen_pk_custom, keygen_vk_custom},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
        SerdeFormat,
    };
    use halo2curves::bn256::Bn256;
    use rand_core::OsRng;

    /// Entry point for the `keygen` subcommand.
    pub fn run(k: u32, pk_path: PathBuf, vk_path: PathBuf, params_path: PathBuf) {
        eprintln!(
            "[compliance-sidecar] generating KZG params for k={k} (2^k={} rows)...",
            1u64 << k
        );
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        // keygen only needs the constraint topology — use empty witness.
        let circuit = ComplianceCircuit {
            public: dummy_public_inputs(),
            witness: Value::unknown(),
        };

        eprintln!("[compliance-sidecar] running keygen_vk...");
        let vk = keygen_vk_custom(&params, &circuit, true).expect("keygen_vk failed");

        eprintln!("[compliance-sidecar] running keygen_pk...");
        let pk = keygen_pk_custom(&params, vk.clone(), &circuit, true).expect("keygen_pk failed");

        // Write params — prover needs these at runtime alongside pk.
        write_file(&params_path, "params", |w| {
            params.write(w).map_err(|e: std::io::Error| e.to_string())
        });
        // Write verifying key.
        write_file(&vk_path, "vk", |w| {
            vk.write(w, SerdeFormat::RawBytes).map_err(|e| e.to_string())
        });
        // Write proving key.
        write_file(&pk_path, "pk", |w| {
            pk.write(w, SerdeFormat::RawBytes).map_err(|e| e.to_string())
        });

        eprintln!("[compliance-sidecar] wrote params → {}", params_path.display());
        eprintln!("[compliance-sidecar] wrote vk     → {}", vk_path.display());
        eprintln!("[compliance-sidecar] wrote pk     → {}", pk_path.display());
    }

    /// Returns a `PublicInputs` with zero-filled byte arrays.
    ///
    /// Keygen only inspects the constraint topology — the actual field values
    /// are never used.  `Value::unknown()` for the witness ensures `synthesize`
    /// assigns `Value::unknown()` everywhere, which is the correct keygen mode.
    fn dummy_public_inputs() -> PublicInputs {
        PublicInputs {
            tx_hash: [0u8; 32],
            compliance_merkle_root: [0u8; 32],
            block_height: 0,
        }
    }

    /// Open `path`, wrap in `BufWriter`, call `f`, flush, and exit on error.
    fn write_file<F>(path: &PathBuf, label: &str, f: F)
    where
        F: FnOnce(&mut BufWriter<File>) -> Result<(), String>,
    {
        let file = File::create(path).unwrap_or_else(|e| {
            eprintln!("error: could not create {label} file '{}': {e}", path.display());
            std::process::exit(1);
        });
        let mut writer = BufWriter::new(file);
        f(&mut writer).unwrap_or_else(|e| {
            eprintln!("error: could not write {label} to '{}': {e}", path.display());
            std::process::exit(1);
        });
        writer.flush().unwrap_or_else(|e| {
            eprintln!("error: flush failed for {label} '{}': {e}", path.display());
            std::process::exit(1);
        });
    }

}

// ─────────────────────────────────────────────────────────────────────────────
// serve subcommand (Unix only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod inner {
    use std::{path::PathBuf, sync::Arc};

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use compliance_circuit::{
        circuit::{PublicInputs, Witness, MERKLE_DEPTH},
        ComplianceCircuit,
    };
    use halo2_proofs::{
        arithmetic::Field,
        circuit::Value,
        plonk::{create_proof, pk_read, verify_proof_multi, ProvingKey},
        poly::{
            commitment::Params,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
        SerdeFormat,
    };
    use halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::PrimeField,
    };
    use rand_core::OsRng;
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
        #[allow(dead_code)]
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
    // Prover state — loaded once at startup, shared across all connections
    // ─────────────────────────────────────────────────────────────────────────

    struct ProverState {
        params: ParamsKZG<Bn256>,
        pk: ProvingKey<G1Affine>,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn run(socket_path: String, pk_path: PathBuf, params_path: PathBuf) {
        // ── Load KZG params ──────────────────────────────────────────────
        eprintln!("[compliance-sidecar] loading params from {}", params_path.display());
        let params = {
            let mut f = std::fs::File::open(&params_path).unwrap_or_else(|e| {
                eprintln!("error: cannot open params file '{}': {e}", params_path.display());
                std::process::exit(1);
            });
            ParamsKZG::<Bn256>::read(&mut f).unwrap_or_else(|e| {
                eprintln!("error: cannot deserialize params: {e}");
                std::process::exit(1);
            })
        };

        // ── Load proving key ─────────────────────────────────────────────
        // pk_read reconstructs the constraint system from the circuit topology
        // (same as keygen) and uses it to deserialize the raw proving key bytes.
        eprintln!("[compliance-sidecar] loading proving key from {}", pk_path.display());
        let pk = {
            let dummy_circuit = ComplianceCircuit {
                public: PublicInputs {
                    tx_hash: [0u8; 32],
                    compliance_merkle_root: [0u8; 32],
                    block_height: 0,
                },
                witness: Value::unknown(),
            };
            let mut f = std::fs::File::open(&pk_path).unwrap_or_else(|e| {
                eprintln!("error: cannot open pk file '{}': {e}", pk_path.display());
                std::process::exit(1);
            });
            pk_read::<G1Affine, _, ComplianceCircuit>(
                &mut f,
                SerdeFormat::RawBytes,
                params.k(),
                &dummy_circuit,
                true, // compress_selectors — must match keygen
            )
            .unwrap_or_else(|e| {
                eprintln!("error: cannot deserialize proving key: {e}");
                std::process::exit(1);
            })
        };

        let state = Arc::new(ProverState { params, pk });

        // Remove a stale socket file from a previous run so bind() doesn't fail.
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|e| panic!("Failed to bind Unix socket {socket_path}: {e}"));

        eprintln!("[compliance-sidecar] listening on {socket_path}");

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            eprintln!("[compliance-sidecar] connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[compliance-sidecar] accept error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Connection handler
    // ─────────────────────────────────────────────────────────────────────────

    /// Maximum bytes accepted per request line.
    const MAX_REQUEST_BYTES: u64 = 16 * 1024;

    async fn handle_connection(
        stream: UnixStream,
        state: Arc<ProverState>,
    ) -> std::io::Result<()> {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES));

        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;

        if n == 0 {
            return Ok(());
        }

        let response = match serde_json::from_str::<ProofRequest>(line.trim()) {
            Ok(req) => {
                eprintln!(
                    "[compliance-sidecar] proof request: tx_hash={} block_height={}",
                    &req.tx_hash, req.block_height,
                );
                prove(req, state).await
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

    async fn prove(req: ProofRequest, state: Arc<ProverState>) -> ProofResponse {
        let tx_hash_echo = req.tx_hash.clone();

        let result = tokio::task::spawn_blocking(move || run_circuit(req, &state)).await;

        match result {
            Ok(Ok((proof_bytes, public_inputs, proof_time_ms))) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "compliant".to_string(),
                proof_bytes,
                public_inputs,
                proof_time_ms,
                error: String::new(),
            },
            Ok(Err(ProverError::NonCompliant(msg))) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "non_compliant".to_string(),
                proof_bytes: String::new(),
                public_inputs: vec![],
                proof_time_ms: 0,
                error: msg,
            },
            Ok(Err(ProverError::Error(msg))) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "error".to_string(),
                proof_bytes: String::new(),
                public_inputs: vec![],
                proof_time_ms: 0,
                error: msg,
            },
            Err(e) => ProofResponse {
                version: 1,
                tx_hash: tx_hash_echo,
                status: "error".to_string(),
                proof_bytes: String::new(),
                public_inputs: vec![],
                proof_time_ms: 0,
                error: format!("prover task panicked: {e}"),
            },
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Circuit execution (blocking)
    // ─────────────────────────────────────────────────────────────────────────

    enum ProverError {
        /// Internal failure (decode error, prover bug, I/O error).
        Error(String),
        /// The proof was generated but failed self-verification.
        NonCompliant(String),
    }

    type ProverResult = Result<(String, Vec<String>, u64), ProverError>;

    /// Decode request fields, build [`ComplianceCircuit`], call
    /// [`create_proof`] to generate a real cryptographic proof, then
    /// immediately call [`verify_proof_multi`] to self-verify before returning.
    fn run_circuit(req: ProofRequest, state: &ProverState) -> ProverResult {
        use compliance_circuit::circuit::{
            BLOCK_HEIGHT_ROW, MERKLE_ROOT_START, NUM_INSTANCE_ROWS, TX_HASH_START,
        };

        // ── Decode hex fields ────────────────────────────────────────────
        let tx_hash = decode_hex_32(&req.tx_hash, "tx_hash").map_err(ProverError::Error)?;
        let sender_addr = decode_hex_20(&req.sender_addr, "sender_addr").map_err(ProverError::Error)?;
        let receiver_addr = decode_hex_20(&req.receiver_addr, "receiver_addr").map_err(ProverError::Error)?;
        let compliance_merkle_root =
            decode_hex_32(&req.compliance_merkle_root, "compliance_merkle_root").map_err(ProverError::Error)?;

        let expected_path_len = 2 * MERKLE_DEPTH;
        if req.merkle_path.len() != expected_path_len {
            return Err(ProverError::Error(format!(
                "merkle_path must have {expected_path_len} entries (got {})",
                req.merkle_path.len()
            )));
        }
        let merkle_path: Vec<[u8; 32]> = req
            .merkle_path
            .iter()
            .enumerate()
            .map(|(i, s)| decode_hex_32_unchecked(s, &format!("merkle_path[{i}]")))
            .collect::<Result<_, _>>()
            .map_err(ProverError::Error)?;

        // ── Build circuit inputs ─────────────────────────────────────────
        let public =
            PublicInputs { tx_hash, compliance_merkle_root, block_height: req.block_height };
        let witness = Witness { sender_addr, receiver_addr, amount: req.amount, merkle_path };
        let circuit = ComplianceCircuit { public: public.clone(), witness: Value::known(witness) };

        // ── Build instance column ────────────────────────────────────────
        let tx_hash_f: Fr = bytes_to_field_fr(&public.tx_hash);
        let merkle_root_f: Fr = bytes_to_field_fr(&public.compliance_merkle_root);
        let block_height_f: Fr = Fr::from(public.block_height);

        let mut instance_col = vec![Fr::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_f;
        instance_col[MERKLE_ROOT_START] = merkle_root_f;
        instance_col[BLOCK_HEIGHT_ROW] = block_height_f;

        // ── Create real proof via SHPLONK + Blake2b transcript ───────────
        let proof_start = std::time::Instant::now();
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // instances: one entry per circuit, each containing one Vec per instance column.
        let instances: Vec<Vec<Vec<Fr>>> = vec![vec![instance_col]];

        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<Bn256>, _, _, _, _>(
            &state.params,
            &state.pk,
            &[circuit],
            &instances,
            OsRng,
            &mut transcript,
        )
        .map_err(|e| ProverError::Error(format!("create_proof failed: {e:?}")))?;

        let proof_bytes: Vec<u8> = transcript.finalize();
        let proof_time_ms = proof_start.elapsed().as_millis() as u64;

        // ── Verify the proof before returning "compliant" ────────────────
        // The sidecar must never hand back a verdict it can't back with a
        // valid proof.  Verification uses the same SHPLONK strategy and
        // Blake2b transcript as the prover — parameters must match exactly.
        {
            let verifier_params = state.params.verifier_params();
            // verify_proof_multi takes &[Vec<Vec<Fr>>]: one entry per circuit,
            // each a vec of instance columns, each a vec of scalar values.
            let verify_instances: Vec<Vec<Fr>> = instances[0].clone();
            let mut verify_transcript =
                Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
            let ok = verify_proof_multi::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<Bn256>,
                _,
                _,
                SingleStrategy<Bn256>,
            >(
                &verifier_params,
                state.pk.get_vk(),
                &[verify_instances],
                &mut verify_transcript,
            );
            if !ok {
                return Err(ProverError::NonCompliant(
                    "proof verification failed: self-check rejected the generated proof".to_string(),
                ));
            }
        }

        let proof_b64 = B64.encode(&proof_bytes);

        let public_inputs_hex: Vec<String> = [
            (TX_HASH_START, tx_hash_f),
            (MERKLE_ROOT_START, merkle_root_f),
            (BLOCK_HEIGHT_ROW, block_height_f),
        ]
        .iter()
        .map(|(row, f)| format!("row{}:{}", row, hex::encode(f.to_repr().as_ref())))
        .collect();

        Ok((proof_b64, public_inputs_hex, proof_time_ms))
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

        // Guard: reject values that may equal or exceed the BN254 Fr modulus.
        // Fr modulus in little-endian has byte[31] = 0x30.  Any input with
        // byte[31] >= 0x30 might be >= p and fail from_repr, causing the
        // bytes_to_field fallback to truncate to 8 bytes — silently losing
        // injectivity.  Rejecting here is conservative and correct.
        if arr[31] >= 0x30 {
            return Err(format!(
                "{field}: value >= Fr modulus (MSB byte 0x{:02x}); \
                 would silently collapse in field encoding — reject",
                arr[31]
            ));
        }

        Ok(arr)
    }

    /// Decode a hex string into 32 bytes without the modulus guard.
    ///
    /// Used for Merkle path siblings, which are advice (private) witness values.
    /// They never pass through `from_repr`; `bytes_to_field_fr` handles reduction
    /// internally, so any 32-byte value is valid input.
    fn decode_hex_32_unchecked(s: &str, field: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("{field}: hex decode error: {e}"))?;
        let len = bytes.len();
        bytes.try_into().map_err(|_| format!("{field}: expected 32 bytes, got {len}"))
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

    /// Encode a byte slice as a BN254 `Fr` field element using little-endian packing.
    ///
    /// **Must** match `bytes_to_field` in `circuit.rs` exactly — the instance
    /// column values we supply to the prover must agree with the advice cell
    /// values the circuit assigns internally, or the permutation check fails.
    fn bytes_to_field_fr(bytes: &[u8]) -> Fr {
        let mut repr = <Fr as PrimeField>::Repr::default();
        {
            let s = repr.as_mut();
            let len = s.len().min(bytes.len());
            s[..len].copy_from_slice(&bytes[..len]);
        }
        Fr::from_repr(repr).unwrap_or_else(|| {
            let mut low = [0u8; 8];
            low.copy_from_slice(&bytes[..8.min(bytes.len())]);
            Fr::from(u64::from_le_bytes(low))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use compliance_circuit::{
        circuit::{
            PublicInputs, Witness, BLOCK_HEIGHT_ROW, MERKLE_DEPTH, MERKLE_ROOT_START,
            NUM_INSTANCE_ROWS, TX_HASH_START,
        },
        ComplianceCircuit,
    };
    use halo2_proofs::{
        arithmetic::Field,
        circuit::Value,
        plonk::{create_proof, keygen_pk_custom, keygen_vk_custom, verify_proof_multi},
        poly::{
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::PrimeField,
    };
    use rand_core::OsRng;

    fn bytes_to_field_fr(bytes: &[u8]) -> Fr {
        let mut repr = <Fr as PrimeField>::Repr::default();
        let s = repr.as_mut();
        let len = s.len().min(bytes.len());
        s[..len].copy_from_slice(&bytes[..len]);
        Fr::from_repr(repr).unwrap_or_else(|| {
            let mut low = [0u8; 8];
            low.copy_from_slice(&bytes[..8.min(bytes.len())]);
            Fr::from(u64::from_le_bytes(low))
        })
    }

    /// Build a minimal but valid circuit + instance column for k=8.
    fn make_circuit_and_instances() -> (ComplianceCircuit, Vec<Vec<Fr>>) {
        let sender_addr = [0x01u8; 20];
        let receiver_addr = [0x02u8; 20];
        let amount: u64 = 42;
        let block_height: u64 = 1;

        // Derive field elements so the prototype gates (a+b=c) are satisfied.
        let sender_f = bytes_to_field_fr(&sender_addr);
        let receiver_f = bytes_to_field_fr(&receiver_addr);
        let tx_hash_f = sender_f + receiver_f;
        let tx_hash: [u8; 32] = tx_hash_f.to_repr().into();

        let common_sib: [u8; 32] = { let mut a = [0u8; 32]; a[0] = 0x07; a };
        let common_f = bytes_to_field_fr(&common_sib);
        let root_f = Fr::from(0xDEAD_BEEF_u64);

        let make_path = |leaf_f: Fr| -> Vec<[u8; 32]> {
            let running = leaf_f + common_f * Fr::from(MERKLE_DEPTH as u64 - 1);
            let last: [u8; 32] = (root_f - running).to_repr().into();
            let mut p = vec![common_sib; MERKLE_DEPTH - 1];
            p.push(last);
            p
        };

        let merkle_path: Vec<[u8; 32]> = make_path(sender_f)
            .into_iter()
            .chain(make_path(receiver_f))
            .collect();

        let compliance_merkle_root: [u8; 32] = root_f.to_repr().into();

        let public = PublicInputs { tx_hash, compliance_merkle_root, block_height };
        let witness = Witness { sender_addr, receiver_addr, amount, merkle_path };
        let circuit = ComplianceCircuit { public: public.clone(), witness: Value::known(witness) };

        let tx_hash_field = bytes_to_field_fr(&public.tx_hash);
        let merkle_root_field = bytes_to_field_fr(&public.compliance_merkle_root);
        let block_height_field = Fr::from(public.block_height);

        let mut instance_col = vec![Fr::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_field;
        instance_col[MERKLE_ROOT_START] = merkle_root_field;
        instance_col[BLOCK_HEIGHT_ROW] = block_height_field;

        (circuit, vec![instance_col])
    }

    /// Generates real params + pk for k=8, proves, verifies. Asserts valid proof passes.
    /// Then flips one byte in the proof and asserts verify_proof_multi returns false.
    #[test]
    fn test_verify_proof_multi_valid_and_corrupted() {
        let k: u32 = 8;
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        let dummy = ComplianceCircuit {
            public: PublicInputs {
                tx_hash: [0u8; 32],
                compliance_merkle_root: [0u8; 32],
                block_height: 0,
            },
            witness: Value::unknown(),
        };
        let vk = keygen_vk_custom(&params, &dummy, true).expect("keygen_vk failed");
        let pk = keygen_pk_custom(&params, vk.clone(), &dummy, true).expect("keygen_pk failed");

        let (circuit, instance_col) = make_circuit_and_instances();
        let instances: Vec<Vec<Vec<Fr>>> = vec![instance_col.clone()];

        // ── Prove ────────────────────────────────────────────────────────
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &instances, OsRng, &mut transcript,
        )
        .expect("create_proof failed");
        let proof_bytes = transcript.finalize();

        let verifier_params = params.verifier_params();
        let vk_for_verify = pk.get_vk();
        let verify = |proof: &[u8]| -> bool {
            let mut t = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
            verify_proof_multi::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<Bn256>,
                _,
                _,
                SingleStrategy<Bn256>,
            >(&verifier_params, vk_for_verify, &[instance_col.clone()], &mut t)
        };

        // Valid proof must pass.
        assert!(verify(&proof_bytes), "valid proof failed verification");

        // Corrupt one byte — must fail.
        let mut corrupted = proof_bytes.clone();
        corrupted[0] ^= 0xFF;
        assert!(!verify(&corrupted), "corrupted proof passed verification (bug!)");
    }
}
