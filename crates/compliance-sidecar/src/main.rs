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
//! | `"error"`         | Malformed request, schema validation failure, or panic.   |
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
#[command(
    name = "compliance-sidecar",
    about = "Post Fiat ZKP compliance sidecar"
)]
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
            vk.write(w, SerdeFormat::RawBytes)
                .map_err(|e| e.to_string())
        });
        // Write proving key.
        write_file(&pk_path, "pk", |w| {
            pk.write(w, SerdeFormat::RawBytes)
                .map_err(|e| e.to_string())
        });

        eprintln!(
            "[compliance-sidecar] wrote params → {}",
            params_path.display()
        );
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
            oracle_pubkey_hash: [0u8; 32],
            block_height: 0,
        }
    }

    /// Open `path`, wrap in `BufWriter`, call `f`, flush, and exit on error.
    fn write_file<F>(path: &PathBuf, label: &str, f: F)
    where
        F: FnOnce(&mut BufWriter<File>) -> Result<(), String>,
    {
        let file = File::create(path).unwrap_or_else(|e| {
            eprintln!(
                "error: could not create {label} file '{}': {e}",
                path.display()
            );
            std::process::exit(1);
        });
        let mut writer = BufWriter::new(file);
        f(&mut writer).unwrap_or_else(|e| {
            eprintln!(
                "error: could not write {label} to '{}': {e}",
                path.display()
            );
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
        circuit::{
            canonical_oracle_pubkey_from_bytes, canonical_schnorr_signature_from_bytes,
            merkle_leaf_hash_from_pubkey, oracle_authorization_limb_witness, CanonicalOraclePubkey,
            CanonicalSchnorrSignature, OracleAuthorizationLimbWitness, PublicInputs, Witness,
            MERKLE_DEPTH,
        },
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
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
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
    #[serde(deny_unknown_fields)]
    pub(crate) struct ProofRequest {
        #[allow(dead_code)]
        pub version: u32,
        /// Hex-encoded Poseidon hash of the transaction (32 bytes).
        pub tx_hash: String,
        /// Hex-encoded sender XRPL ed25519 pubkey (32 bytes).
        pub sender_pubkey: String,
        /// Hex-encoded receiver XRPL ed25519 pubkey (32 bytes).
        pub receiver_pubkey: String,
        /// Transaction amount.
        pub amount: u64,
        /// Hex-encoded canonical Schnorr signature over `Poseidon(sender_pubkey)`
        /// as compressed `R` point (32 bytes) || scalar `s` (32 bytes).
        pub sender_oracle_sig: String,
        /// Hex-encoded canonical Schnorr signature over `Poseidon(receiver_pubkey)`
        /// as compressed `R` point (32 bytes) || scalar `s` (32 bytes).
        pub receiver_oracle_sig: String,
        /// Hex-encoded compressed canonical Pallas oracle public key (32 bytes).
        pub oracle_pubkey: String,
        /// Hex-encoded compliance Merkle tree root (32 bytes).
        pub compliance_merkle_root: String,
        /// Hex-encoded Poseidon hash of the active oracle pubkey (32 bytes).
        pub oracle_pubkey_hash: String,
        /// Block height of the compliance snapshot.
        pub block_height: u64,
        /// Hex-encoded sender Merkle sibling hashes.
        /// Must contain exactly `MERKLE_DEPTH` entries.
        pub sender_merkle_siblings: Vec<String>,
        /// Sender per-level direction bits. `false` means current node is left.
        pub sender_merkle_directions: Vec<bool>,
        /// Hex-encoded receiver Merkle sibling hashes.
        /// Must contain exactly `MERKLE_DEPTH` entries.
        pub receiver_merkle_siblings: Vec<String>,
        /// Receiver per-level direction bits. `false` means current node is left.
        pub receiver_merkle_directions: Vec<bool>,
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

    #[derive(Debug)]
    pub(crate) struct NormalizedProofRequest {
        pub(crate) tx_hash: [u8; 32],
        pub(crate) sender_pubkey: [u8; 32],
        pub(crate) receiver_pubkey: [u8; 32],
        pub(crate) amount: u64,
        pub(crate) sender_oracle_sig: CanonicalSchnorrSignature,
        pub(crate) receiver_oracle_sig: CanonicalSchnorrSignature,
        pub(crate) oracle_pubkey: CanonicalOraclePubkey,
        pub(crate) sender_authorization_limbs: OracleAuthorizationLimbWitness,
        pub(crate) receiver_authorization_limbs: OracleAuthorizationLimbWitness,
        pub(crate) compliance_merkle_root: [u8; 32],
        pub(crate) oracle_pubkey_hash: [u8; 32],
        pub(crate) block_height: u64,
        pub(crate) sender_merkle_siblings: Vec<[u8; 32]>,
        pub(crate) sender_merkle_directions: Vec<bool>,
        pub(crate) receiver_merkle_siblings: Vec<[u8; 32]>,
        pub(crate) receiver_merkle_directions: Vec<bool>,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn run(socket_path: String, pk_path: PathBuf, params_path: PathBuf) {
        // ── Load KZG params ──────────────────────────────────────────────
        eprintln!(
            "[compliance-sidecar] loading params from {}",
            params_path.display()
        );
        let params = {
            let mut f = std::fs::File::open(&params_path).unwrap_or_else(|e| {
                eprintln!(
                    "error: cannot open params file '{}': {e}",
                    params_path.display()
                );
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
        eprintln!(
            "[compliance-sidecar] loading proving key from {}",
            pk_path.display()
        );
        let pk = {
            let dummy_circuit = ComplianceCircuit {
                public: PublicInputs {
                    tx_hash: [0u8; 32],
                    compliance_merkle_root: [0u8; 32],
                    oracle_pubkey_hash: [0u8; 32],
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

    async fn handle_connection(stream: UnixStream, state: Arc<ProverState>) -> std::io::Result<()> {
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

        let mut response_bytes =
            serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"status\":\"error\"}".to_vec());
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
            BLOCK_HEIGHT_ROW, MERKLE_ROOT_START, NUM_INSTANCE_ROWS, ORACLE_PUBKEY_HASH_START,
            TX_HASH_START,
        };

        let req = normalize_request(req).map_err(ProverError::Error)?;

        // ── Build circuit inputs ─────────────────────────────────────────
        let public = PublicInputs {
            tx_hash: req.tx_hash,
            compliance_merkle_root: req.compliance_merkle_root,
            oracle_pubkey_hash: req.oracle_pubkey_hash,
            block_height: req.block_height,
        };
        let witness = Witness {
            sender_pubkey: req.sender_pubkey,
            receiver_pubkey: req.receiver_pubkey,
            amount: req.amount,
            sender_oracle_sig: req.sender_oracle_sig.to_bytes(),
            receiver_oracle_sig: req.receiver_oracle_sig.to_bytes(),
            oracle_pubkey: req.oracle_pubkey.to_bytes(),
            sender_merkle_siblings: req.sender_merkle_siblings,
            sender_merkle_directions: req.sender_merkle_directions,
            receiver_merkle_siblings: req.receiver_merkle_siblings,
            receiver_merkle_directions: req.receiver_merkle_directions,
        };
        let circuit = ComplianceCircuit {
            public: public.clone(),
            witness: Value::known(witness),
        };

        // ── Build instance column ────────────────────────────────────────
        let tx_hash_f: Fr = bytes_to_field_fr(&public.tx_hash);
        let merkle_root_f: Fr = bytes_to_field_fr(&public.compliance_merkle_root);
        let oracle_hash_f: Fr = bytes_to_field_fr(&public.oracle_pubkey_hash);
        let block_height_f: Fr = Fr::from(public.block_height);

        let mut instance_col = vec![Fr::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_f;
        instance_col[MERKLE_ROOT_START] = merkle_root_f;
        instance_col[ORACLE_PUBKEY_HASH_START] = oracle_hash_f;
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
                    "proof verification failed: self-check rejected the generated proof"
                        .to_string(),
                ));
            }
        }

        let proof_b64 = B64.encode(&proof_bytes);

        let public_inputs_hex: Vec<String> = [
            (TX_HASH_START, tx_hash_f),
            (MERKLE_ROOT_START, merkle_root_f),
            (ORACLE_PUBKEY_HASH_START, oracle_hash_f),
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

    pub(crate) fn normalize_request(req: ProofRequest) -> Result<NormalizedProofRequest, String> {
        let tx_hash = decode_hex_32(&req.tx_hash, "tx_hash")?;
        let sender_pubkey = decode_hex_32(&req.sender_pubkey, "sender_pubkey")?;
        let receiver_pubkey = decode_hex_32(&req.receiver_pubkey, "receiver_pubkey")?;
        let sender_oracle_sig =
            decode_oracle_signature(&req.sender_oracle_sig, "sender_oracle_sig")?;
        let receiver_oracle_sig =
            decode_oracle_signature(&req.receiver_oracle_sig, "receiver_oracle_sig")?;
        let oracle_pubkey = decode_oracle_pubkey(&req.oracle_pubkey, "oracle_pubkey")?;
        let compliance_merkle_root =
            decode_hex_32(&req.compliance_merkle_root, "compliance_merkle_root")?;
        let oracle_pubkey_hash = decode_hex_32(&req.oracle_pubkey_hash, "oracle_pubkey_hash")?;
        let expected_oracle_pubkey_hash =
            merkle_leaf_hash_from_pubkey::<Fr>(&oracle_pubkey.to_bytes()).to_repr();
        if expected_oracle_pubkey_hash.as_ref() != oracle_pubkey_hash {
            return Err(
                "oracle_pubkey_hash does not match canonical oracle_pubkey encoding".to_string(),
            );
        }

        if req.sender_merkle_siblings.len() != MERKLE_DEPTH {
            return Err(format!(
                "sender_merkle_siblings must have {MERKLE_DEPTH} entries (got {})",
                req.sender_merkle_siblings.len()
            ));
        }
        if req.sender_merkle_directions.len() != MERKLE_DEPTH {
            return Err(format!(
                "sender_merkle_directions must have {MERKLE_DEPTH} entries (got {})",
                req.sender_merkle_directions.len()
            ));
        }
        if req.receiver_merkle_siblings.len() != MERKLE_DEPTH {
            return Err(format!(
                "receiver_merkle_siblings must have {MERKLE_DEPTH} entries (got {})",
                req.receiver_merkle_siblings.len()
            ));
        }
        if req.receiver_merkle_directions.len() != MERKLE_DEPTH {
            return Err(format!(
                "receiver_merkle_directions must have {MERKLE_DEPTH} entries (got {})",
                req.receiver_merkle_directions.len()
            ));
        }

        let sender_merkle_siblings = req
            .sender_merkle_siblings
            .iter()
            .enumerate()
            .map(|(i, s)| decode_hex_32_unchecked(s, &format!("sender_merkle_siblings[{i}]")))
            .collect::<Result<_, _>>()?;
        let receiver_merkle_siblings = req
            .receiver_merkle_siblings
            .iter()
            .enumerate()
            .map(|(i, s)| decode_hex_32_unchecked(s, &format!("receiver_merkle_siblings[{i}]")))
            .collect::<Result<_, _>>()?;
        let sender_authorization_limbs =
            oracle_authorization_limb_witness(&oracle_pubkey, &sender_oracle_sig, &sender_pubkey)
                .map_err(|e| format!("sender authorization limbs: {e}"))?;
        let receiver_authorization_limbs = oracle_authorization_limb_witness(
            &oracle_pubkey,
            &receiver_oracle_sig,
            &receiver_pubkey,
        )
        .map_err(|e| format!("receiver authorization limbs: {e}"))?;

        Ok(NormalizedProofRequest {
            tx_hash,
            sender_pubkey,
            receiver_pubkey,
            amount: req.amount,
            sender_oracle_sig,
            receiver_oracle_sig,
            oracle_pubkey,
            sender_authorization_limbs,
            receiver_authorization_limbs,
            compliance_merkle_root,
            oracle_pubkey_hash,
            block_height: req.block_height,
            sender_merkle_siblings,
            sender_merkle_directions: req.sender_merkle_directions,
            receiver_merkle_siblings,
            receiver_merkle_directions: req.receiver_merkle_directions,
        })
    }

    fn decode_hex_32(s: &str, field: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("{field}: hex decode error: {e}"))?;
        let len = bytes.len();
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{field}: expected 32 bytes, got {len}"))?;

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

    fn decode_oracle_pubkey(s: &str, field: &str) -> Result<CanonicalOraclePubkey, String> {
        let bytes = decode_hex_32_unchecked(s, field)?;
        canonical_oracle_pubkey_from_bytes(bytes)
    }

    fn decode_oracle_signature(s: &str, field: &str) -> Result<CanonicalSchnorrSignature, String> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("{field}: hex decode error: {e}"))?;
        let len = bytes.len();
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| format!("{field}: expected 64 bytes, got {len}"))?;
        canonical_schnorr_signature_from_bytes(arr).map_err(|e| format!("{field}: {e}"))
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
        bytes
            .try_into()
            .map_err(|_| format!("{field}: expected 32 bytes, got {len}"))
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

#[cfg(all(test, unix))]
mod tests {
    use super::inner::{normalize_request, ProofRequest};
    use compliance_circuit::{
        circuit::{
            merkle_leaf_hash_from_pubkey, merkle_parent_hash_fields,
            oracle_authorization_challenge_scalar_from_witness, oracle_authorization_limb_witness,
            oracle_authorization_message_bytes, tx_hash_field_from_inputs, PublicInputs, Witness,
            BLOCK_HEIGHT_ROW, MERKLE_DEPTH, MERKLE_ROOT_START, NUM_INSTANCE_ROWS,
            ORACLE_PUBKEY_HASH_START, TX_HASH_START,
        },
        ComplianceCircuit,
    };
    use halo2_proofs::{
        arithmetic::Field,
        circuit::Value,
        plonk::{create_proof, keygen_pk_custom, keygen_vk_custom, verify_proof_multi},
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::PrimeField,
    };
    use pasta_curves::{
        group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding},
        pallas,
    };
    use rand_core::OsRng;
    use serde_json::json;

    const ZK15C_REFERENCE_ORACLE_PUBKEY_HEX: &str =
        "badd5cdf47e39611a21e3526e80cbb9394a5926a48b824103fa85469fb3b4218";
    const ZK15C_REFERENCE_SIGNATURE_HEX: &str =
        "f96bd719329a1a817d9e010f103dfd699b0a3026c819400da04061d929fdbf01df5b73d6a737a615f6a52da918efa8e0293a5477bf0e47e851d54fb9e6576917";
    const ZK15C_REFERENCE_MESSAGE_BYTES_HEX: &str =
        "f0502835e5a787a3e37eafb84008c62412da623a82591778f9a3d202f9da530b";

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

    fn fits_bn254_witness_encoding(bytes: [u8; 32]) -> bool {
        Fr::from_repr(bytes.into()).into_option().is_some()
    }

    fn find_bn254_incompatible_pallas_point() -> [u8; 32] {
        for scalar in 1u64..10_000 {
            let encoded = (pallas::Point::generator() * pallas::Scalar::from(scalar))
                .to_affine()
                .to_bytes();
            if !fits_bn254_witness_encoding(encoded) {
                return encoded;
            }
        }

        panic!("expected to find a Pallas point that does not fit BN254 witness encoding");
    }

    fn find_bn254_compatible_pallas_point(start_scalar: u64) -> [u8; 32] {
        for scalar in start_scalar..start_scalar + 10_000 {
            let encoded = (pallas::Point::generator() * pallas::Scalar::from(scalar))
                .to_affine()
                .to_bytes();
            if fits_bn254_witness_encoding(encoded) {
                return encoded;
            }
        }

        panic!("expected to find a Pallas point that fits BN254 witness encoding");
    }

    fn field_to_bytes(f: Fr) -> [u8; 32] {
        f.to_repr().into()
    }

    fn binary_merkle_parent(left: Fr, right: Fr) -> Fr {
        merkle_parent_hash_fields(left, right)
    }

    fn build_merkle_tree(leaves: Vec<Fr>) -> Vec<Vec<Fr>> {
        let mut levels = vec![leaves];

        while levels.last().expect("non-empty tree").len() > 1 {
            let next_level = levels
                .last()
                .expect("non-empty tree")
                .chunks_exact(2)
                .map(|pair| binary_merkle_parent(pair[0], pair[1]))
                .collect::<Vec<_>>();
            levels.push(next_level);
        }

        levels
    }

    fn extract_merkle_path(
        levels: &[Vec<Fr>],
        mut leaf_index: usize,
    ) -> (Vec<[u8; 32]>, Vec<bool>) {
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

    fn sign_authorization(
        oracle_pubkey: [u8; 32],
        authorized_pubkey: [u8; 32],
        nonce_seed: u64,
    ) -> [u8; 64] {
        let encoded_r = find_bn254_compatible_pallas_point(nonce_seed);
        let encoded_r_field = bytes_to_field_fr(&encoded_r);
        let oracle_key = bytes_to_field_fr(&oracle_pubkey);
        let oracle_hash = merkle_leaf_hash_from_pubkey::<Fr>(&oracle_pubkey);
        let authorized_hash = merkle_leaf_hash_from_pubkey::<Fr>(&authorized_pubkey);
        let challenge = compliance_circuit::circuit::oracle_authorization_staged_challenge(
            oracle_hash,
            authorized_hash,
            encoded_r_field,
        );
        let response = encoded_r_field + challenge * oracle_key;

        let mut encoded = [0u8; 64];
        encoded[..32].copy_from_slice(&encoded_r);
        encoded[32..].copy_from_slice(response.to_repr().as_ref());
        encoded
    }

    /// Build a minimal but valid circuit + instance column for k=10.
    fn make_circuit_and_instances() -> (ComplianceCircuit, Vec<Vec<Fr>>) {
        let sender_pubkey = [0x01u8; 32];
        let receiver_pubkey = [0x02u8; 32];
        let oracle_pubkey = find_bn254_compatible_pallas_point(17);
        let sender_oracle_sig = sign_authorization(oracle_pubkey, sender_pubkey, 7);
        let receiver_oracle_sig = sign_authorization(oracle_pubkey, receiver_pubkey, 11);
        let amount: u64 = 42;
        let block_height: u64 = 1;

        let sender_f = merkle_leaf_hash_from_pubkey::<Fr>(&sender_pubkey);
        let receiver_f = merkle_leaf_hash_from_pubkey::<Fr>(&receiver_pubkey);
        let tx_hash_f = tx_hash_field_from_inputs::<Fr>(&sender_pubkey, &receiver_pubkey, amount);
        let tx_hash: [u8; 32] = tx_hash_f.to_repr().into();

        let sender_index = 3usize;
        let receiver_index = 10usize;
        let mut leaves = (0..(1 << MERKLE_DEPTH))
            .map(|i| Fr::from((i as u64) + 100))
            .collect::<Vec<_>>();
        leaves[sender_index] = sender_f;
        leaves[receiver_index] = receiver_f;
        let tree = build_merkle_tree(leaves);
        let root_f = *tree
            .last()
            .expect("root exists")
            .first()
            .expect("root element exists");
        let (sender_merkle_siblings, sender_merkle_directions) =
            extract_merkle_path(&tree, sender_index);
        let (receiver_merkle_siblings, receiver_merkle_directions) =
            extract_merkle_path(&tree, receiver_index);

        let compliance_merkle_root: [u8; 32] = root_f.to_repr().into();
        let oracle_pubkey_hash: [u8; 32] = merkle_leaf_hash_from_pubkey::<Fr>(&oracle_pubkey)
            .to_repr()
            .into();

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

        let tx_hash_field = bytes_to_field_fr(&public.tx_hash);
        let merkle_root_field = bytes_to_field_fr(&public.compliance_merkle_root);
        let oracle_hash_field = bytes_to_field_fr(&public.oracle_pubkey_hash);
        let block_height_field = Fr::from(public.block_height);

        let mut instance_col = vec![Fr::ZERO; NUM_INSTANCE_ROWS];
        instance_col[TX_HASH_START] = tx_hash_field;
        instance_col[MERKLE_ROOT_START] = merkle_root_field;
        instance_col[ORACLE_PUBKEY_HASH_START] = oracle_hash_field;
        instance_col[BLOCK_HEIGHT_ROW] = block_height_field;

        (circuit, vec![instance_col])
    }

    /// Generates real params + pk for k=10, proves, verifies. Asserts valid proof passes.
    /// Then flips one byte in the proof and asserts verify_proof_multi returns false.
    #[test]
    fn test_verify_proof_multi_valid_and_corrupted() {
        let k: u32 = 10;
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        let dummy = ComplianceCircuit {
            public: PublicInputs {
                tx_hash: [0u8; 32],
                compliance_merkle_root: [0u8; 32],
                oracle_pubkey_hash: [0u8; 32],
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
            &params,
            &pk,
            &[circuit],
            &instances,
            OsRng,
            &mut transcript,
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
            >(
                &verifier_params,
                vk_for_verify,
                &[instance_col.clone()],
                &mut t,
            )
        };

        // Valid proof must pass.
        assert!(verify(&proof_bytes), "valid proof failed verification");

        // Corrupt one byte — must fail.
        let mut corrupted = proof_bytes.clone();
        corrupted[0] ^= 0xFF;
        assert!(
            !verify(&corrupted),
            "corrupted proof passed verification (bug!)"
        );
    }

    fn valid_request_json() -> serde_json::Value {
        let tx_hash = {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x11;
            bytes
        };
        let sender_pubkey = {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x22;
            bytes
        };
        let receiver_pubkey = {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x23;
            bytes
        };
        let compliance_merkle_root = {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x12;
            bytes
        };
        let oracle_pubkey = find_bn254_compatible_pallas_point(17);
        let oracle_pubkey_hash = merkle_leaf_hash_from_pubkey::<Fr>(&oracle_pubkey).to_repr();
        let sender_oracle_sig = sign_authorization(oracle_pubkey, sender_pubkey, 7);
        let receiver_oracle_sig = sign_authorization(oracle_pubkey, receiver_pubkey, 11);
        let sender_sibling = format!("0x{}", hex::encode([0x07u8; 32]));
        let receiver_sibling = format!("0x{}", hex::encode([0x08u8; 32]));
        json!({
            "version": 1,
            "tx_hash": format!("0x{}", hex::encode(tx_hash)),
            "sender_pubkey": format!("0x{}", hex::encode(sender_pubkey)),
            "receiver_pubkey": format!("0x{}", hex::encode(receiver_pubkey)),
            "amount": 1000,
            "sender_oracle_sig": format!("0x{}", hex::encode(sender_oracle_sig)),
            "receiver_oracle_sig": format!("0x{}", hex::encode(receiver_oracle_sig)),
            "oracle_pubkey": format!("0x{}", hex::encode(oracle_pubkey)),
            "compliance_merkle_root": format!("0x{}", hex::encode(compliance_merkle_root)),
            "oracle_pubkey_hash": format!("0x{}", hex::encode(oracle_pubkey_hash)),
            "block_height": 42,
            "sender_merkle_siblings": vec![sender_sibling; MERKLE_DEPTH],
            "sender_merkle_directions": vec![false, true, false, true],
            "receiver_merkle_siblings": vec![receiver_sibling; MERKLE_DEPTH],
            "receiver_merkle_directions": vec![true, false, true, false],
        })
    }

    fn zk15c_reference_request_json() -> serde_json::Value {
        let sender_pubkey = [0x01u8; 32];
        let receiver_pubkey = [0x02u8; 32];
        let amount: u64 = 999;
        let block_height: u64 = 1_000_000;
        let sender_sibling = format!("0x{}", hex::encode([0x07u8; 32]));
        let receiver_sibling = format!("0x{}", hex::encode([0x08u8; 32]));
        let oracle_pubkey = hex::decode(ZK15C_REFERENCE_ORACLE_PUBKEY_HEX)
            .expect("reference oracle pubkey should decode");
        let oracle_pubkey_hash = merkle_leaf_hash_from_pubkey::<Fr>(
            &oracle_pubkey
                .as_slice()
                .try_into()
                .expect("reference oracle pubkey length"),
        )
        .to_repr();

        json!({
            "version": 1,
            "tx_hash": format!("0x{}", hex::encode(tx_hash_field_from_inputs::<Fr>(&sender_pubkey, &receiver_pubkey, amount).to_repr())),
            "sender_pubkey": format!("0x{}", hex::encode(sender_pubkey)),
            "receiver_pubkey": format!("0x{}", hex::encode(receiver_pubkey)),
            "amount": amount,
            "sender_oracle_sig": format!("0x{}", ZK15C_REFERENCE_SIGNATURE_HEX),
            "receiver_oracle_sig": format!("0x{}", hex::encode(sign_authorization(
                oracle_pubkey
                    .as_slice()
                    .try_into()
                    .expect("reference oracle pubkey length"),
                receiver_pubkey,
                11
            ))),
            "oracle_pubkey": format!("0x{}", ZK15C_REFERENCE_ORACLE_PUBKEY_HEX),
            "compliance_merkle_root": format!("0x{}", hex::encode([0x12u8; 32])),
            "oracle_pubkey_hash": format!("0x{}", hex::encode(oracle_pubkey_hash)),
            "block_height": block_height,
            "sender_merkle_siblings": vec![sender_sibling; MERKLE_DEPTH],
            "sender_merkle_directions": vec![false; MERKLE_DEPTH],
            "receiver_merkle_siblings": vec![receiver_sibling; MERKLE_DEPTH],
            "receiver_merkle_directions": vec![true; MERKLE_DEPTH],
        })
    }

    #[test]
    fn test_v1_request_deserializes_and_normalizes() {
        let raw = valid_request_json().to_string();
        let req: ProofRequest = serde_json::from_str(&raw).expect("request should deserialize");
        let normalized = normalize_request(req).expect("request should normalize");

        let mut expected_sender = [0u8; 32];
        expected_sender[0] = 0x22;
        let mut expected_receiver = [0u8; 32];
        expected_receiver[0] = 0x23;
        assert_eq!(normalized.sender_pubkey, expected_sender);
        assert_eq!(normalized.receiver_pubkey, expected_receiver);
        assert_ne!(normalized.sender_oracle_sig.to_bytes(), [0u8; 64]);
        assert_ne!(normalized.receiver_oracle_sig.to_bytes(), [0u8; 64]);
        let expected_oracle = find_bn254_compatible_pallas_point(17);
        assert_eq!(normalized.oracle_pubkey.to_bytes(), expected_oracle);
        assert_eq!(normalized.sender_merkle_siblings.len(), MERKLE_DEPTH);
        assert_eq!(
            normalized.sender_merkle_directions,
            vec![false, true, false, true]
        );
        assert_eq!(
            normalized.receiver_merkle_directions,
            vec![true, false, true, false]
        );
    }

    #[test]
    fn zk15d_final_transcript_survives_request_normalization() {
        let raw = zk15c_reference_request_json().to_string();
        let req: ProofRequest =
            serde_json::from_str(&raw).expect("reference request should deserialize");
        let normalized = normalize_request(req).expect("reference request should normalize");
        let expected_message_bytes = hex::decode(ZK15C_REFERENCE_MESSAGE_BYTES_HEX)
            .expect("reference message bytes should decode");
        let expected_signature =
            hex::decode(ZK15C_REFERENCE_SIGNATURE_HEX).expect("reference signature should decode");
        let expected_oracle_pubkey = hex::decode(ZK15C_REFERENCE_ORACLE_PUBKEY_HEX)
            .expect("reference oracle pubkey should decode");

        assert_eq!(
            normalized.oracle_pubkey.to_bytes().as_slice(),
            expected_oracle_pubkey.as_slice(),
            "normalization must preserve the fixed canonical oracle pubkey bytes"
        );
        assert_eq!(
            normalized.sender_oracle_sig.to_bytes().as_slice(),
            expected_signature.as_slice(),
            "normalization must preserve the fixed canonical Schnorr witness bytes"
        );
        assert_eq!(
            oracle_authorization_message_bytes(&normalized.sender_pubkey).as_slice(),
            expected_message_bytes.as_slice(),
            "reference request must derive the same current authorization message bytes after normalization"
        );
        assert_eq!(
            merkle_leaf_hash_from_pubkey::<Fr>(&normalized.oracle_pubkey.to_bytes())
                .to_repr()
                .as_ref(),
            normalized.oracle_pubkey_hash.as_slice(),
            "reference request must keep the current canonical oracle_pubkey_hash binding"
        );
        assert!(
            oracle_authorization_challenge_scalar_from_witness(
                &normalized.oracle_pubkey.to_bytes(),
                &normalized.sender_oracle_sig.to_bytes(),
                &normalized.sender_pubkey,
            )
            .map(|challenge| {
                let encoded_r: [u8; 32] = normalized.sender_oracle_sig.to_bytes()[..32]
                    .try_into()
                    .expect("sender signature R bytes");
                challenge
                    == compliance_circuit::circuit::oracle_authorization_challenge_scalar(
                        &normalized.oracle_pubkey.to_bytes(),
                        &encoded_r,
                        &oracle_authorization_message_bytes(&normalized.sender_pubkey),
                    )
            })
            .unwrap_or(false),
            "reference request must derive the finalized Schnorr challenge from canonical normalized witness bytes"
        );
    }

    #[test]
    fn zk15e_reference_request_derives_verifier_limb_contract() {
        let raw = zk15c_reference_request_json().to_string();
        let req: ProofRequest =
            serde_json::from_str(&raw).expect("reference request should deserialize");
        let normalized = normalize_request(req).expect("reference request should normalize");
        let expected_sender_limbs = oracle_authorization_limb_witness(
            &normalized.oracle_pubkey,
            &normalized.sender_oracle_sig,
            &normalized.sender_pubkey,
        )
        .expect("normalized sender auth should decompose into non-native limbs");
        let expected_receiver_limbs = oracle_authorization_limb_witness(
            &normalized.oracle_pubkey,
            &normalized.receiver_oracle_sig,
            &normalized.receiver_pubkey,
        )
        .expect("normalized receiver auth should decompose into non-native limbs");

        assert_eq!(
            normalized.sender_authorization_limbs, expected_sender_limbs,
            "sidecar normalization must preserve the shared sender limb ABI"
        );
        assert_eq!(
            normalized.receiver_authorization_limbs, expected_receiver_limbs,
            "sidecar normalization must preserve the shared receiver limb ABI"
        );
        assert_ne!(
            normalized.sender_authorization_limbs.challenge_e,
            normalized.receiver_authorization_limbs.challenge_e,
            "sender and receiver challenges should stay message-specific"
        );
    }

    #[test]
    fn test_invalid_oracle_pubkey_encoding_rejected() {
        let mut raw = valid_request_json();
        raw["oracle_pubkey"] = json!(format!("0x{}", hex::encode([0xFFu8; 32])));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("bad oracle pubkey should fail");
        assert!(
            err.contains("oracle_pubkey: invalid compressed Pallas point encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_identity_oracle_pubkey_rejected() {
        let mut raw = valid_request_json();
        let identity = pallas::Affine::identity().to_bytes();
        raw["oracle_pubkey"] = json!(format!("0x{}", hex::encode(identity)));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("identity oracle pubkey should fail");
        assert!(
            err.contains("oracle_pubkey: identity point is not allowed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_bn254_incompatible_oracle_pubkey_rejected() {
        let mut raw = valid_request_json();
        raw["oracle_pubkey"] = json!(format!(
            "0x{}",
            hex::encode(find_bn254_incompatible_pallas_point())
        ));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("BN254-incompatible oracle pubkey should fail");
        assert!(
            err.contains("oracle_pubkey: compressed Pallas public key does not fit the current BN254 witness encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_invalid_signature_r_encoding_rejected() {
        let mut raw = valid_request_json();
        let mut sig = hex::decode(
            raw["sender_oracle_sig"]
                .as_str()
                .expect("sender_oracle_sig string")
                .trim_start_matches("0x"),
        )
        .expect("valid hex");
        sig[..32].copy_from_slice(&[0xFFu8; 32]);
        raw["sender_oracle_sig"] = json!(format!("0x{}", hex::encode(sig)));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("bad R encoding should fail");
        assert!(
            err.contains("sender_oracle_sig: R: invalid compressed Pallas point encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_non_canonical_signature_scalar_rejected() {
        let mut raw = valid_request_json();
        let mut sig = hex::decode(
            raw["receiver_oracle_sig"]
                .as_str()
                .expect("receiver_oracle_sig string")
                .trim_start_matches("0x"),
        )
        .expect("valid hex");
        sig[63] = 0xFF;
        raw["receiver_oracle_sig"] = json!(format!("0x{}", hex::encode(sig)));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("non-canonical scalar should fail");
        assert!(
            err.contains("receiver_oracle_sig: s: non-canonical Pallas scalar encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_bn254_incompatible_signature_r_rejected() {
        let mut raw = valid_request_json();
        let mut sig = hex::decode(
            raw["receiver_oracle_sig"]
                .as_str()
                .expect("receiver_oracle_sig string")
                .trim_start_matches("0x"),
        )
        .expect("valid hex");
        sig[..32].copy_from_slice(&find_bn254_incompatible_pallas_point());
        raw["receiver_oracle_sig"] = json!(format!("0x{}", hex::encode(sig)));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("BN254-incompatible R point should fail");
        assert!(
            err.contains("receiver_oracle_sig: R: compressed Pallas point does not fit the current BN254 witness encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_oracle_pubkey_hash_mismatch_rejected() {
        let mut raw = valid_request_json();
        raw["oracle_pubkey_hash"] = json!(format!("0x{}", hex::encode([0x24u8; 32])));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("mismatched oracle hash should fail");
        assert!(
            err.contains("oracle_pubkey_hash does not match canonical oracle_pubkey encoding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_invalid_pubkey_fails_cleanly() {
        let mut raw = valid_request_json();
        raw["sender_pubkey"] = json!(format!("0x{}", hex::encode([0x22u8; 31])));

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("bad pubkey should fail");
        assert!(
            err.contains("sender_pubkey: expected 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_missing_or_invalid_oracle_field_fails_cleanly() {
        let mut missing_sig = valid_request_json();
        missing_sig
            .as_object_mut()
            .expect("object")
            .remove("sender_oracle_sig");
        let err = serde_json::from_str::<ProofRequest>(&missing_sig.to_string())
            .expect_err("missing sender_oracle_sig should fail deserialization");
        assert!(
            err.to_string().contains("sender_oracle_sig"),
            "unexpected serde error: {err}"
        );

        let mut missing_oracle_pubkey = valid_request_json();
        missing_oracle_pubkey
            .as_object_mut()
            .expect("object")
            .remove("oracle_pubkey");
        let err = serde_json::from_str::<ProofRequest>(&missing_oracle_pubkey.to_string())
            .expect_err("missing oracle_pubkey should fail deserialization");
        assert!(
            err.to_string().contains("oracle_pubkey"),
            "unexpected serde error: {err}"
        );

        let mut bad_hash = valid_request_json();
        bad_hash["oracle_pubkey_hash"] = json!(format!("0x{}", hex::encode([0x13u8; 31])));
        let req: ProofRequest =
            serde_json::from_str(&bad_hash.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("bad oracle field should fail");
        assert!(
            err.contains("oracle_pubkey_hash: expected 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_invalid_merkle_direction_length_fails_cleanly() {
        let mut raw = valid_request_json();
        raw["sender_merkle_directions"] = json!([false, true]);

        let req: ProofRequest =
            serde_json::from_str(&raw.to_string()).expect("schema should still deserialize");
        let err = normalize_request(req).expect_err("bad merkle directions should fail");
        assert!(
            err.contains("sender_merkle_directions must have"),
            "unexpected error: {err}"
        );
    }
}
