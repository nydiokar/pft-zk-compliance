use serde::{Deserialize, Serialize};

/// IPC request from validator daemon → sidecar.
/// Validator sends this when it needs a compliance proof for a transaction.
#[derive(Debug, Deserialize)]
struct ProofRequest {
    version: u32,
    /// Hex-encoded Poseidon hash of the transaction.
    tx_hash: String,
    /// Hex-encoded sender Ethereum-style address (20 bytes).
    sender_addr: String,
    /// Hex-encoded receiver address (20 bytes).
    receiver_addr: String,
    /// Transaction amount.
    amount: u64,
    /// Hex-encoded compliance Merkle tree root (32 bytes).
    compliance_merkle_root: String,
    /// Block height of the compliance snapshot.
    block_height: u64,
    /// Hex-encoded sibling hashes for Merkle membership proof.
    merkle_path: Vec<String>,
}

/// IPC response from sidecar → validator daemon.
#[derive(Debug, Serialize)]
struct ProofResponse {
    version: u32,
    tx_hash: String,
    /// "compliant" | "non_compliant" | "error"
    status: String,
    /// Base64-encoded serialized Halo2 proof (empty string if status != "compliant").
    proof_bytes: String,
    /// Hex-encoded public instance values fed into the proof.
    public_inputs: Vec<String>,
    /// Wall-clock time to generate the proof, in milliseconds.
    proof_time_ms: u64,
}

/// Default proof timeout. Validator will quarantine tx if sidecar exceeds this.
const PROOF_TIMEOUT_MS: u64 = 2000;

#[tokio::main]
async fn main() {
    // TODO(Step 2): replace with actual Unix socket / named pipe listener
    eprintln!("[compliance-sidecar] starting (PROOF_TIMEOUT_MS={})", PROOF_TIMEOUT_MS);

    // Daemon loop skeleton:
    // 1. Listen on IPC socket for ProofRequest messages
    // 2. For each request, spawn a task:
    //    a. Deserialize request fields into ComplianceCircuit public + witness
    //    b. Run halo2_proofs::plonk::create_proof (with timeout)
    //    c. Serialize proof to ProofResponse and send back
    // 3. On timeout or proof failure, respond with status "error"

    loop {
        // TODO(Step 2): accept connection from validator daemon
        // let request: ProofRequest = read_request(&socket).await;
        // let response = handle_request(request).await;
        // write_response(&socket, response).await;

        // Placeholder — prevents tight loop in stub
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        eprintln!("[compliance-sidecar] waiting for proof requests...");
    }
}

/// Handle a single proof request.
/// Returns a ProofResponse with status "compliant", "non_compliant", or "error".
#[allow(dead_code)]
async fn handle_request(req: ProofRequest) -> ProofResponse {
    let start = std::time::Instant::now();

    // TODO(Step 2):
    // 1. Decode hex fields from req
    // 2. Build ComplianceCircuit { public, witness: Value::known(Witness { ... }) }
    // 3. Create proving key from circuit + params
    // 4. Call halo2_proofs::plonk::create_proof
    // 5. Serialize proof bytes to base64

    let proof_time_ms = start.elapsed().as_millis() as u64;

    ProofResponse {
        version: 1,
        tx_hash: req.tx_hash,
        status: "error".to_string(), // stub — replace with actual proof result
        proof_bytes: String::new(),
        public_inputs: vec![],
        proof_time_ms,
    }
}
