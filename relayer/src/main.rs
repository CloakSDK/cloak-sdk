use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use tower_http::cors::CorsLayer;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    rpc_client: RpcClient,
    relayer_keypair: Keypair,
    program_id: Pubkey,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RelayRequest {
    /// The user's partially-signed transaction (base58-encoded).
    /// The user signs for the SOL transfer; the relayer co-signs as payer.
    transaction: String,
}

#[derive(Serialize)]
struct RelayResponse {
    signature: String,
}

#[derive(Deserialize)]
struct BuildRelayRequest {
    /// User's public key (base58)
    user_pubkey: String,
    /// Stealth address (base58)
    stealth_address: String,
    /// Ephemeral public key (hex, 32 bytes)
    ephemeral_pubkey: String,
    /// Amount in lamports
    amount: u64,
}

#[derive(Serialize)]
struct BuildRelayResponse {
    /// The partially-built transaction for the user to sign (base58)
    transaction: String,
    /// The relayer's pubkey so the user knows who co-signs
    relayer_pubkey: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{}", name).as_bytes());
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

fn get_counter_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"counter"], program_id)
}

fn get_announcement_pda(program_id: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"announcement", &index.to_le_bytes()],
        program_id,
    )
}

fn fetch_counter_index(rpc: &RpcClient, counter_pda: &Pubkey) -> anyhow::Result<u64> {
    let data = rpc.get_account_data(counter_pda)?;
    // Layout: 8 (discriminator) + 32 (authority) + 1 (bump) + 8 (next_index)
    if data.len() < 49 {
        anyhow::bail!("Counter account data too short");
    }
    let index = u64::from_le_bytes(data[41..49].try_into()?);
    Ok(index)
}

fn build_send_stealth_relayed_ix(
    program_id: &Pubkey,
    relayer: &Pubkey,
    user: &Pubkey,
    stealth_address: &Pubkey,
    counter_pda: &Pubkey,
    announcement_pda: &Pubkey,
    ephemeral_pubkey: [u8; 32],
    amount: u64,
) -> Instruction {
    let disc = anchor_discriminator("send_stealth_relayed");
    let mut data = Vec::with_capacity(8 + 32 + 8);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&ephemeral_pubkey);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*counter_pda, false),
            AccountMeta::new(*announcement_pda, false),
            AccountMeta::new(*relayer, true),      // relayer = payer + signer
            AccountMeta::new(*user, true),          // user = signer for SOL transfer
            AccountMeta::new(*stealth_address, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// POST /build-relay
///
/// The client sends payment details and receives a partially-signed transaction
/// (signed by the relayer). The client then signs it with their key and submits
/// via POST /relay.
async fn build_relay(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BuildRelayRequest>,
) -> Result<Json<BuildRelayResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_pubkey = Pubkey::from_str(&req.user_pubkey).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid user_pubkey: {e}") }))
    })?;

    let stealth_address = Pubkey::from_str(&req.stealth_address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid stealth_address: {e}") }))
    })?;

    let eph_bytes = hex::decode(&req.ephemeral_pubkey).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid ephemeral_pubkey hex: {e}") }))
    })?;
    if eph_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "ephemeral_pubkey must be 32 bytes".to_string(),
        })));
    }
    let mut ephemeral_pubkey = [0u8; 32];
    ephemeral_pubkey.copy_from_slice(&eph_bytes);

    if req.amount == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "amount must be > 0".to_string(),
        })));
    }

    let (counter_pda, _) = get_counter_pda(&state.program_id);
    let next_index = fetch_counter_index(&state.rpc_client, &counter_pda).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Failed to fetch counter: {e}") }))
    })?;

    let (announcement_pda, _) = get_announcement_pda(&state.program_id, next_index);
    let relayer_pubkey = state.relayer_keypair.pubkey();

    let ix = build_send_stealth_relayed_ix(
        &state.program_id,
        &relayer_pubkey,
        &user_pubkey,
        &stealth_address,
        &counter_pda,
        &announcement_pda,
        ephemeral_pubkey,
        req.amount,
    );

    let recent_blockhash = state.rpc_client.get_latest_blockhash().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Failed to get blockhash: {e}") }))
    })?;

    // Create tx with relayer as fee payer, partially sign with relayer key
    let mut tx = Transaction::new_with_payer(&[ix], Some(&relayer_pubkey));
    tx.partial_sign(&[&state.relayer_keypair], recent_blockhash);

    let tx_bytes = bincode::serialize(&tx).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Serialize error: {e}") }))
    })?;

    Ok(Json(BuildRelayResponse {
        transaction: bs58::encode(&tx_bytes).into_string(),
        relayer_pubkey: relayer_pubkey.to_string(),
    }))
}

/// POST /relay
///
/// The client sends a fully-signed transaction (both relayer + user signatures).
/// The relayer submits it to the Solana network.
async fn relay(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RelayRequest>,
) -> Result<Json<RelayResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tx_bytes = bs58::decode(&req.transaction).into_vec().map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid base58 transaction: {e}") }))
    })?;

    let tx: Transaction = bincode::deserialize(&tx_bytes).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("Invalid transaction: {e}") }))
    })?;

    // Verify the transaction has the relayer's signature
    let relayer_pubkey = state.relayer_keypair.pubkey();
    let has_relayer_sig = tx.message.account_keys.iter().any(|k| *k == relayer_pubkey);
    if !has_relayer_sig {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Transaction does not include relayer as account".to_string(),
        })));
    }

    let sig = state.rpc_client.send_and_confirm_transaction(&tx).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Transaction failed: {e}") }))
    })?;

    Ok(Json(RelayResponse {
        signature: sig.to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    let program_id_str = std::env::var("CLOAK_PROGRAM_ID")
        .expect("CLOAK_PROGRAM_ID env var required");

    let relayer_key_path = std::env::var("RELAYER_KEYPAIR")
        .unwrap_or_else(|_| {
            let home = dirs::home_dir().expect("No home directory");
            home.join(".config/solana/id.json").to_string_lossy().to_string()
        });

    let program_id = Pubkey::from_str(&program_id_str)?;

    let key_data = std::fs::read_to_string(&relayer_key_path)?;
    let key_bytes: Vec<u8> = serde_json::from_str(&key_data)?;
    let relayer_keypair = Keypair::from_bytes(&key_bytes)?;

    let rpc_client = RpcClient::new_with_commitment(&rpc_url, CommitmentConfig::confirmed());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    println!("Cloak Relayer starting...");
    println!("  RPC:        {}", rpc_url);
    println!("  Program:    {}", program_id);
    println!("  Relayer:    {}", relayer_keypair.pubkey());
    println!("  Port:       {}", port);

    let state = Arc::new(AppState {
        rpc_client,
        relayer_keypair,
        program_id,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/build-relay", post(build_relay))
        .route("/relay", post(relay))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
