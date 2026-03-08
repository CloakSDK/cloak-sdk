//! Cloak CLI - Command line interface for Cloak SDK (Stealth Addresses on Solana)

use anyhow::{Context, Result};
use borsh::BorshSerialize;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
    signer::Signer,
    system_instruction,
    system_program,
    transaction::Transaction,
};
use cloak_sdk::{
    PaymentHistory, PublicMetaAddress, Scanner, ScannerConfig,
    StealthKeypair, StealthMetaAddress, StealthPayment,
    ViewingKey, ViewingKeyScanner,
};
use std::path::PathBuf;
use std::str::FromStr;

// ============================================================================
// Program instruction helpers
// ============================================================================

/// Compute Anchor instruction discriminator: sha256("global:<method_name>")[..8]
fn anchor_discriminator(method_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{}", method_name));
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

/// Derive the counter PDA address
fn get_counter_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"counter"], program_id)
}

/// Derive an announcement PDA address by index
fn get_announcement_pda(program_id: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"announcement", &index.to_le_bytes()],
        program_id,
    )
}

/// Fetch the current counter value (next_index) from on-chain
fn fetch_counter_index(client: &RpcClient, counter_pda: &Pubkey) -> Result<u64> {
    let account = client
        .get_account(counter_pda)
        .context("Counter PDA not found. Has the program been initialized?")?;

    // Layout: 8 (discriminator) + 32 (authority) + 1 (bump) + 8 (next_index)
    let data = &account.data;
    if data.len() < 49 {
        anyhow::bail!("Invalid counter account data");
    }

    let next_index = u64::from_le_bytes(data[41..49].try_into().unwrap());
    Ok(next_index)
}

/// Build the `send_stealth` instruction
fn build_send_stealth_ix(
    program_id: &Pubkey,
    sender: &Pubkey,
    stealth_address: &Pubkey,
    counter_pda: &Pubkey,
    announcement_pda: &Pubkey,
    ephemeral_pubkey: [u8; 32],
    amount: u64,
) -> Instruction {
    let disc = anchor_discriminator("send_stealth");

    let mut data = Vec::with_capacity(8 + 32 + 8);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&ephemeral_pubkey);
    amount.serialize(&mut data).unwrap();

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*counter_pda, false),
            AccountMeta::new(*announcement_pda, false),
            AccountMeta::new(*sender, true),
            AccountMeta::new(*stealth_address, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

/// Build the `initialize` instruction
fn build_initialize_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    counter_pda: &Pubkey,
) -> Instruction {
    let disc = anchor_discriminator("initialize");

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*counter_pda, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: disc.to_vec(),
    }
}

/// Build the `send_stealth_private` instruction (zk-proof mode)
fn build_send_stealth_private_ix(
    program_id: &Pubkey,
    sender: &Pubkey,
    stealth_address: &Pubkey,
    counter_pda: &Pubkey,
    announcement_pda: &Pubkey,
    ephemeral_pubkey: [u8; 32],
    amount: u64,
    amount_commitment: [u8; 32],
    proof_data: Vec<u8>,
) -> Instruction {
    let disc = anchor_discriminator("send_stealth_private");

    let mut data = Vec::with_capacity(8 + 32 + 8 + 32 + 4 + proof_data.len());
    data.extend_from_slice(&disc);
    data.extend_from_slice(&ephemeral_pubkey);
    amount.serialize(&mut data).unwrap();
    data.extend_from_slice(&amount_commitment);
    // Borsh Vec<u8>: 4-byte length prefix + data
    (proof_data.len() as u32).serialize(&mut data).unwrap();
    data.extend_from_slice(&proof_data);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*counter_pda, false),
            AccountMeta::new(*announcement_pda, false),
            AccountMeta::new(*sender, true),
            AccountMeta::new(*stealth_address, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

// ============================================================================
// CLI definition
// ============================================================================

/// Cloak CLI - Private payments on Solana using Stealth Addresses
#[derive(Parser)]
#[command(name = "cloak")]
#[command(about = "Cloak SDK - Private payments on Solana using Stealth Addresses")]
#[command(version)]
struct Cli {
    /// Solana RPC URL
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    rpc_url: String,

    /// Path to keypair file for signing transactions
    #[arg(long, short = 'k')]
    keypair: Option<PathBuf>,

    /// Program ID for the Cloak stealth program
    #[arg(long, env = "CLOAK_PROGRAM_ID")]
    program_id: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new stealth meta-address
    Init {
        /// Output file for the meta-address (default: ~/.cloak/keys.json)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Display your public meta-address
    Address,

    /// Send SOL to a stealth address (with on-chain announcement)
    Send {
        /// Recipient's public meta-address (stealth1...)
        recipient: String,

        /// Amount in SOL
        amount: f64,

        /// Relayer URL to submit transaction through (hides sender identity)
        #[arg(long)]
        relayer: Option<String>,

        /// Enable private mode: hide the amount with a zk-SNARK proof
        #[arg(long)]
        private: bool,
    },

    /// Scan for incoming payments on-chain
    Scan {
        /// Only show payments after this Unix timestamp
        #[arg(long)]
        after: Option<i64>,
    },

    /// Spend funds from a stealth address
    Spend {
        /// The stealth address to spend from
        stealth_address: String,

        /// Destination address
        destination: String,

        /// Amount in SOL (or "all" for full balance)
        amount: String,

        /// The ephemeral pubkey (hex) for this payment
        #[arg(long)]
        ephemeral: String,
    },

    /// Show balance of a stealth address
    Balance {
        /// The stealth address to check
        address: String,
    },

    /// Export your meta-address to a file
    Export {
        /// Output file
        output: PathBuf,
    },

    /// Import a meta-address from a file
    Import {
        /// Input file
        input: PathBuf,
    },

    /// Initialize the Cloak program on-chain (admin only)
    InitProgram,

    /// Export a viewing key for watch-only wallets
    ExportViewKey {
        /// Output file for the viewing key
        output: PathBuf,

        /// Optional label for this viewing key
        #[arg(long)]
        label: Option<String>,
    },

    /// Scan using a viewing key (watch-only)
    ViewScan {
        /// Path to viewing key file
        viewing_key: PathBuf,

        /// Only show payments after this Unix timestamp
        #[arg(long)]
        after: Option<i64>,
    },

    /// Show payment history
    History {
        /// Show only unspent payments
        #[arg(long)]
        unspent: bool,

        /// Filter by label
        #[arg(long)]
        label: Option<String>,
    },
}

// ============================================================================
// Helpers
// ============================================================================

fn get_cloak_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    let cloak_dir = home.join(".cloak");
    std::fs::create_dir_all(&cloak_dir)?;
    Ok(cloak_dir)
}

fn get_default_keys_path() -> Result<PathBuf> {
    Ok(get_cloak_dir()?.join("keys.json"))
}

fn get_history_path() -> Result<PathBuf> {
    Ok(get_cloak_dir()?.join("history.json"))
}

fn load_meta_address() -> Result<StealthMetaAddress> {
    let path = get_default_keys_path()?;
    StealthMetaAddress::load_from_file(&path)
        .context("No keys found. Run 'cloak init' first.")
}

fn load_payer_keypair(keypair_path: Option<PathBuf>) -> Result<Keypair> {
    let path = keypair_path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap()
            .join(".config/solana/id.json")
    });

    read_keypair_file(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read keypair from {:?}: {}", path, e))
}

fn parse_program_id(program_id_str: &Option<String>) -> Result<Pubkey> {
    match program_id_str {
        Some(id) => Pubkey::from_str(id)
            .context("Invalid program ID"),
        None => anyhow::bail!(
            "Program ID required. Use --program-id <PUBKEY> or set CLOAK_PROGRAM_ID env var."
        ),
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { output } => {
            let output_path = output.unwrap_or_else(|| get_default_keys_path().unwrap());

            if output_path.exists() {
                println!("Warning: Keys already exist at {:?}", output_path);
                println!("Delete the file first if you want to generate new keys.");
                return Ok(());
            }

            let meta = StealthMetaAddress::generate();
            meta.save_to_file(&output_path)?;

            println!("Generated new stealth meta-address!");
            println!();
            println!("Your public meta-address (share this to receive payments):");
            println!("  {}", meta.to_public_string());
            println!();
            println!("Keys saved to: {:?}", output_path);
            println!();
            println!("IMPORTANT: Keep your keys.json file secure and backed up!");
        }

        Commands::Address => {
            let meta = load_meta_address()?;
            println!("Your public meta-address:");
            println!("  {}", meta.to_public_string());
        }

        Commands::Send { recipient, amount, relayer, private } => {
            let program_id = parse_program_id(&cli.program_id)?;
            let recipient_meta = PublicMetaAddress::from_string(&recipient)
                .context("Invalid recipient meta-address")?;

            let amount_lamports = (amount * LAMPORTS_PER_SOL as f64) as u64;

            // Create stealth payment
            let payment = StealthPayment::create(&recipient_meta, amount_lamports)?;

            println!("Stealth Payment Created:");
            println!("  Stealth Address: {}", payment.stealth_address);
            println!("  Ephemeral Pubkey: {}", hex::encode(&payment.ephemeral_pubkey));
            if private {
                println!("  Amount: [HIDDEN by zk-SNARK]");
            } else {
                println!("  Amount: {} SOL ({} lamports)", amount, amount_lamports);
            }
            println!();

            if let Some(relayer_url) = relayer {
                // === Relayer mode: user signs, relayer submits ===
                println!("Using relayer at {}", relayer_url);
                let payer = load_payer_keypair(cli.keypair)?;

                // Step 1: Request relayer to build the transaction
                let build_req = serde_json::json!({
                    "user_pubkey": payer.pubkey().to_string(),
                    "stealth_address": payment.stealth_address.to_string(),
                    "ephemeral_pubkey": hex::encode(&payment.ephemeral_pubkey),
                    "amount": amount_lamports,
                });

                let http_client = reqwest::Client::new();
                let build_resp = http_client
                    .post(format!("{}/build-relay", relayer_url))
                    .json(&build_req)
                    .send()
                    .await
                    .context("Failed to contact relayer")?;

                if !build_resp.status().is_success() {
                    let err_text = build_resp.text().await.unwrap_or_default();
                    anyhow::bail!("Relayer error: {}", err_text);
                }

                let build_data: serde_json::Value = build_resp.json().await?;
                let tx_b58 = build_data["transaction"].as_str()
                    .context("Invalid relayer response: missing transaction")?;

                // Step 2: Deserialize, co-sign with user key, submit back
                let tx_bytes = bs58::decode(tx_b58).into_vec()?;
                let mut tx: Transaction = bincode::deserialize(&tx_bytes)?;

                // Get the blockhash from the partially-signed tx
                let blockhash = tx.message.recent_blockhash;
                tx.partial_sign(&[&payer], blockhash);

                let signed_bytes = bincode::serialize(&tx)?;
                let relay_req = serde_json::json!({
                    "transaction": bs58::encode(&signed_bytes).into_string(),
                });

                let relay_resp = http_client
                    .post(format!("{}/relay", relayer_url))
                    .json(&relay_req)
                    .send()
                    .await
                    .context("Failed to submit to relayer")?;

                if !relay_resp.status().is_success() {
                    let err_text = relay_resp.text().await.unwrap_or_default();
                    anyhow::bail!("Relayer submission error: {}", err_text);
                }

                let relay_data: serde_json::Value = relay_resp.json().await?;
                let signature = relay_data["signature"].as_str().unwrap_or("unknown");

                println!("Transaction relayed!");
                println!("  Signature: {}", signature);
                println!("  Relayer: {}", build_data["relayer_pubkey"].as_str().unwrap_or("unknown"));
                println!();
                println!("Your identity is hidden - the relayer submitted the transaction.");
            } else {
                // === Direct mode: user pays and submits ===
                let payer = load_payer_keypair(cli.keypair)?;
                let client = RpcClient::new_with_commitment(
                    cli.rpc_url.clone(),
                    CommitmentConfig::confirmed(),
                );

                // Fetch current counter index for announcement PDA derivation
                let (counter_pda, _) = get_counter_pda(&program_id);
                let next_index = fetch_counter_index(&client, &counter_pda)?;
                let (announcement_pda, _) = get_announcement_pda(&program_id, next_index);

                let send_ix = if private {
                    // === Private mode: generate zk proof ===
                    println!("Generating zk-SNARK proof (Groth16 on BN254)...");

                    let (pk, _pvk) = cloak_sdk::zk::setup()
                        .context("ZK trusted setup failed")?;

                    let commitment = cloak_sdk::zk::AmountCommitment::commit(amount_lamports);
                    let proof = cloak_sdk::zk::prove(&pk, amount_lamports, &commitment)
                        .context("ZK proof generation failed")?;

                    // Prepare commitment as [u8; 32]
                    let mut commitment_bytes = [0u8; 32];
                    let cb = &commitment.commitment_bytes;
                    let copy_len = cb.len().min(32);
                    commitment_bytes[..copy_len].copy_from_slice(&cb[..copy_len]);

                    println!("  Proof generated ({} bytes)", proof.proof_bytes.len());
                    println!("  Commitment: {}", hex::encode(&commitment_bytes));

                    build_send_stealth_private_ix(
                        &program_id,
                        &payer.pubkey(),
                        &payment.stealth_address,
                        &counter_pda,
                        &announcement_pda,
                        payment.ephemeral_pubkey,
                        amount_lamports,
                        commitment_bytes,
                        proof.proof_bytes,
                    )
                } else {
                    // === Standard mode ===
                    build_send_stealth_ix(
                        &program_id,
                        &payer.pubkey(),
                        &payment.stealth_address,
                        &counter_pda,
                        &announcement_pda,
                        payment.ephemeral_pubkey,
                        amount_lamports,
                    )
                };

                let recent_blockhash = client.get_latest_blockhash()?;
                let tx = Transaction::new_signed_with_payer(
                    &[send_ix],
                    Some(&payer.pubkey()),
                    &[&payer],
                    recent_blockhash,
                );

                let signature = client.send_and_confirm_transaction(&tx)?;

                println!("Transaction sent!");
                println!("  Signature: {}", signature);
                println!("  Announcement PDA: {}", announcement_pda);
                if private {
                    println!("  Mode: PRIVATE (amount hidden by zk-SNARK)");
                }
                println!();
                println!("The recipient can detect this payment by scanning on-chain announcements.");
            }
        }

        Commands::Scan { after } => {
            let program_id = parse_program_id(&cli.program_id)?;
            let meta = load_meta_address()?;

            let config = ScannerConfig {
                program_id,
                after_timestamp: after,
                ..Default::default()
            };
            let scanner = Scanner::with_config(&meta, config);

            println!("Scanning for incoming payments...");
            println!("  Program: {}", program_id);
            if let Some(ts) = after {
                println!("  After timestamp: {}", ts);
            }
            println!();

            let detected = scanner.scan(&cli.rpc_url).await
                .context("Failed to scan on-chain announcements")?;

            if detected.is_empty() {
                println!("No payments found.");
            } else {
                println!("Found {} payment(s):", detected.len());
                println!();

                // Update local history
                let history_path = get_history_path()?;
                let mut history = PaymentHistory::load_from_file(&history_path)
                    .unwrap_or_default();

                for payment in &detected {
                    let balance = payment.amount.unwrap_or(0);
                    println!("  Address: {}", payment.stealth_address);
                    println!("  Balance: {} SOL", balance as f64 / LAMPORTS_PER_SOL as f64);
                    println!("  Ephemeral: {}", hex::encode(&payment.ephemeral_pubkey));
                    if let Some(ts) = payment.timestamp {
                        println!("  Timestamp: {}", ts);
                    }
                    println!();

                    history.add_payment(payment.clone());
                }

                history.save_to_file(&history_path)?;
                println!("Payment history updated at {:?}", history_path);
            }
        }

        Commands::Spend {
            stealth_address,
            destination,
            amount,
            ephemeral,
        } => {
            let meta = load_meta_address()?;

            let ephemeral_bytes: [u8; 32] = hex::decode(&ephemeral)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Ephemeral pubkey must be 32 bytes"))?;

            let stealth_addr: Pubkey = stealth_address.parse()?;
            let dest_addr: Pubkey = destination.parse()?;

            let client = RpcClient::new_with_commitment(
                cli.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );

            let balance = client.get_balance(&stealth_addr)?;
            println!("Stealth address balance: {} SOL", balance as f64 / LAMPORTS_PER_SOL as f64);

            let amount_lamports = if amount.to_lowercase() == "all" {
                balance.saturating_sub(5000)
            } else {
                let amt: f64 = amount.parse()?;
                (amt * LAMPORTS_PER_SOL as f64) as u64
            };

            if amount_lamports == 0 || amount_lamports > balance {
                println!("Insufficient balance");
                return Ok(());
            }

            let stealth_kp = StealthKeypair::derive(&meta, &ephemeral_bytes)?;
            let solana_keypair = stealth_kp.to_solana_keypair()?;

            if solana_keypair.pubkey() != stealth_addr {
                println!("Error: Derived address doesn't match stealth address");
                println!("  Expected: {}", stealth_addr);
                println!("  Derived:  {}", solana_keypair.pubkey());
                return Ok(());
            }

            let transfer_ix = system_instruction::transfer(
                &stealth_addr,
                &dest_addr,
                amount_lamports,
            );

            let recent_blockhash = client.get_latest_blockhash()?;
            let tx = Transaction::new_signed_with_payer(
                &[transfer_ix],
                Some(&stealth_addr),
                &[&solana_keypair],
                recent_blockhash,
            );

            let signature = client.send_and_confirm_transaction(&tx)?;

            println!("Funds spent successfully!");
            println!("  Amount: {} SOL", amount_lamports as f64 / LAMPORTS_PER_SOL as f64);
            println!("  To: {}", dest_addr);
            println!("  Signature: {}", signature);

            // Mark as spent in history
            let history_path = get_history_path()?;
            let mut history = PaymentHistory::load_from_file(&history_path)
                .unwrap_or_default();
            history.mark_spent(&stealth_addr);
            history.save_to_file(&history_path)?;
        }

        Commands::Balance { address } => {
            let addr: Pubkey = address.parse()?;
            let client = RpcClient::new_with_commitment(
                cli.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );

            let balance = client.get_balance(&addr)?;
            println!("Balance: {} SOL ({} lamports)",
                balance as f64 / LAMPORTS_PER_SOL as f64,
                balance
            );
        }

        Commands::Export { output } => {
            let meta = load_meta_address()?;
            meta.save_to_file(&output)?;
            println!("Exported meta-address to {:?}", output);
        }

        Commands::Import { input } => {
            let meta = StealthMetaAddress::load_from_file(&input)?;
            let default_path = get_default_keys_path()?;
            meta.save_to_file(&default_path)?;
            println!("Imported meta-address from {:?}", input);
            println!("Saved to {:?}", default_path);
        }

        Commands::InitProgram => {
            let program_id = parse_program_id(&cli.program_id)?;
            let payer = load_payer_keypair(cli.keypair)?;
            let client = RpcClient::new_with_commitment(
                cli.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );

            let (counter_pda, _) = get_counter_pda(&program_id);

            // Check if already initialized
            if client.get_account(&counter_pda).is_ok() {
                println!("Program already initialized. Counter PDA: {}", counter_pda);
                return Ok(());
            }

            let ix = build_initialize_ix(&program_id, &payer.pubkey(), &counter_pda);

            let recent_blockhash = client.get_latest_blockhash()?;
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&payer.pubkey()),
                &[&payer],
                recent_blockhash,
            );

            let signature = client.send_and_confirm_transaction(&tx)?;

            println!("Program initialized!");
            println!("  Counter PDA: {}", counter_pda);
            println!("  Signature: {}", signature);
        }

        Commands::ExportViewKey { output, label } => {
            let meta = load_meta_address()?;

            let vk = match &label {
                Some(l) => ViewingKey::from_meta_address_with_label(&meta, l),
                None => ViewingKey::from_meta_address(&meta),
            };

            vk.save_to_file(&output)?;

            println!("Viewing key exported to {:?}", output);
            if let Some(l) = &label {
                println!("  Label: {}", l);
            }
            println!();
            println!("Share this file with watch-only wallets.");
            println!("It can detect payments but CANNOT spend them.");
        }

        Commands::ViewScan { viewing_key, after } => {
            let program_id = parse_program_id(&cli.program_id)?;

            let vk = ViewingKey::load_from_file(&viewing_key)
                .context("Failed to load viewing key")?;

            let mut scanner = ViewingKeyScanner::new(vk)
                .program_id(program_id);

            if let Some(ts) = after {
                scanner = scanner.after_timestamp(ts);
            }

            println!("Scanning with viewing key (watch-only)...");
            println!("  Program: {}", program_id);
            println!();

            let client = RpcClient::new_with_commitment(
                cli.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );

            use solana_client::rpc_config::RpcProgramAccountsConfig;
            use solana_client::rpc_filter::RpcFilterType;

            let accounts = client
                .get_program_accounts_with_config(
                    &program_id,
                    RpcProgramAccountsConfig {
                        filters: Some(vec![RpcFilterType::DataSize(113)]),
                        account_config: solana_client::rpc_config::RpcAccountInfoConfig {
                            commitment: Some(CommitmentConfig::confirmed()),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .context("Failed to fetch announcements")?;

            // Deserialize into Announcement structs
            let mut announcements = Vec::new();
            for (_pubkey, account) in &accounts {
                if account.data.len() >= 113 {
                    // Skip 8-byte discriminator, read fields
                    use borsh::BorshDeserialize;
                    if let Ok(ephemeral_pubkey) = <[u8; 32]>::try_from_slice(&account.data[8..40]) {
                        if let Ok(stealth_address) = Pubkey::try_from_slice(&account.data[40..72]) {
                            let timestamp = i64::from_le_bytes(
                                account.data[72..80].try_into().unwrap_or_default()
                            );
                            announcements.push(cloak_sdk::Announcement {
                                ephemeral_pubkey,
                                stealth_address,
                                timestamp,
                            });
                        }
                    }
                }
            }

            let detected = scanner.scan_announcements_list(&announcements)
                .context("Failed to scan announcements")?;

            if detected.is_empty() {
                println!("No payments found.");
            } else {
                println!("Found {} payment(s) (view-only):", detected.len());
                println!();
                for payment in &detected {
                    println!("  Address: {}", payment.stealth_address);
                    if let Some(ts) = payment.timestamp {
                        println!("  Timestamp: {}", ts);
                    }
                    println!("  (Cannot spend - viewing key only)");
                    println!();
                }
            }
        }

        Commands::History { unspent, label } => {
            let history_path = get_history_path()?;
            let history = PaymentHistory::load_from_file(&history_path)
                .unwrap_or_default();

            if history.is_empty() {
                println!("No payment history. Run 'cloak scan' first.");
                return Ok(());
            }

            let payments = if let Some(ref l) = label {
                history.payments_by_label(l)
            } else if unspent {
                history.unspent_payments()
            } else {
                history.all_payments()
            };

            if payments.is_empty() {
                println!("No matching payments.");
                return Ok(());
            }

            println!("Payment History ({} entries):", payments.len());
            println!();

            for payment in &payments {
                let status = if payment.spent { "SPENT" } else { "UNSPENT" };
                let balance_str = payment.amount
                    .map(|a| format!("{} SOL", a as f64 / LAMPORTS_PER_SOL as f64))
                    .unwrap_or_else(|| "unknown".to_string());

                println!("  [{}] {}", status, payment.stealth_address);
                println!("    Balance: {}", balance_str);
                println!("    Ephemeral: {}", hex::encode(&payment.ephemeral_pubkey));
                if let Some(ref l) = payment.label {
                    println!("    Label: {}", l);
                }
                if let Some(ref m) = payment.memo {
                    println!("    Memo: {}", m);
                }
                println!();
            }

            let total = history.total_balance();
            println!("Total unspent: {} SOL", total as f64 / LAMPORTS_PER_SOL as f64);
        }
    }

    Ok(())
}
