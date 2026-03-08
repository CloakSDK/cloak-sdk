//! # Solana Stealth SDK
//!
//! A library for private payments on Solana using Stealth Addresses.
//!
//! ## Overview
//!
//! Stealth addresses allow a sender to pay a recipient without revealing the
//! connection between them. Each payment generates a unique one-time address
//! that only the recipient can detect and spend from.
//!
//! ## Quick Start
//!
//! ### Receiving Payments
//!
//! ```rust,ignore
//! use solana_stealth::{StealthMetaAddress, Scanner};
//!
//! // Generate a meta-address (do this once)
//! let meta = StealthMetaAddress::generate();
//! println!("Share this publicly: {}", meta.to_public_string());
//!
//! // Save your keys securely
//! meta.save_to_file("~/.stealth/keys.json").unwrap();
//!
//! // Scan for incoming payments
//! let scanner = Scanner::new(&meta);
//! let payments = scanner.scan("https://api.devnet.solana.com").await.unwrap();
//!
//! for payment in payments {
//!     println!("Received {} lamports at {}", payment.amount.unwrap_or(0), payment.stealth_address);
//!
//!     // Derive the keypair to spend these funds
//!     let keypair = scanner.derive_spend_keypair(&payment).unwrap();
//!     let solana_keypair = keypair.to_solana_keypair().unwrap();
//! }
//! ```
//!
//! ### Sending Payments
//!
//! ```rust,ignore
//! use solana_stealth::{PublicMetaAddress, StealthPayment};
//!
//! // Parse recipient's meta-address
//! let recipient = PublicMetaAddress::from_string("stealth1abc...").unwrap();
//!
//! // Create a stealth payment
//! let payment = StealthPayment::create(&recipient, 1_000_000_000).unwrap(); // 1 SOL
//!
//! // The payment contains:
//! // - stealth_address: where to send the funds
//! // - ephemeral_pubkey: publish this on-chain so recipient can detect the payment
//! ```
//!
//! ## How It Works
//!
//! 1. **Recipient** generates a stealth meta-address (spending + viewing keypairs)
//! 2. **Recipient** publishes their meta-address publicly
//! 3. **Sender** generates a unique stealth address using ECDH with the meta-address
//! 4. **Sender** sends funds to the stealth address and publishes an announcement
//! 5. **Recipient** scans announcements and detects payments addressed to them
//! 6. **Recipient** derives the private key to spend the received funds
//!
//! ## Privacy Properties
//!
//! - Each payment uses a unique one-time address
//! - Only the recipient can detect which payments are theirs
//! - The sender cannot be linked to the recipient on-chain
//! - Amounts are visible on-chain (v1 limitation)

pub mod address;
pub mod error;
pub mod keys;
pub mod scanner;
pub mod spend;
pub mod zk;

// Re-export main types
pub use address::{derive_stealth_address, check_stealth_address, StealthPayment, PrivateStealthPayment};
pub use error::{Result, StealthError};
pub use keys::{PublicMetaAddress, StealthMetaAddress};
pub use scanner::{Announcement, DetectedPayment, Scanner, ScannerConfig};
pub use spend::StealthKeypair;

// v0.2: Enhanced Scanning exports
pub use scanner::{PaymentHistory, ViewingKey, ViewingKeyScanner};

// v0.3: Zero-knowledge proof exports
pub use zk::{AmountCommitment, AmountProof};

/// Version of the protocol
pub const PROTOCOL_VERSION: &str = "v2";

/// Prefix for encoded meta-addresses
pub const META_ADDRESS_PREFIX: &str = "stealth1";
