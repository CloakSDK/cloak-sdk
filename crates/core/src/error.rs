//! Error types for the Solana Stealth SDK

use thiserror::Error;

/// Errors that can occur in the Stealth SDK
#[derive(Error, Debug)]
pub enum StealthError {
    #[error("Invalid meta-address format: {0}")]
    InvalidMetaAddress(String),

    #[error("Invalid stealth address: {0}")]
    InvalidStealthAddress(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Solana client error: {0}")]
    SolanaClientError(String),

    #[error("No payments found for this meta-address")]
    NoPaymentsFound,

    #[error("Invalid ephemeral public key")]
    InvalidEphemeralKey,
}

pub type Result<T> = std::result::Result<T, StealthError>;
