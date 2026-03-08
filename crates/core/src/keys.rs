//! Key generation and management for Stealth Addresses
//!
//! A StealthMetaAddress consists of:
//! - spending_key: Used to spend received funds
//! - viewing_key: Used to scan and detect incoming payments
//!
//! The meta-address (public part) can be shared publicly for receiving payments.

use crate::error::{Result, StealthError};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Domain separator for key derivation
const SPENDING_KEY_DOMAIN: &[u8] = b"solana-stealth-spending-v1";
const VIEWING_KEY_DOMAIN: &[u8] = b"solana-stealth-viewing-v1";

/// A complete stealth meta-address with both private and public components.
///
/// This is what the receiver generates and keeps secret (the private keys).
/// The public part (spending_pubkey + viewing_pubkey) is shared for receiving payments.
#[derive(Clone, Serialize, Deserialize)]
pub struct StealthMetaAddress {
    /// Private spending key (keep secret!)
    spending_key: [u8; 32],
    /// Private viewing key (keep secret!)
    viewing_key: [u8; 32],
    /// Public spending key (share publicly)
    spending_pubkey: [u8; 32],
    /// Public viewing key (share publicly)
    viewing_pubkey: [u8; 32],
}

/// Public part of a meta-address (safe to share)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicMetaAddress {
    /// Public spending key
    pub spending_pubkey: [u8; 32],
    /// Public viewing key
    pub viewing_pubkey: [u8; 32],
}

impl StealthMetaAddress {
    /// Generate a new random stealth meta-address
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();

        // Generate random 32-byte seeds
        let mut spending_seed = [0u8; 32];
        let mut viewing_seed = [0u8; 32];

        rng.fill_bytes(&mut spending_seed);
        rng.fill_bytes(&mut viewing_seed);

        // Derive keys using domain separation
        let spending_key = Self::derive_key(&spending_seed, SPENDING_KEY_DOMAIN);
        let viewing_key = Self::derive_key(&viewing_seed, VIEWING_KEY_DOMAIN);

        // Generate public keys from private keys using curve25519-dalek
        let spending_scalar = Scalar::from_bytes_mod_order(spending_key);
        let viewing_scalar = Scalar::from_bytes_mod_order(viewing_key);

        let spending_point = &spending_scalar * &ED25519_BASEPOINT_POINT;
        let viewing_point = &viewing_scalar * &ED25519_BASEPOINT_POINT;

        let spending_pubkey = spending_point.compress().to_bytes();
        let viewing_pubkey = viewing_point.compress().to_bytes();

        Self {
            spending_key,
            viewing_key,
            spending_pubkey,
            viewing_pubkey,
        }
    }

    /// Derive a key using domain separation
    fn derive_key(seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(seed);
        hasher.finalize().into()
    }

    /// Get the public meta-address (safe to share)
    pub fn public_meta_address(&self) -> PublicMetaAddress {
        PublicMetaAddress {
            spending_pubkey: self.spending_pubkey,
            viewing_pubkey: self.viewing_pubkey,
        }
    }

    /// Get the spending private key (for deriving spend keys)
    pub fn spending_key(&self) -> &[u8; 32] {
        &self.spending_key
    }

    /// Get the viewing private key (for scanning payments)
    pub fn viewing_key(&self) -> &[u8; 32] {
        &self.viewing_key
    }

    /// Get the spending public key
    pub fn spending_pubkey(&self) -> &[u8; 32] {
        &self.spending_pubkey
    }

    /// Get the viewing public key
    pub fn viewing_pubkey(&self) -> &[u8; 32] {
        &self.viewing_pubkey
    }

    /// Encode the public meta-address to a string (for sharing)
    pub fn to_public_string(&self) -> String {
        self.public_meta_address().to_string()
    }

    /// Save the full meta-address (including private keys) to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load a meta-address from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let meta: Self = serde_json::from_str(&json)?;
        Ok(meta)
    }

    /// Derive the spend key seed for a specific payment
    ///
    /// This uses the same derivation as `derive_stealth_seed` to produce
    /// a 32-byte seed that can be used with `keypair_from_seed`.
    ///
    /// The seed is: hash(spending_pubkey || shared_secret)
    pub fn derive_spend_key(&self, ephemeral_pubkey: &[u8; 32]) -> Result<[u8; 32]> {
        // Compute shared secret: ECDH(viewing_key, ephemeral_pubkey)
        let shared_secret = self.compute_shared_secret(ephemeral_pubkey)?;

        // Use the same derivation as derive_stealth_seed in address.rs
        // seed = hash("solana-stealth-seed-v1" || spending_pubkey || shared_secret)
        let mut hasher = Sha256::new();
        hasher.update(b"solana-stealth-seed-v1");
        hasher.update(&self.spending_pubkey);
        hasher.update(&shared_secret);

        Ok(hasher.finalize().into())
    }

    /// Compute ECDH shared secret using viewing key
    pub(crate) fn compute_shared_secret(&self, ephemeral_pubkey: &[u8; 32]) -> Result<[u8; 32]> {
        // Convert ephemeral pubkey to curve point
        let ephemeral_point = curve25519_dalek::edwards::CompressedEdwardsY(*ephemeral_pubkey)
            .decompress()
            .ok_or_else(|| StealthError::InvalidEphemeralKey)?;

        // Multiply by viewing key scalar
        let viewing_scalar = Scalar::from_bytes_mod_order(self.viewing_key);
        let shared_point = ephemeral_point * viewing_scalar;

        Ok(shared_point.compress().to_bytes())
    }
}

impl PublicMetaAddress {
    /// Parse a public meta-address from a string
    pub fn from_string(s: &str) -> Result<Self> {
        // Format: "stealth1<spending_pubkey_b58><viewing_pubkey_b58>"
        let s = s.trim();

        if !s.starts_with("stealth1") {
            return Err(StealthError::InvalidMetaAddress(
                "Must start with 'stealth1'".to_string(),
            ));
        }

        let data = &s[8..]; // Skip "stealth1"
        let bytes = bs58::decode(data)
            .into_vec()
            .map_err(|e| StealthError::InvalidMetaAddress(e.to_string()))?;

        if bytes.len() != 64 {
            return Err(StealthError::InvalidMetaAddress(
                "Invalid length".to_string(),
            ));
        }

        let mut spending_pubkey = [0u8; 32];
        let mut viewing_pubkey = [0u8; 32];
        spending_pubkey.copy_from_slice(&bytes[0..32]);
        viewing_pubkey.copy_from_slice(&bytes[32..64]);

        Ok(Self {
            spending_pubkey,
            viewing_pubkey,
        })
    }

    /// Encode to a shareable string
    pub fn to_string(&self) -> String {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.spending_pubkey);
        bytes.extend_from_slice(&self.viewing_pubkey);
        format!("stealth1{}", bs58::encode(&bytes).into_string())
    }

    /// Get the spending public key
    pub fn spending_pubkey(&self) -> &[u8; 32] {
        &self.spending_pubkey
    }

    /// Get the viewing public key
    pub fn viewing_pubkey(&self) -> &[u8; 32] {
        &self.viewing_pubkey
    }
}

impl std::fmt::Display for PublicMetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Debug for StealthMetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthMetaAddress")
            .field("spending_pubkey", &hex::encode(&self.spending_pubkey))
            .field("viewing_pubkey", &hex::encode(&self.viewing_pubkey))
            .field("spending_key", &"[REDACTED]")
            .field("viewing_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_meta_address() {
        let meta = StealthMetaAddress::generate();

        // Keys should be non-zero
        assert_ne!(meta.spending_key, [0u8; 32]);
        assert_ne!(meta.viewing_key, [0u8; 32]);
        assert_ne!(meta.spending_pubkey, [0u8; 32]);
        assert_ne!(meta.viewing_pubkey, [0u8; 32]);

        // Spending and viewing keys should be different
        assert_ne!(meta.spending_key, meta.viewing_key);
    }

    #[test]
    fn test_public_meta_address_encoding() {
        let meta = StealthMetaAddress::generate();
        let public_addr = meta.public_meta_address();

        // Encode to string
        let encoded = public_addr.to_string();
        assert!(encoded.starts_with("stealth1"));

        // Decode back
        let decoded = PublicMetaAddress::from_string(&encoded).unwrap();
        assert_eq!(decoded.spending_pubkey, public_addr.spending_pubkey);
        assert_eq!(decoded.viewing_pubkey, public_addr.viewing_pubkey);
    }

    #[test]
    fn test_save_and_load() {
        let meta = StealthMetaAddress::generate();
        let temp_path = "/tmp/test_stealth_meta.json";

        meta.save_to_file(temp_path).unwrap();
        let loaded = StealthMetaAddress::load_from_file(temp_path).unwrap();

        assert_eq!(meta.spending_key, loaded.spending_key);
        assert_eq!(meta.viewing_key, loaded.viewing_key);
        assert_eq!(meta.spending_pubkey, loaded.spending_pubkey);
        assert_eq!(meta.viewing_pubkey, loaded.viewing_pubkey);

        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }
}
