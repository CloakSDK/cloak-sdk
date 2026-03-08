//! Spend key derivation for stealth addresses
//!
//! After detecting a payment, the receiver needs to derive the private key
//! that can spend the funds at the stealth address.

use crate::error::{Result, StealthError};
use crate::keys::StealthMetaAddress;
use solana_sdk::signature::{keypair_from_seed, Keypair};
use solana_sdk::signer::Signer;

/// A spendable keypair derived from a stealth payment
pub struct StealthKeypair {
    /// The Solana keypair (contains both secret and public key)
    keypair: Keypair,
}

impl StealthKeypair {
    /// Derive a spendable keypair from a meta-address and ephemeral pubkey
    ///
    /// This is what the receiver calls after detecting a payment to derive
    /// the private key that can spend the funds.
    pub fn derive(
        meta: &StealthMetaAddress,
        ephemeral_pubkey: &[u8; 32],
    ) -> Result<Self> {
        // Get the derived spend key (32 bytes seed)
        let spend_key_bytes = meta.derive_spend_key(ephemeral_pubkey)?;

        // Use Solana's keypair_from_seed which properly handles Ed25519 key derivation
        // This applies the correct clamping and derives the public key correctly
        let keypair = keypair_from_seed(&spend_key_bytes)
            .map_err(|e| StealthError::CryptoError(format!("Failed to derive keypair: {}", e)))?;

        Ok(Self { keypair })
    }

    /// Get the stealth address (public key)
    pub fn address(&self) -> solana_sdk::pubkey::Pubkey {
        self.keypair.pubkey()
    }

    /// Get the private key bytes (the seed used for derivation)
    pub fn private_key(&self) -> [u8; 32] {
        // Return the secret key portion
        let bytes = self.keypair.to_bytes();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[..32]);
        secret
    }

    /// Convert to a Solana Keypair for signing transactions
    pub fn to_solana_keypair(&self) -> Result<Keypair> {
        // Clone the keypair using insecure_clone (only method available)
        Ok(self.keypair.insecure_clone())
    }

    /// Get a reference to the inner keypair
    pub fn as_keypair(&self) -> &Keypair {
        &self.keypair
    }
}

impl std::fmt::Debug for StealthKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthKeypair")
            .field("address", &self.address().to_string())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::StealthPayment;

    #[test]
    fn test_derive_spend_key() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create a payment
        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        // Derive the spend keypair
        let stealth_keypair = StealthKeypair::derive(&meta, &payment.ephemeral_pubkey).unwrap();

        // The derived address MUST match the stealth address from the payment
        // Both use the same Ed25519-compatible derivation scheme
        assert_eq!(
            stealth_keypair.address(),
            payment.stealth_address,
            "Derived address should match payment's stealth address"
        );
    }

    #[test]
    fn test_to_solana_keypair() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();
        let stealth_keypair = StealthKeypair::derive(&meta, &payment.ephemeral_pubkey).unwrap();

        // Should be able to convert to Solana keypair
        let solana_keypair = stealth_keypair.to_solana_keypair().unwrap();

        // The public key should match
        assert_eq!(
            solana_keypair.pubkey().to_bytes(),
            stealth_keypair.address().to_bytes()
        );
    }

    #[test]
    fn test_different_ephemeral_different_keypair() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create two payments
        let payment1 = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();
        let payment2 = StealthPayment::create(&public_meta, 2_000_000_000).unwrap();

        // Derive keypairs for both
        let keypair1 = StealthKeypair::derive(&meta, &payment1.ephemeral_pubkey).unwrap();
        let keypair2 = StealthKeypair::derive(&meta, &payment2.ephemeral_pubkey).unwrap();

        // They should be different
        assert_ne!(
            keypair1.private_key(), keypair2.private_key(),
            "Different payments should produce different keypairs"
        );
        assert_ne!(keypair1.address(), keypair2.address());
    }
}
