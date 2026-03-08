//! Stealth address generation and payment creation
//!
//! This module handles the sender's side of stealth payments:
//! - Generating a unique stealth address from a recipient's meta-address
//! - Creating the ephemeral keypair
//! - Computing the shared secret
//!
//! # Cryptographic Scheme (Ed25519 Compatible)
//!
//! Instead of using point addition (which breaks Ed25519 compatibility),
//! we derive a seed from the shared secret and spending key, then use
//! Solana's `keypair_from_seed` to get a valid Ed25519 keypair.
//!
//! This ensures the stealth address can be spent using standard Solana signing.

use crate::error::{Result, StealthError};
use crate::keys::PublicMetaAddress;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::keypair_from_seed;
use solana_sdk::signer::Signer;

/// A stealth payment ready to be sent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthPayment {
    /// The stealth address where funds will be sent
    pub stealth_address: Pubkey,
    /// The ephemeral public key (must be published for receiver to detect)
    pub ephemeral_pubkey: [u8; 32],
    /// Amount in lamports
    pub amount: u64,
}

/// Ephemeral keypair used for a single payment
pub struct EphemeralKeypair {
    /// Private scalar (keep secret during payment creation)
    private_key: Scalar,
    /// Public key (publish on-chain)
    pub public_key: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a new random ephemeral keypair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Create scalar from seed
        let private_key = Scalar::from_bytes_mod_order(seed);

        // Compute public key: ephemeral_pubkey = private_key * G
        let public_point = &private_key * &ED25519_BASEPOINT_POINT;
        let public_key = public_point.compress().to_bytes();

        Self {
            private_key,
            public_key,
        }
    }

    /// Compute ECDH shared secret with recipient's viewing pubkey
    pub fn compute_shared_secret(&self, viewing_pubkey: &[u8; 32]) -> Result<[u8; 32]> {
        // Decompress the viewing public key
        let viewing_point = CompressedEdwardsY(*viewing_pubkey)
            .decompress()
            .ok_or_else(|| StealthError::InvalidPublicKey("Invalid viewing pubkey".to_string()))?;

        // shared_secret = ephemeral_private * viewing_pubkey
        let shared_point = viewing_point * self.private_key;

        Ok(shared_point.compress().to_bytes())
    }
}

impl StealthPayment {
    /// Create a new stealth payment to a recipient
    ///
    /// This generates:
    /// 1. A random ephemeral keypair
    /// 2. A shared secret via ECDH
    /// 3. A unique stealth address derived from the shared secret
    pub fn create(recipient: &PublicMetaAddress, amount: u64) -> Result<Self> {
        // Generate ephemeral keypair
        let ephemeral = EphemeralKeypair::generate();

        // Compute shared secret: ECDH(ephemeral_private, viewing_pubkey)
        let shared_secret = ephemeral.compute_shared_secret(recipient.viewing_pubkey())?;

        // Derive stealth address using Ed25519-compatible scheme
        let stealth_address = derive_stealth_address(recipient.spending_pubkey(), &shared_secret)?;

        Ok(Self {
            stealth_address,
            ephemeral_pubkey: ephemeral.public_key,
            amount,
        })
    }
}

/// A stealth payment with a zero-knowledge proof hiding the amount.
///
/// Instead of revealing the amount on-chain, a Pedersen commitment is stored.
/// The zk proof guarantees the commitment is valid and the amount > 0.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateStealthPayment {
    /// The stealth address where funds will be sent
    pub stealth_address: Pubkey,
    /// The ephemeral public key (must be published for receiver to detect)
    pub ephemeral_pubkey: [u8; 32],
    /// Pedersen commitment to the amount (public)
    pub commitment: crate::zk::AmountCommitment,
    /// Zero-knowledge proof that the commitment is valid
    pub proof: crate::zk::AmountProof,
}

impl PrivateStealthPayment {
    /// Create a new private stealth payment with a zk proof.
    ///
    /// The amount is hidden behind a Pedersen commitment and a Groth16 proof
    /// guarantees the commitment is valid and amount > 0.
    pub fn create(
        recipient: &PublicMetaAddress,
        amount: u64,
        proving_key: &ark_groth16::ProvingKey<ark_bn254::Bn254>,
    ) -> Result<Self> {
        let ephemeral = EphemeralKeypair::generate();
        let shared_secret = ephemeral.compute_shared_secret(recipient.viewing_pubkey())?;
        let stealth_address = derive_stealth_address(recipient.spending_pubkey(), &shared_secret)?;

        // Create Pedersen commitment
        let commitment = crate::zk::AmountCommitment::commit(amount);

        // Generate zk proof
        let proof = crate::zk::prove(proving_key, amount, &commitment)?;

        Ok(Self {
            stealth_address,
            ephemeral_pubkey: ephemeral.public_key,
            commitment,
            proof,
        })
    }

    /// Verify the zk proof for this payment.
    pub fn verify_proof(
        &self,
        verifying_key: &ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254>,
    ) -> Result<bool> {
        crate::zk::verify(verifying_key, &self.proof)
    }

    /// Get the amount hint for the receiver.
    ///
    /// Returns (amount, blinding_bytes) that the receiver needs to verify
    /// the commitment opening. This should be sent off-chain or encrypted.
    pub fn amount_hint(&self) -> Option<(u64, Vec<u8>)> {
        let amount = self.commitment.amount?;
        let blinding = self.commitment.blinding.clone()?;
        Some((amount, blinding))
    }
}

/// Derive a stealth address seed from spending pubkey and shared secret
///
/// This creates a deterministic 32-byte seed that can be used with
/// Ed25519 key derivation.
pub fn derive_stealth_seed(
    spending_pubkey: &[u8; 32],
    shared_secret: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"solana-stealth-seed-v1");
    hasher.update(spending_pubkey);
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Derive a stealth address from spending pubkey and shared secret
///
/// Uses Ed25519-compatible derivation: the seed is derived from
/// hash(spending_pubkey || shared_secret), then used with keypair_from_seed
/// to get a valid Ed25519 public key.
pub fn derive_stealth_address(
    spending_pubkey: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<Pubkey> {
    // Derive seed deterministically
    let seed = derive_stealth_seed(spending_pubkey, shared_secret);

    // Use Solana's keypair_from_seed which applies proper Ed25519 derivation
    let keypair = keypair_from_seed(&seed)
        .map_err(|e| StealthError::CryptoError(format!("Failed to derive keypair: {}", e)))?;

    Ok(keypair.pubkey())
}

/// Check if a stealth address matches a meta-address given an ephemeral pubkey
///
/// Used by the receiver to detect incoming payments
pub fn check_stealth_address(
    viewing_key: &[u8; 32],
    spending_pubkey: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    stealth_address: &Pubkey,
) -> Result<bool> {
    // Compute shared secret: ECDH(viewing_key, ephemeral_pubkey)
    let ephemeral_point = CompressedEdwardsY(*ephemeral_pubkey)
        .decompress()
        .ok_or_else(|| StealthError::InvalidEphemeralKey)?;

    let viewing_scalar = Scalar::from_bytes_mod_order(*viewing_key);
    let shared_point = ephemeral_point * viewing_scalar;
    let shared_secret = shared_point.compress().to_bytes();

    // Derive expected stealth address
    let expected_address = derive_stealth_address(spending_pubkey, &shared_secret)?;

    Ok(expected_address == *stealth_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::StealthMetaAddress;

    #[test]
    fn test_create_stealth_payment() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        // Stealth address should be valid
        assert_ne!(payment.stealth_address, Pubkey::default());

        // Ephemeral pubkey should be non-zero
        assert_ne!(payment.ephemeral_pubkey, [0u8; 32]);

        // Amount should match
        assert_eq!(payment.amount, 1_000_000_000);
    }

    #[test]
    fn test_stealth_address_detection() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create a payment
        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        // Receiver should be able to detect this payment
        let is_mine = check_stealth_address(
            meta.viewing_key(),
            meta.spending_pubkey(),
            &payment.ephemeral_pubkey,
            &payment.stealth_address,
        )
        .unwrap();

        assert!(is_mine, "Receiver should detect their own payment");
    }

    #[test]
    fn test_different_receiver_cannot_detect() {
        let alice = StealthMetaAddress::generate();
        let bob = StealthMetaAddress::generate();

        // Create payment to Alice
        let payment = StealthPayment::create(&alice.public_meta_address(), 1_000_000_000).unwrap();

        // Bob should NOT be able to detect this payment
        let is_bobs = check_stealth_address(
            bob.viewing_key(),
            bob.spending_pubkey(),
            &payment.ephemeral_pubkey,
            &payment.stealth_address,
        )
        .unwrap();

        assert!(!is_bobs, "Bob should not detect Alice's payment");
    }

    #[test]
    fn test_each_payment_unique_address() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let payment1 = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();
        let payment2 = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        // Each payment should have a unique stealth address
        assert_ne!(
            payment1.stealth_address, payment2.stealth_address,
            "Each payment should have a unique stealth address"
        );

        // And unique ephemeral pubkeys
        assert_ne!(payment1.ephemeral_pubkey, payment2.ephemeral_pubkey);
    }
}
