//! Zero-knowledge proof module for private amounts
//!
//! Uses Groth16 on BN254 to prove that a Pedersen commitment
//! hides a valid amount without revealing it.
//!
//! ## Scheme
//!
//! - **Pedersen Commitment**: `C = amount * G + blinding * H`
//!   where G and H are independent generators on BN254's scalar field.
//! - **ZK Circuit**: Proves knowledge of `amount` and `blinding` such that
//!   the commitment is correct and `amount > 0`.
//! - **On-chain**: Only the commitment bytes are stored, not the amount.
//! - **Receiver**: Gets the amount + blinding via an encrypted hint (off-chain or in memo).

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField};
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey,
};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StealthError};

// ============================================================================
// Pedersen Commitment (in scalar field, not EC points for simplicity on-chain)
// ============================================================================

/// Domain separator for the H generator derivation
const H_GENERATOR_DOMAIN: &[u8] = b"cloak-pedersen-h-generator-v1";

/// Derive the H generator deterministically from a domain separator.
/// H = hash_to_field(domain) so it's independent of G (the default generator = 1).
fn h_generator() -> Fr {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(H_GENERATOR_DOMAIN);
    let hash = hasher.finalize();
    // Convert hash to field element
    Fr::from_le_bytes_mod_order(&hash)
}

/// A Pedersen commitment to an amount.
///
/// `commitment = amount * G + blinding * H` computed in Fr (BN254 scalar field).
/// G = Fr::from(1) (generator), H = derived independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AmountCommitment {
    /// The commitment value (serialized as bytes)
    pub commitment_bytes: Vec<u8>,
    /// The blinding factor (private - only known to sender/receiver)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blinding: Option<Vec<u8>>,
    /// The actual amount (private - only known to sender/receiver)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
}

impl AmountCommitment {
    /// Create a new commitment to an amount.
    ///
    /// Returns the commitment and keeps the blinding factor for the proof.
    pub fn commit(amount: u64) -> Self {
        let mut rng = thread_rng();
        let blinding = Fr::rand(&mut rng);
        let h = h_generator();

        // commitment = amount + blinding * H (in scalar field)
        let amount_fr = Fr::from(amount);
        let commitment = amount_fr + blinding * h;

        let commitment_bytes = fr_to_bytes(&commitment);
        let blinding_bytes = fr_to_bytes(&blinding);

        Self {
            commitment_bytes,
            blinding: Some(blinding_bytes),
            amount: Some(amount),
        }
    }

    /// Create a public-only commitment (no private data).
    pub fn from_bytes(commitment_bytes: Vec<u8>) -> Self {
        Self {
            commitment_bytes,
            blinding: None,
            amount: None,
        }
    }

    /// Get the commitment as a field element.
    pub fn as_field_element(&self) -> Option<Fr> {
        fr_from_bytes(&self.commitment_bytes)
    }

    /// Verify that this commitment matches the given amount and blinding.
    pub fn verify_opening(&self, amount: u64, blinding_bytes: &[u8]) -> bool {
        let Some(blinding) = fr_from_bytes(blinding_bytes) else {
            return false;
        };
        let h = h_generator();
        let amount_fr = Fr::from(amount);
        let expected = amount_fr + blinding * h;
        let expected_bytes = fr_to_bytes(&expected);
        self.commitment_bytes == expected_bytes
    }
}

// ============================================================================
// ZK Circuit: Amount Commitment Proof
// ============================================================================

/// R1CS circuit that proves:
/// 1. Knowledge of `amount` and `blinding` such that `commitment = amount + blinding * H`
/// 2. `amount > 0` (i.e., amount != 0)
#[derive(Clone)]
pub struct AmountCircuit {
    /// The committed amount (private witness)
    pub amount: Option<Fr>,
    /// The blinding factor (private witness)
    pub blinding: Option<Fr>,
    /// The commitment value (public input)
    pub commitment: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for AmountCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> std::result::Result<(), SynthesisError> {
        let h = h_generator();

        // Allocate private witnesses
        let amount_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let blinding_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public input (the commitment)
        let commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // H as a constant
        let h_var = FpVar::<Fr>::new_constant(cs.clone(), h)?;

        // Constraint 1: commitment == amount + blinding * H
        let computed = &amount_var + &blinding_var * &h_var;
        computed.enforce_equal(&commitment_var)?;

        // Constraint 2: amount != 0 (amount is non-zero)
        // We prove amount is invertible (has a multiplicative inverse),
        // which is equivalent to amount != 0 in a prime field.
        let amount_inv = FpVar::<Fr>::new_witness(cs.clone(), || {
            let amt = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            amt.inverse().ok_or(SynthesisError::AssignmentMissing)
        })?;

        let one = FpVar::<Fr>::new_constant(cs, Fr::from(1u64))?;
        let product = &amount_var * &amount_inv;
        product.enforce_equal(&one)?;

        Ok(())
    }
}

// ============================================================================
// Proof generation and verification
// ============================================================================

/// A serialized Groth16 proof with public inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AmountProof {
    /// Serialized Groth16 proof bytes
    pub proof_bytes: Vec<u8>,
    /// Serialized public inputs (the commitment)
    pub public_inputs: Vec<Vec<u8>>,
}

/// Generate the proving and verifying keys for the amount circuit.
///
/// This is a one-time trusted setup. In production, this would be done
/// via a multi-party ceremony.
pub fn setup() -> Result<(ProvingKey<Bn254>, PreparedVerifyingKey<Bn254>)> {
    let circuit = AmountCircuit {
        amount: None,
        blinding: None,
        commitment: None,
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| StealthError::CryptoError(format!("ZK setup failed: {}", e)))?;

    let pvk = Groth16::<Bn254>::process_vk(&vk)
        .map_err(|e| StealthError::CryptoError(format!("VK processing failed: {}", e)))?;

    Ok((pk, pvk))
}

/// Generate a proof that a commitment hides a valid amount > 0.
pub fn prove(
    pk: &ProvingKey<Bn254>,
    amount: u64,
    commitment: &AmountCommitment,
) -> Result<AmountProof> {
    let amount_fr = Fr::from(amount);
    let blinding_bytes = commitment.blinding.as_ref()
        .ok_or_else(|| StealthError::CryptoError("Missing blinding factor".to_string()))?;
    let blinding = fr_from_bytes(blinding_bytes)
        .ok_or_else(|| StealthError::CryptoError("Invalid blinding bytes".to_string()))?;
    let commitment_fr = commitment.as_field_element()
        .ok_or_else(|| StealthError::CryptoError("Invalid commitment".to_string()))?;

    let circuit = AmountCircuit {
        amount: Some(amount_fr),
        blinding: Some(blinding),
        commitment: Some(commitment_fr),
    };

    let mut rng = thread_rng();
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| StealthError::CryptoError(format!("Proof generation failed: {}", e)))?;

    // Serialize proof
    let mut proof_bytes = Vec::new();
    use ark_serialize::CanonicalSerialize;
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| StealthError::CryptoError(format!("Proof serialization failed: {}", e)))?;

    let public_inputs = vec![fr_to_bytes(&commitment_fr)];

    Ok(AmountProof {
        proof_bytes,
        public_inputs,
    })
}

/// Verify a proof that a commitment hides a valid amount > 0.
pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof: &AmountProof,
) -> Result<bool> {
    use ark_serialize::CanonicalDeserialize;

    let groth_proof = Proof::<Bn254>::deserialize_compressed(&proof.proof_bytes[..])
        .map_err(|e| StealthError::CryptoError(format!("Proof deserialization failed: {}", e)))?;

    let public_inputs: Vec<Fr> = proof.public_inputs.iter()
        .filter_map(|b| fr_from_bytes(b))
        .collect();

    if public_inputs.len() != proof.public_inputs.len() {
        return Err(StealthError::CryptoError("Invalid public inputs".to_string()));
    }

    let valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &groth_proof)
        .map_err(|e| StealthError::CryptoError(format!("Verification failed: {}", e)))?;

    Ok(valid)
}

// ============================================================================
// Serialized keys for storage/transmission
// ============================================================================

/// Serialize proving key to bytes.
pub fn serialize_proving_key(pk: &ProvingKey<Bn254>) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| StealthError::CryptoError(format!("PK serialization failed: {}", e)))?;
    Ok(bytes)
}

/// Deserialize proving key from bytes.
pub fn deserialize_proving_key(bytes: &[u8]) -> Result<ProvingKey<Bn254>> {
    use ark_serialize::CanonicalDeserialize;
    ProvingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| StealthError::CryptoError(format!("PK deserialization failed: {}", e)))
}

/// Serialize verifying key to bytes.
pub fn serialize_verifying_key(pvk: &PreparedVerifyingKey<Bn254>) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    pvk.serialize_compressed(&mut bytes)
        .map_err(|e| StealthError::CryptoError(format!("VK serialization failed: {}", e)))?;
    Ok(bytes)
}

/// Deserialize verifying key from bytes.
pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<PreparedVerifyingKey<Bn254>> {
    use ark_serialize::CanonicalDeserialize;
    PreparedVerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| StealthError::CryptoError(format!("VK deserialization failed: {}", e)))
}

// ============================================================================
// Helpers
// ============================================================================

fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let bigint = fr.into_bigint();
    let mut bytes = Vec::new();
    for limb in bigint.0.iter() {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn fr_from_bytes(bytes: &[u8]) -> Option<Fr> {
    if bytes.len() < 32 {
        return None;
    }
    Fr::from_le_bytes_mod_order(bytes).into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        let commitment = AmountCommitment::commit(1_000_000_000);

        // Commitment should have data
        assert!(!commitment.commitment_bytes.is_empty());
        assert!(commitment.blinding.is_some());
        assert_eq!(commitment.amount, Some(1_000_000_000));

        // Should verify with correct opening
        let blinding = commitment.blinding.as_ref().unwrap();
        assert!(commitment.verify_opening(1_000_000_000, blinding));

        // Should fail with wrong amount
        assert!(!commitment.verify_opening(999_999_999, blinding));
    }

    #[test]
    fn test_different_amounts_different_commitments() {
        let c1 = AmountCommitment::commit(100);
        let c2 = AmountCommitment::commit(200);

        assert_ne!(c1.commitment_bytes, c2.commitment_bytes);
    }

    #[test]
    fn test_same_amount_different_commitments() {
        // Due to random blinding, same amount produces different commitments
        let c1 = AmountCommitment::commit(100);
        let c2 = AmountCommitment::commit(100);

        assert_ne!(c1.commitment_bytes, c2.commitment_bytes);
    }

    #[test]
    fn test_zk_proof_valid() {
        // Setup
        let (pk, pvk) = setup().unwrap();

        // Create commitment
        let commitment = AmountCommitment::commit(1_000_000_000);

        // Generate proof
        let proof = prove(&pk, 1_000_000_000, &commitment).unwrap();

        // Verify proof
        let valid = verify(&pvk, &proof).unwrap();
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_zk_proof_different_amounts() {
        let (pk, pvk) = setup().unwrap();

        // Test with various amounts
        for amount in [1u64, 100, 1_000_000, 1_000_000_000, u64::MAX / 2] {
            let commitment = AmountCommitment::commit(amount);
            let proof = prove(&pk, amount, &commitment).unwrap();
            let valid = verify(&pvk, &proof).unwrap();
            assert!(valid, "Proof for amount {} should verify", amount);
        }
    }

    #[test]
    fn test_zk_proof_wrong_commitment_fails() {
        let (pk, pvk) = setup().unwrap();

        // Create commitment for 1000
        let commitment = AmountCommitment::commit(1000);
        let proof = prove(&pk, 1000, &commitment).unwrap();

        // Tamper with the public input (commitment)
        let mut bad_proof = proof.clone();
        let fake_commitment = AmountCommitment::commit(2000);
        bad_proof.public_inputs = vec![fake_commitment.commitment_bytes];

        let valid = verify(&pvk, &bad_proof).unwrap();
        assert!(!valid, "Proof with tampered commitment should fail");
    }

    #[test]
    fn test_proof_serialization() {
        let (pk, pvk) = setup().unwrap();

        let commitment = AmountCommitment::commit(500);
        let proof = prove(&pk, 500, &commitment).unwrap();

        // Serialize/deserialize proof via JSON
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: AmountProof = serde_json::from_str(&json).unwrap();

        let valid = verify(&pvk, &deserialized).unwrap();
        assert!(valid, "Deserialized proof should verify");
    }

    #[test]
    fn test_key_serialization() {
        let (pk, pvk) = setup().unwrap();

        // Serialize keys
        let pk_bytes = serialize_proving_key(&pk).unwrap();
        let pvk_bytes = serialize_verifying_key(&pvk).unwrap();

        // Deserialize keys
        let pk2 = deserialize_proving_key(&pk_bytes).unwrap();
        let pvk2 = deserialize_verifying_key(&pvk_bytes).unwrap();

        // Prove with original pk, verify with deserialized pvk
        let commitment = AmountCommitment::commit(42);
        let proof = prove(&pk2, 42, &commitment).unwrap();
        let valid = verify(&pvk2, &proof).unwrap();
        assert!(valid);
    }
}
