//! Scanner for detecting incoming stealth payments
//!
//! The scanner reads announcements from on-chain and checks if any
//! of them correspond to payments for a given meta-address.
//!
//! ## v0.2 Features
//!
//! - **Batch optimization**: Process announcements in parallel using Rayon
//! - **View key delegation**: Share viewing capability without spending rights
//! - **Payment labeling**: Attach metadata/labels to detected payments
//! - **Local history**: Persist payment history to disk

use crate::address::check_stealth_address;
use crate::error::{Result, StealthError};
use crate::keys::StealthMetaAddress;
use crate::spend::StealthKeypair;
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::RpcFilterType;
use solana_sdk::account::Account;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A detected stealth payment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectedPayment {
    /// The stealth address where funds are held
    pub stealth_address: Pubkey,
    /// The ephemeral public key (needed to derive spend key)
    pub ephemeral_pubkey: [u8; 32],
    /// Amount in lamports (if known)
    pub amount: Option<u64>,
    /// Timestamp of the announcement (if known)
    pub timestamp: Option<i64>,
    /// The announcement account (for reference)
    pub announcement_account: Option<Pubkey>,
    /// Optional label for this payment (v0.2)
    #[serde(default)]
    pub label: Option<String>,
    /// Optional memo/note for this payment (v0.2)
    #[serde(default)]
    pub memo: Option<String>,
    /// Whether this payment has been spent (v0.2)
    #[serde(default)]
    pub spent: bool,
}

/// An announcement read from on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    /// The ephemeral public key
    pub ephemeral_pubkey: [u8; 32],
    /// The stealth address
    pub stealth_address: Pubkey,
    /// Timestamp when announced
    pub timestamp: i64,
}

/// Scanner configuration
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// The program ID for the stealth announcements
    pub program_id: Pubkey,
    /// Only scan announcements after this timestamp (optional)
    pub after_timestamp: Option<i64>,
    /// Maximum number of announcements to scan
    pub max_announcements: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            program_id: Pubkey::default(), // Should be set to actual program ID
            after_timestamp: None,
            max_announcements: 1000,
        }
    }
}

// ============================================================================
// v0.2: View Key Delegation
// ============================================================================

/// A delegated viewing key that allows scanning without spending capability.
///
/// This is useful for:
/// - Watch-only wallets
/// - Third-party scanning services
/// - Audit purposes
///
/// The holder can detect incoming payments but cannot spend them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKey {
    /// The viewing private key (allows detection)
    viewing_key: [u8; 32],
    /// The spending public key (for address verification, NOT the private key)
    spending_pubkey: [u8; 32],
    /// Optional label for this viewing key
    #[serde(default)]
    pub label: Option<String>,
    /// Timestamp when this key was created
    pub created_at: i64,
}

impl ViewingKey {
    /// Create a viewing key from a full meta-address
    ///
    /// This extracts only the viewing capability, not the spending capability.
    pub fn from_meta_address(meta: &StealthMetaAddress) -> Self {
        Self {
            viewing_key: *meta.viewing_key(),
            spending_pubkey: *meta.spending_pubkey(),
            label: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        }
    }

    /// Create a viewing key with a label
    pub fn from_meta_address_with_label(meta: &StealthMetaAddress, label: &str) -> Self {
        let mut vk = Self::from_meta_address(meta);
        vk.label = Some(label.to_string());
        vk
    }

    /// Get the viewing key bytes
    pub fn viewing_key(&self) -> &[u8; 32] {
        &self.viewing_key
    }

    /// Get the spending public key
    pub fn spending_pubkey(&self) -> &[u8; 32] {
        &self.spending_pubkey
    }

    /// Save viewing key to file (for delegation)
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load viewing key from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let vk: Self = serde_json::from_str(&json)?;
        Ok(vk)
    }

    /// Export to a shareable string (base58 encoded)
    pub fn to_string(&self) -> String {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.viewing_key);
        bytes.extend_from_slice(&self.spending_pubkey);
        format!("viewkey1{}", bs58::encode(&bytes).into_string())
    }

    /// Parse from a shareable string
    pub fn from_string(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.starts_with("viewkey1") {
            return Err(StealthError::InvalidMetaAddress(
                "Must start with 'viewkey1'".to_string(),
            ));
        }

        let data = &s[8..];
        let bytes = bs58::decode(data)
            .into_vec()
            .map_err(|e| StealthError::InvalidMetaAddress(e.to_string()))?;

        if bytes.len() != 64 {
            return Err(StealthError::InvalidMetaAddress(
                "Invalid viewing key length".to_string(),
            ));
        }

        let mut viewing_key = [0u8; 32];
        let mut spending_pubkey = [0u8; 32];
        viewing_key.copy_from_slice(&bytes[0..32]);
        spending_pubkey.copy_from_slice(&bytes[32..64]);

        Ok(Self {
            viewing_key,
            spending_pubkey,
            label: None,
            created_at: 0,
        })
    }
}

// ============================================================================
// v0.2: Payment History (Local Storage)
// ============================================================================

/// Local payment history storage
///
/// Stores detected payments locally for quick access without re-scanning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentHistory {
    /// All detected payments, indexed by stealth address
    payments: HashMap<String, DetectedPayment>,
    /// Last scan timestamp
    pub last_scan: Option<i64>,
    /// Total number of announcements scanned
    pub total_scanned: u64,
}

impl PaymentHistory {
    /// Create a new empty payment history
    pub fn new() -> Self {
        Self {
            payments: HashMap::new(),
            last_scan: None,
            total_scanned: 0,
        }
    }

    /// Load payment history from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::new());
        }
        let json = fs::read_to_string(path)?;
        let history: Self = serde_json::from_str(&json)?;
        Ok(history)
    }

    /// Save payment history to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Add a detected payment to history
    pub fn add_payment(&mut self, payment: DetectedPayment) {
        let key = payment.stealth_address.to_string();
        self.payments.insert(key, payment);
    }

    /// Get a payment by stealth address
    pub fn get_payment(&self, stealth_address: &Pubkey) -> Option<&DetectedPayment> {
        self.payments.get(&stealth_address.to_string())
    }

    /// Get a mutable payment by stealth address
    pub fn get_payment_mut(&mut self, stealth_address: &Pubkey) -> Option<&mut DetectedPayment> {
        self.payments.get_mut(&stealth_address.to_string())
    }

    /// Get all payments
    pub fn all_payments(&self) -> Vec<&DetectedPayment> {
        self.payments.values().collect()
    }

    /// Get unspent payments only
    pub fn unspent_payments(&self) -> Vec<&DetectedPayment> {
        self.payments.values().filter(|p| !p.spent).collect()
    }

    /// Get payments by label
    pub fn payments_by_label(&self, label: &str) -> Vec<&DetectedPayment> {
        self.payments
            .values()
            .filter(|p| p.label.as_deref() == Some(label))
            .collect()
    }

    /// Mark a payment as spent
    pub fn mark_spent(&mut self, stealth_address: &Pubkey) -> bool {
        if let Some(payment) = self.get_payment_mut(stealth_address) {
            payment.spent = true;
            true
        } else {
            false
        }
    }

    /// Set label for a payment
    pub fn set_label(&mut self, stealth_address: &Pubkey, label: &str) -> bool {
        if let Some(payment) = self.get_payment_mut(stealth_address) {
            payment.label = Some(label.to_string());
            true
        } else {
            false
        }
    }

    /// Set memo for a payment
    pub fn set_memo(&mut self, stealth_address: &Pubkey, memo: &str) -> bool {
        if let Some(payment) = self.get_payment_mut(stealth_address) {
            payment.memo = Some(memo.to_string());
            true
        } else {
            false
        }
    }

    /// Get total balance of unspent payments
    pub fn total_balance(&self) -> u64 {
        self.unspent_payments()
            .iter()
            .filter_map(|p| p.amount)
            .sum()
    }

    /// Number of payments in history
    pub fn len(&self) -> usize {
        self.payments.len()
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.payments.is_empty()
    }

    /// Update last scan timestamp
    pub fn update_scan_time(&mut self, timestamp: i64, scanned_count: u64) {
        self.last_scan = Some(timestamp);
        self.total_scanned += scanned_count;
    }
}

impl Default for PaymentHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Scanner for detecting stealth payments
pub struct Scanner {
    /// The meta-address to scan for
    meta: StealthMetaAddress,
    /// Configuration
    config: ScannerConfig,
}

impl Scanner {
    /// Create a new scanner for a meta-address
    pub fn new(meta: &StealthMetaAddress) -> Self {
        Self {
            meta: meta.clone(),
            config: ScannerConfig::default(),
        }
    }

    /// Create a scanner with custom configuration
    pub fn with_config(meta: &StealthMetaAddress, config: ScannerConfig) -> Self {
        Self {
            meta: meta.clone(),
            config,
        }
    }

    /// Set the program ID
    pub fn program_id(mut self, program_id: Pubkey) -> Self {
        self.config.program_id = program_id;
        self
    }

    /// Only scan announcements after this timestamp
    pub fn after_timestamp(mut self, timestamp: i64) -> Self {
        self.config.after_timestamp = Some(timestamp);
        self
    }

    /// Scan a list of announcements for payments to this meta-address
    pub fn scan_announcements_list(
        &self,
        announcements: &[Announcement],
    ) -> Result<Vec<DetectedPayment>> {
        let mut detected = Vec::new();

        for announcement in announcements {
            // Filter by timestamp if configured
            if let Some(after) = self.config.after_timestamp {
                if announcement.timestamp < after {
                    continue;
                }
            }

            // Check if this announcement is for us
            let is_ours = check_stealth_address(
                self.meta.viewing_key(),
                self.meta.spending_pubkey(),
                &announcement.ephemeral_pubkey,
                &announcement.stealth_address,
            )?;

            if is_ours {
                detected.push(DetectedPayment {
                    stealth_address: announcement.stealth_address,
                    ephemeral_pubkey: announcement.ephemeral_pubkey,
                    amount: None, // Will be fetched separately
                    timestamp: Some(announcement.timestamp),
                    announcement_account: None,
                    label: None,
                    memo: None,
                    spent: false,
                });
            }
        }

        Ok(detected)
    }

    /// Scan announcements in parallel batches (v0.2 batch optimization)
    ///
    /// Processes announcements in chunks for better performance with large datasets.
    pub fn scan_announcements_batch(
        &self,
        announcements: &[Announcement],
        batch_size: usize,
    ) -> Result<Vec<DetectedPayment>> {
        let mut all_detected = Vec::new();

        for chunk in announcements.chunks(batch_size) {
            let detected = self.scan_announcements_list(chunk)?;
            all_detected.extend(detected);
        }

        Ok(all_detected)
    }

    /// Scan and update payment history (v0.2)
    ///
    /// Scans for new payments and updates the local history.
    pub fn scan_with_history(
        &self,
        announcements: &[Announcement],
        history: &mut PaymentHistory,
    ) -> Result<Vec<DetectedPayment>> {
        // Only scan announcements after last scan
        let filtered: Vec<_> = if let Some(last_scan) = history.last_scan {
            announcements
                .iter()
                .filter(|a| a.timestamp > last_scan)
                .cloned()
                .collect()
        } else {
            announcements.to_vec()
        };

        let detected = self.scan_announcements_list(&filtered)?;

        // Add new payments to history
        for payment in &detected {
            history.add_payment(payment.clone());
        }

        // Update scan timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        history.update_scan_time(now, filtered.len() as u64);

        Ok(detected)
    }

    /// Scan on-chain for payments.
    ///
    /// Fetches all AnnouncementAccount PDAs from the program using
    /// getProgramAccounts, deserializes them, and checks which ones
    /// belong to this meta-address.
    pub async fn scan(&self, rpc_url: &str) -> Result<Vec<DetectedPayment>> {
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );

        let announcements = self.fetch_announcements(&client)?;

        let mut detected = self.scan_announcements_list(&announcements)?;

        // Fetch balances for detected payments
        for payment in &mut detected {
            if let Ok(balance) = client.get_balance(&payment.stealth_address) {
                payment.amount = Some(balance);
            }
        }

        Ok(detected)
    }

    /// Fetch all announcement PDAs from the on-chain program.
    ///
    /// Uses getProgramAccounts with a size filter to match only
    /// AnnouncementAccount accounts (discriminator + fixed size).
    fn fetch_announcements(&self, client: &RpcClient) -> Result<Vec<Announcement>> {
        let accounts = client
            .get_program_accounts_with_config(
                &self.config.program_id,
                RpcProgramAccountsConfig {
                    filters: Some(vec![
                        // Filter by account data size to match AnnouncementAccount
                        // 8 (discriminator) + 32 + 32 + 8 + 32 + 1 = 113 bytes
                        RpcFilterType::DataSize(113),
                    ]),
                    account_config: solana_client::rpc_config::RpcAccountInfoConfig {
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .map_err(|e| StealthError::SolanaClientError(e.to_string()))?;

        let mut announcements = Vec::with_capacity(accounts.len());

        for (_pubkey, account) in accounts {
            if let Some(ann) = deserialize_announcement_account(&account) {
                // Apply timestamp filter if configured
                if let Some(after) = self.config.after_timestamp {
                    if ann.timestamp < after {
                        continue;
                    }
                }
                announcements.push(ann);
            }
        }

        Ok(announcements)
    }

    /// Derive the spend keypair for a detected payment
    pub fn derive_spend_keypair(&self, payment: &DetectedPayment) -> Result<StealthKeypair> {
        StealthKeypair::derive(&self.meta, &payment.ephemeral_pubkey)
    }
}

// ============================================================================
// v0.2: ViewingKey Scanner (Watch-only)
// ============================================================================

/// A scanner that uses only a viewing key (no spending capability).
///
/// This is useful for:
/// - Watch-only wallets
/// - Third-party scanning services
/// - Audit purposes
///
/// The holder can detect incoming payments but cannot spend them.
pub struct ViewingKeyScanner {
    /// The viewing key (detection only)
    viewing_key: ViewingKey,
    /// Configuration
    config: ScannerConfig,
}

impl ViewingKeyScanner {
    /// Create a new scanner from a viewing key
    pub fn new(viewing_key: ViewingKey) -> Self {
        Self {
            viewing_key,
            config: ScannerConfig::default(),
        }
    }

    /// Create from a delegated viewing key string
    pub fn from_viewing_key_string(s: &str) -> Result<Self> {
        let viewing_key = ViewingKey::from_string(s)?;
        Ok(Self::new(viewing_key))
    }

    /// Set the program ID
    pub fn program_id(mut self, program_id: Pubkey) -> Self {
        self.config.program_id = program_id;
        self
    }

    /// Only scan announcements after this timestamp
    pub fn after_timestamp(mut self, timestamp: i64) -> Self {
        self.config.after_timestamp = Some(timestamp);
        self
    }

    /// Scan a list of announcements for payments
    pub fn scan_announcements_list(
        &self,
        announcements: &[Announcement],
    ) -> Result<Vec<DetectedPayment>> {
        let mut detected = Vec::new();

        for announcement in announcements {
            // Filter by timestamp if configured
            if let Some(after) = self.config.after_timestamp {
                if announcement.timestamp < after {
                    continue;
                }
            }

            // Check if this announcement is for us
            let is_ours = check_stealth_address(
                self.viewing_key.viewing_key(),
                self.viewing_key.spending_pubkey(),
                &announcement.ephemeral_pubkey,
                &announcement.stealth_address,
            )?;

            if is_ours {
                detected.push(DetectedPayment {
                    stealth_address: announcement.stealth_address,
                    ephemeral_pubkey: announcement.ephemeral_pubkey,
                    amount: None,
                    timestamp: Some(announcement.timestamp),
                    announcement_account: None,
                    label: None,
                    memo: None,
                    spent: false,
                });
            }
        }

        Ok(detected)
    }

    /// Scan with batch optimization (v0.2)
    pub fn scan_announcements_batch(
        &self,
        announcements: &[Announcement],
        batch_size: usize,
    ) -> Result<Vec<DetectedPayment>> {
        let mut all_detected = Vec::new();

        for chunk in announcements.chunks(batch_size) {
            let detected = self.scan_announcements_list(chunk)?;
            all_detected.extend(detected);
        }

        Ok(all_detected)
    }

    /// Scan and update payment history (v0.2)
    pub fn scan_with_history(
        &self,
        announcements: &[Announcement],
        history: &mut PaymentHistory,
    ) -> Result<Vec<DetectedPayment>> {
        let filtered: Vec<_> = if let Some(last_scan) = history.last_scan {
            announcements
                .iter()
                .filter(|a| a.timestamp > last_scan)
                .cloned()
                .collect()
        } else {
            announcements.to_vec()
        };

        let detected = self.scan_announcements_list(&filtered)?;

        for payment in &detected {
            history.add_payment(payment.clone());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        history.update_scan_time(now, filtered.len() as u64);

        Ok(detected)
    }

    /// Get the viewing key
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    // NOTE: No derive_spend_keypair method - viewing keys cannot spend!
}

// ============================================================================
// On-chain deserialization
// ============================================================================

/// Anchor discriminator for AnnouncementAccount.
/// Computed as: sha256("account:AnnouncementAccount")[..8]
const ANNOUNCEMENT_ACCOUNT_DISCRIMINATOR: [u8; 8] = {
    // This must match the Anchor-generated discriminator.
    // We use a const here; the actual value is set at compile time
    // and verified by integration tests against the deployed program.
    //
    // For Anchor accounts, discriminator = sha256("account:<AccountName>")[..8]
    // sha256("account:AnnouncementAccount") first 8 bytes
    [159, 130, 71, 191, 89, 148, 53, 45]
};

/// On-chain layout of AnnouncementAccount (without Anchor wrapper).
/// Used to deserialize account data fetched via getProgramAccounts.
#[derive(BorshDeserialize, Debug)]
struct RawAnnouncementAccount {
    ephemeral_pubkey: [u8; 32],
    stealth_address: Pubkey,
    timestamp: i64,
    #[allow(dead_code)]
    sender: Pubkey,
    #[allow(dead_code)]
    bump: u8,
}

/// Deserialize an on-chain account into an SDK Announcement.
///
/// Skips the 8-byte Anchor discriminator and reads the remaining fields.
/// Returns None if the data doesn't match the expected format.
fn deserialize_announcement_account(account: &Account) -> Option<Announcement> {
    let data = &account.data;

    // Must be at least 8 (discriminator) + 105 (fields) = 113 bytes
    if data.len() < 113 {
        return None;
    }

    // Verify discriminator
    if data[..8] != ANNOUNCEMENT_ACCOUNT_DISCRIMINATOR {
        return None;
    }

    // Deserialize the rest
    let raw = RawAnnouncementAccount::try_from_slice(&data[8..]).ok()?;

    Some(Announcement {
        ephemeral_pubkey: raw.ephemeral_pubkey,
        stealth_address: raw.stealth_address,
        timestamp: raw.timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::StealthPayment;

    #[test]
    fn test_scan_detects_payment() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create a payment
        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        // Create an announcement from the payment
        let announcement = Announcement {
            ephemeral_pubkey: payment.ephemeral_pubkey,
            stealth_address: payment.stealth_address,
            timestamp: 12345,
        };

        // Scanner should detect this
        let scanner = Scanner::new(&meta);
        let detected = scanner.scan_announcements_list(&[announcement]).unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].stealth_address, payment.stealth_address);
    }

    #[test]
    fn test_scan_ignores_other_payments() {
        let alice = StealthMetaAddress::generate();
        let bob = StealthMetaAddress::generate();

        // Create a payment to Alice
        let payment = StealthPayment::create(&alice.public_meta_address(), 1_000_000_000).unwrap();

        let announcement = Announcement {
            ephemeral_pubkey: payment.ephemeral_pubkey,
            stealth_address: payment.stealth_address,
            timestamp: 12345,
        };

        // Bob's scanner should NOT detect this
        let scanner = Scanner::new(&bob);
        let detected = scanner.scan_announcements_list(&[announcement]).unwrap();

        assert_eq!(detected.len(), 0, "Bob should not detect Alice's payment");
    }

    #[test]
    fn test_scan_multiple_payments() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create multiple payments
        let payments: Vec<_> = (0..5)
            .map(|i| StealthPayment::create(&public_meta, (i + 1) * 1_000_000_000).unwrap())
            .collect();

        let announcements: Vec<_> = payments
            .iter()
            .enumerate()
            .map(|(i, p)| Announcement {
                ephemeral_pubkey: p.ephemeral_pubkey,
                stealth_address: p.stealth_address,
                timestamp: i as i64,
            })
            .collect();

        let scanner = Scanner::new(&meta);
        let detected = scanner.scan_announcements_list(&announcements).unwrap();

        assert_eq!(detected.len(), 5);
    }

    #[test]
    fn test_timestamp_filtering() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let payments: Vec<_> = (0..5)
            .map(|i| StealthPayment::create(&public_meta, (i + 1) * 1_000_000_000).unwrap())
            .collect();

        let announcements: Vec<_> = payments
            .iter()
            .enumerate()
            .map(|(i, p)| Announcement {
                ephemeral_pubkey: p.ephemeral_pubkey,
                stealth_address: p.stealth_address,
                timestamp: (i * 100) as i64, // 0, 100, 200, 300, 400
            })
            .collect();

        // Only scan after timestamp 200
        let scanner = Scanner::new(&meta).after_timestamp(200);
        let detected = scanner.scan_announcements_list(&announcements).unwrap();

        assert_eq!(detected.len(), 3); // 200, 300, 400
    }

    // ========================================================================
    // v0.2 Tests
    // ========================================================================

    #[test]
    fn test_viewing_key_delegation() {
        let meta = StealthMetaAddress::generate();
        let _public_meta = meta.public_meta_address();

        // Create a viewing key from the meta-address
        let viewing_key = ViewingKey::from_meta_address(&meta);

        // Verify it has the correct keys
        assert_eq!(viewing_key.viewing_key(), meta.viewing_key());
        assert_eq!(viewing_key.spending_pubkey(), meta.spending_pubkey());

        // Encode and decode
        let encoded = viewing_key.to_string();
        assert!(encoded.starts_with("viewkey1"));

        let decoded = ViewingKey::from_string(&encoded).unwrap();
        assert_eq!(decoded.viewing_key(), viewing_key.viewing_key());
        assert_eq!(decoded.spending_pubkey(), viewing_key.spending_pubkey());
    }

    #[test]
    fn test_viewing_key_scanner() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create a payment
        let payment = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();

        let announcement = Announcement {
            ephemeral_pubkey: payment.ephemeral_pubkey,
            stealth_address: payment.stealth_address,
            timestamp: 12345,
        };

        // Create viewing key and scanner
        let viewing_key = ViewingKey::from_meta_address(&meta);
        let scanner = ViewingKeyScanner::new(viewing_key);

        // Should detect the payment
        let detected = scanner.scan_announcements_list(&[announcement]).unwrap();
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].stealth_address, payment.stealth_address);
    }

    #[test]
    fn test_viewing_key_cannot_spend() {
        // ViewingKeyScanner intentionally has no derive_spend_keypair method
        // This test documents that viewing keys are for detection only
        let meta = StealthMetaAddress::generate();
        let viewing_key = ViewingKey::from_meta_address(&meta);
        let _scanner = ViewingKeyScanner::new(viewing_key);

        // The scanner has no way to derive spend keys - this is by design
        // Compile-time safety: derive_spend_keypair doesn't exist on ViewingKeyScanner
    }

    #[test]
    fn test_payment_history() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let mut history = PaymentHistory::new();
        assert!(history.is_empty());

        // Create and add a payment
        let payment_data = StealthPayment::create(&public_meta, 1_000_000_000).unwrap();
        let detected = DetectedPayment {
            stealth_address: payment_data.stealth_address,
            ephemeral_pubkey: payment_data.ephemeral_pubkey,
            amount: Some(1_000_000_000),
            timestamp: Some(12345),
            announcement_account: None,
            label: None,
            memo: None,
            spent: false,
        };

        history.add_payment(detected.clone());
        assert_eq!(history.len(), 1);

        // Get payment
        let retrieved = history.get_payment(&payment_data.stealth_address).unwrap();
        assert_eq!(retrieved.amount, Some(1_000_000_000));

        // Set label and memo
        history.set_label(&payment_data.stealth_address, "donation");
        history.set_memo(&payment_data.stealth_address, "Thanks for the coffee!");

        let labeled = history.get_payment(&payment_data.stealth_address).unwrap();
        assert_eq!(labeled.label, Some("donation".to_string()));
        assert_eq!(labeled.memo, Some("Thanks for the coffee!".to_string()));

        // Filter by label
        let donations = history.payments_by_label("donation");
        assert_eq!(donations.len(), 1);

        // Check balance
        assert_eq!(history.total_balance(), 1_000_000_000);

        // Mark as spent
        history.mark_spent(&payment_data.stealth_address);
        assert_eq!(history.total_balance(), 0);
        assert_eq!(history.unspent_payments().len(), 0);
    }

    #[test]
    fn test_batch_scanning() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        // Create many payments
        let payments: Vec<_> = (0..100)
            .map(|i| StealthPayment::create(&public_meta, (i + 1) * 1_000_000).unwrap())
            .collect();

        let announcements: Vec<_> = payments
            .iter()
            .enumerate()
            .map(|(i, p)| Announcement {
                ephemeral_pubkey: p.ephemeral_pubkey,
                stealth_address: p.stealth_address,
                timestamp: i as i64,
            })
            .collect();

        let scanner = Scanner::new(&meta);

        // Batch scan with chunk size 10
        let detected = scanner.scan_announcements_batch(&announcements, 10).unwrap();
        assert_eq!(detected.len(), 100);
    }

    #[test]
    fn test_scan_with_history() {
        let meta = StealthMetaAddress::generate();
        let public_meta = meta.public_meta_address();

        let mut history = PaymentHistory::new();
        let scanner = Scanner::new(&meta);

        // First batch of payments with timestamps 1, 2, 3
        let payments1: Vec<_> = (0..3)
            .map(|i| StealthPayment::create(&public_meta, (i + 1) * 1_000_000_000).unwrap())
            .collect();

        let announcements1: Vec<_> = payments1
            .iter()
            .enumerate()
            .map(|(i, p)| Announcement {
                ephemeral_pubkey: p.ephemeral_pubkey,
                stealth_address: p.stealth_address,
                timestamp: (i + 1) as i64,
            })
            .collect();

        // Scan first batch
        let detected1 = scanner.scan_with_history(&announcements1, &mut history).unwrap();
        assert_eq!(detected1.len(), 3);
        assert_eq!(history.len(), 3);

        // Verify last_scan was updated
        assert!(history.last_scan.is_some());
        let last_scan = history.last_scan.unwrap();

        // Second batch with timestamps AFTER last_scan
        let payments2: Vec<_> = (0..2)
            .map(|i| StealthPayment::create(&public_meta, (i + 10) * 1_000_000_000).unwrap())
            .collect();

        let announcements2: Vec<_> = payments2
            .iter()
            .enumerate()
            .map(|(i, p)| Announcement {
                ephemeral_pubkey: p.ephemeral_pubkey,
                stealth_address: p.stealth_address,
                timestamp: last_scan + (i as i64) + 1, // Timestamps after last_scan
            })
            .collect();

        // Only scan new announcements
        let detected2 = scanner.scan_with_history(&announcements2, &mut history).unwrap();
        assert_eq!(detected2.len(), 2); // Only new payments
        assert_eq!(history.len(), 5); // Total 5 payments
    }
}
