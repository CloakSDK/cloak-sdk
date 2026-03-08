//! Program state accounts

use anchor_lang::prelude::*;

/// A single stealth payment announcement stored as its own PDA.
///
/// Each announcement gets its own account, derived from:
///   seeds = [b"announcement", counter.to_le_bytes()]
///
/// This design scales indefinitely - no circular buffer, no overwrites.
#[account]
pub struct AnnouncementAccount {
    /// The ephemeral public key (for receiver to derive shared secret)
    pub ephemeral_pubkey: [u8; 32],
    /// The stealth address where funds were sent
    pub stealth_address: Pubkey,
    /// Unix timestamp when announced
    pub timestamp: i64,
    /// The sender (who paid for the account rent)
    pub sender: Pubkey,
    /// Bump seed for this PDA
    pub bump: u8,
}

impl AnnouncementAccount {
    pub const fn space() -> usize {
        8 +  // discriminator
        32 + // ephemeral_pubkey
        32 + // stealth_address
        8 +  // timestamp
        32 + // sender
        1    // bump
    }
}

/// A private stealth payment announcement with a zk commitment.
///
/// Instead of storing the amount on-chain, we store a Pedersen commitment
/// and a Groth16 proof that the commitment is valid.
#[account]
pub struct PrivateAnnouncementAccount {
    /// The ephemeral public key (for receiver to derive shared secret)
    pub ephemeral_pubkey: [u8; 32],
    /// The stealth address where funds were sent
    pub stealth_address: Pubkey,
    /// Unix timestamp when announced
    pub timestamp: i64,
    /// The sender (who paid for the account rent)
    pub sender: Pubkey,
    /// Bump seed for this PDA
    pub bump: u8,
    /// Pedersen commitment to the amount (32 bytes)
    pub amount_commitment: [u8; 32],
    /// Groth16 proof bytes (variable length, stored with a length prefix)
    pub proof_len: u16,
    /// Proof data (max 256 bytes for a compressed Groth16 proof)
    pub proof_data: [u8; 256],
}

impl PrivateAnnouncementAccount {
    pub const fn space() -> usize {
        8 +   // discriminator
        32 +  // ephemeral_pubkey
        32 +  // stealth_address
        8 +   // timestamp
        32 +  // sender
        1 +   // bump
        32 +  // amount_commitment
        2 +   // proof_len
        256   // proof_data
    }
}

/// Global counter for announcement indexing.
///
/// A single PDA (seeds = [b"counter"]) that tracks the total number
/// of announcements. Used to derive deterministic PDA addresses for
/// each new announcement.
#[account]
pub struct AnnouncementCounter {
    /// Authority that initialized the counter
    pub authority: Pubkey,
    /// Bump seed for this PDA
    pub bump: u8,
    /// Next index to use for a new announcement
    pub next_index: u64,
}

impl AnnouncementCounter {
    pub const fn space() -> usize {
        8 +  // discriminator
        32 + // authority
        1 +  // bump
        8    // next_index
    }
}
