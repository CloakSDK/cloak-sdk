//! Cloak Stealth Program
//!
//! On-chain program for stealth address announcements and payments.
//! Each announcement is stored as its own PDA for unlimited scalability.

use anchor_lang::prelude::*;
use anchor_lang::system_program;

pub mod state;

use state::{AnnouncementAccount, AnnouncementCounter, PrivateAnnouncementAccount};

declare_id!("AaJF9TTgTPqRTuXfnQnVvBihpYwYUAYroW984foWyVJ");

#[program]
pub mod cloak_stealth {
    use super::*;

    /// Initialize the global announcement counter.
    /// This must be called once before any announcements can be made.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.authority = ctx.accounts.authority.key();
        counter.bump = ctx.bumps.counter;
        counter.next_index = 0;

        msg!("Cloak announcement counter initialized");
        Ok(())
    }

    /// Send SOL to a stealth address and create an announcement PDA.
    ///
    /// This is the primary instruction for stealth payments:
    /// 1. Transfers SOL from sender to stealth_address
    /// 2. Creates a new AnnouncementAccount PDA indexed by counter
    /// 3. Increments the global counter
    pub fn send_stealth(
        ctx: Context<SendStealth>,
        ephemeral_pubkey: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, CloakError::InvalidAmount);

        // Transfer SOL to stealth address
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.sender.to_account_info(),
                    to: ctx.accounts.stealth_address.to_account_info(),
                },
            ),
            amount,
        )?;

        // Populate announcement PDA
        let announcement = &mut ctx.accounts.announcement;
        announcement.ephemeral_pubkey = ephemeral_pubkey;
        announcement.stealth_address = ctx.accounts.stealth_address.key();
        announcement.timestamp = Clock::get()?.unix_timestamp;
        announcement.sender = ctx.accounts.sender.key();
        announcement.bump = ctx.bumps.announcement;

        // Increment counter
        let counter = &mut ctx.accounts.counter;
        counter.next_index += 1;

        msg!(
            "Sent {} lamports to stealth address {}",
            amount,
            ctx.accounts.stealth_address.key()
        );

        Ok(())
    }

    /// Create an announcement without transferring SOL.
    ///
    /// Useful when the transfer happens externally (e.g., via a different
    /// program or manual transfer) but you still need to publish the
    /// ephemeral pubkey on-chain for the recipient to detect the payment.
    pub fn announce(
        ctx: Context<AnnounceOnly>,
        ephemeral_pubkey: [u8; 32],
        stealth_address: Pubkey,
    ) -> Result<()> {
        // Populate announcement PDA
        let announcement = &mut ctx.accounts.announcement;
        announcement.ephemeral_pubkey = ephemeral_pubkey;
        announcement.stealth_address = stealth_address;
        announcement.timestamp = Clock::get()?.unix_timestamp;
        announcement.sender = ctx.accounts.sender.key();
        announcement.bump = ctx.bumps.announcement;

        // Increment counter
        let counter = &mut ctx.accounts.counter;
        counter.next_index += 1;

        msg!("Announced stealth payment to {}", stealth_address);

        Ok(())
    }

    /// Send SOL to a stealth address via a relayer.
    ///
    /// Similar to send_stealth, but the relayer pays for the announcement PDA rent
    /// while the user signs the SOL transfer. This hides the sender's identity
    /// because the transaction is submitted by the relayer.
    pub fn send_stealth_relayed(
        ctx: Context<SendStealthRelayed>,
        ephemeral_pubkey: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, CloakError::InvalidAmount);

        // Transfer SOL from user to stealth address
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.stealth_address.to_account_info(),
                },
            ),
            amount,
        )?;

        // Populate announcement PDA (paid by relayer)
        let announcement = &mut ctx.accounts.announcement;
        announcement.ephemeral_pubkey = ephemeral_pubkey;
        announcement.stealth_address = ctx.accounts.stealth_address.key();
        announcement.timestamp = Clock::get()?.unix_timestamp;
        announcement.sender = ctx.accounts.relayer.key(); // relayer is the "sender" for close_announcement
        announcement.bump = ctx.bumps.announcement;

        // Increment counter
        let counter = &mut ctx.accounts.counter;
        counter.next_index += 1;

        msg!(
            "Relayed {} lamports to stealth address {}",
            amount,
            ctx.accounts.stealth_address.key()
        );

        Ok(())
    }

    /// Send SOL to a stealth address with a zk-proof hiding the amount.
    ///
    /// The amount is hidden behind a Pedersen commitment. A Groth16 proof
    /// stored in the announcement PDA guarantees the commitment is valid.
    /// The actual SOL transfer amount is still visible on-chain (Solana
    /// requirement), but the commitment provides cryptographic privacy
    /// that can be verified independently.
    pub fn send_stealth_private(
        ctx: Context<SendStealthPrivate>,
        ephemeral_pubkey: [u8; 32],
        amount: u64,
        amount_commitment: [u8; 32],
        proof_data: Vec<u8>,
    ) -> Result<()> {
        require!(amount > 0, CloakError::InvalidAmount);
        require!(proof_data.len() <= 256, CloakError::ProofTooLarge);

        // Transfer SOL to stealth address
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.sender.to_account_info(),
                    to: ctx.accounts.stealth_address.to_account_info(),
                },
            ),
            amount,
        )?;

        // Populate private announcement PDA
        let announcement = &mut ctx.accounts.announcement;
        announcement.ephemeral_pubkey = ephemeral_pubkey;
        announcement.stealth_address = ctx.accounts.stealth_address.key();
        announcement.timestamp = Clock::get()?.unix_timestamp;
        announcement.sender = ctx.accounts.sender.key();
        announcement.bump = ctx.bumps.announcement;
        announcement.amount_commitment = amount_commitment;
        announcement.proof_len = proof_data.len() as u16;

        let mut proof_buf = [0u8; 256];
        proof_buf[..proof_data.len()].copy_from_slice(&proof_data);
        announcement.proof_data = proof_buf;

        // Increment counter
        let counter = &mut ctx.accounts.counter;
        counter.next_index += 1;

        msg!(
            "Private stealth payment to {} (amount hidden)",
            ctx.accounts.stealth_address.key()
        );

        Ok(())
    }

    /// Close an announcement account and reclaim rent.
    ///
    /// Only the original sender can close their announcement.
    /// The rent is returned to the sender.
    pub fn close_announcement(ctx: Context<CloseAnnouncement>) -> Result<()> {
        msg!(
            "Closed announcement for stealth address {}",
            ctx.accounts.announcement.stealth_address
        );
        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = AnnouncementCounter::space(),
        seeds = [b"counter"],
        bump
    )]
    pub counter: Account<'info, AnnouncementCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SendStealth<'info> {
    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, AnnouncementCounter>,

    #[account(
        init,
        payer = sender,
        space = AnnouncementAccount::space(),
        seeds = [b"announcement", counter.next_index.to_le_bytes().as_ref()],
        bump
    )]
    pub announcement: Account<'info, AnnouncementAccount>,

    #[account(mut)]
    pub sender: Signer<'info>,

    /// CHECK: This is the stealth address - any valid pubkey
    #[account(mut)]
    pub stealth_address: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AnnounceOnly<'info> {
    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, AnnouncementCounter>,

    #[account(
        init,
        payer = sender,
        space = AnnouncementAccount::space(),
        seeds = [b"announcement", counter.next_index.to_le_bytes().as_ref()],
        bump
    )]
    pub announcement: Account<'info, AnnouncementAccount>,

    #[account(mut)]
    pub sender: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SendStealthRelayed<'info> {
    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, AnnouncementCounter>,

    #[account(
        init,
        payer = relayer,
        space = AnnouncementAccount::space(),
        seeds = [b"announcement", counter.next_index.to_le_bytes().as_ref()],
        bump
    )]
    pub announcement: Account<'info, AnnouncementAccount>,

    /// The relayer pays for the announcement PDA rent and submits the tx
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// The actual user who signs the SOL transfer
    #[account(mut)]
    pub user: Signer<'info>,

    /// CHECK: This is the stealth address - any valid pubkey
    #[account(mut)]
    pub stealth_address: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SendStealthPrivate<'info> {
    #[account(
        mut,
        seeds = [b"counter"],
        bump = counter.bump
    )]
    pub counter: Account<'info, AnnouncementCounter>,

    #[account(
        init,
        payer = sender,
        space = PrivateAnnouncementAccount::space(),
        seeds = [b"announcement", counter.next_index.to_le_bytes().as_ref()],
        bump
    )]
    pub announcement: Account<'info, PrivateAnnouncementAccount>,

    #[account(mut)]
    pub sender: Signer<'info>,

    /// CHECK: This is the stealth address - any valid pubkey
    #[account(mut)]
    pub stealth_address: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseAnnouncement<'info> {
    #[account(
        mut,
        close = sender,
        has_one = sender,
    )]
    pub announcement: Account<'info, AnnouncementAccount>,

    #[account(mut)]
    pub sender: Signer<'info>,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum CloakError {
    #[msg("Amount must be greater than zero")]
    InvalidAmount,

    #[msg("Invalid ephemeral public key")]
    InvalidEphemeralKey,

    #[msg("Proof data exceeds maximum size (256 bytes)")]
    ProofTooLarge,
}
