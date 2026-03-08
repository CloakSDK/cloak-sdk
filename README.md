# Cloak SDK

**Privacy-preserving stealth addresses for Solana.**

Cloak SDK enables private payments on Solana using stealth addresses. Senders can transfer SOL to unique one-time addresses that only the intended recipient can detect and spend from, without revealing the recipient's identity on-chain.

## Features

- **Stealth Addresses** - Generate unique one-time addresses for each payment
- **Unlinkable Payments** - Observers cannot connect payments to your public identity
- **View Key Delegation** - Share viewing keys for watch-only wallets
- **Payment History** - Track and label payments with local persistence
- **Batch Scanning** - Efficiently scan multiple announcements at once
- **Ed25519 Compatible** - Works with Solana's native key format
- **Anchor Program** - Ready-to-deploy on-chain announcement registry

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
cloak-sdk = "0.2"
```

Or install via cargo:

```bash
cargo add cloak-sdk
```

## Quick Start

### Receiver: Generate a Stealth Meta-Address

```rust
use cloak_sdk::prelude::*;

// Generate new stealth meta-address
let meta = StealthMetaAddress::generate();

// Share this publicly to receive payments
let public_meta = meta.to_public();
println!("My stealth address: {}", public_meta.encode());

// Save privately (contains spending key!)
meta.save_to_file("~/.cloak/keys.json")?;
```

### Sender: Create a Stealth Payment

```rust
use cloak_sdk::prelude::*;

// Parse receiver's public meta-address
let public_meta = PublicMetaAddress::decode("st:sol:...")?;

// Create stealth payment
let payment = StealthPayment::create(&public_meta)?;

println!("Send SOL to: {}", payment.stealth_address);
println!("Ephemeral key: {}", hex::encode(&payment.ephemeral_pubkey));

// Transfer SOL to payment.stealth_address
// Publish payment.ephemeral_pubkey to the registry
```

### Receiver: Detect and Spend

```rust
use cloak_sdk::prelude::*;

// Load your meta-address
let meta = StealthMetaAddress::load_from_file("~/.cloak/keys.json")?;

// Check if a payment is for you
if let Some(_) = meta.try_detect(&ephemeral_pubkey)? {
    // Derive the keypair to spend
    let keypair = StealthKeypair::derive(&meta, &ephemeral_pubkey)?;

    // Use keypair.to_solana_keypair() to sign transactions
    println!("Can spend from: {}", keypair.address());
}
```

## Enhanced Scanning (v0.2)

### View Key Delegation

Delegate viewing capability to watch-only wallets without exposing spending keys:

```rust
use cloak_sdk::{StealthMetaAddress, ViewingKey, ViewingKeyScanner};

// Create a viewing key from your meta-address
let meta = StealthMetaAddress::load_from_file("~/.cloak/keys.json")?;
let viewing_key = ViewingKey::from_meta_address(&meta, Some("Mobile Wallet".to_string()));

// Export for watch-only wallet
viewing_key.save_to_file("viewing_key.json")?;

// Watch-only wallet can scan without spending capability
let vk = ViewingKey::load_from_file("viewing_key.json")?;
let scanner = ViewingKeyScanner::new(&vk);

for announcement in announcements {
    if let Some(payment) = scanner.try_detect(&announcement.ephemeral_pubkey, &announcement.stealth_address)? {
        println!("Detected payment: {} lamports", payment.amount);
        // Note: Cannot spend - only viewing
    }
}
```

### Payment History

Track detected payments with labels and persistence:

```rust
use cloak_sdk::{PaymentHistory, Scanner};

// Create scanner with history
let meta = StealthMetaAddress::load_from_file("~/.cloak/keys.json")?;
let scanner = Scanner::new(&meta);
let mut history = PaymentHistory::new();

// Scan with automatic history tracking
let new_payments = scanner.scan_with_history(&announcements, &mut history)?;
println!("Found {} new payments", new_payments.len());

// Label a payment
history.label_payment(&stealth_address.to_string(), "Payment from Alice");

// Mark as spent
history.mark_spent(&stealth_address.to_string());

// Persist history
history.save_to_file("~/.cloak/history.json")?;

// Load history on next run
let history = PaymentHistory::load_from_file("~/.cloak/history.json")?;
```

### Batch Scanning

Efficiently scan multiple announcements:

```rust
use cloak_sdk::Scanner;

let scanner = Scanner::new(&meta);

// Scan a batch of announcements
let detected = scanner.scan_announcements_batch(&announcements)?;

for payment in detected {
    println!("Payment to {} - {} lamports", payment.stealth_address, payment.amount);
}
```

## How It Works

1. **Receiver** generates a stealth meta-address (spending + viewing keypairs) and shares the public portion
2. **Sender** uses the meta-address to derive a unique stealth address and ephemeral keypair
3. **Sender** transfers SOL to the stealth address and publishes the ephemeral public key
4. **Receiver** scans ephemeral keys, detects payments meant for them, and derives the spending key

The cryptographic scheme uses ECDH (Elliptic Curve Diffie-Hellman) to create shared secrets that allow the receiver to derive the same stealth address and spending key that the sender generated.

## Project Structure

```
cloak-sdk/
├── crates/
│   ├── core/       # Main SDK library (cloak-sdk)
│   └── program/    # Anchor program (cloak-program)
└── cli/            # Command-line interface (cloak)
```

## CLI Usage

```bash
# Install
cargo install --path cli

# Generate new stealth meta-address
cloak init

# Show your public meta-address
cloak address

# Send SOL to a stealth address
cloak send <recipient-meta-address> <amount>

# Check balance
cloak balance <address>
```

## Anchor Program

The `cloak-program` provides an on-chain registry for stealth payment announcements:

- `initialize` - Create the announcement registry (PDA)
- `send_stealth` - Transfer SOL + register announcement in one transaction
- `announce` - Register an announcement without transfer

## Security

- **Private keys** are never transmitted or stored on-chain
- **Viewing keys** allow detection without spending capability
- **Spending keys** are derived deterministically from the shared secret
- Uses SHA-256 for key derivation with domain separation

## Changelog

### v0.2.0
- **View Key Delegation** - Export viewing keys for watch-only wallets
- **Payment History** - Local persistence with labels and spent tracking
- **Batch Scanning** - `scan_announcements_batch()` for efficient bulk scanning
- **Incremental Scanning** - `scan_with_history()` to avoid re-processing
- **Payment Labels** - Add custom labels and memos to detected payments

### v0.1.0
- Initial release with stealth address generation
- ECDH-based payment detection
- Solana Ed25519 compatibility
- Basic scanner implementation

## License

MIT OR Apache-2.0
