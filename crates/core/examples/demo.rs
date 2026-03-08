//! Cloak SDK Demo - Stealth Payment Flow
//!
//! This example demonstrates the complete stealth payment flow without
//! requiring any blockchain connection. It proves the cryptography works.
//!
//! Run with: cargo run --example demo

use cloak_sdk::{Scanner, StealthMetaAddress, StealthPayment, StealthKeypair};

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           Cloak SDK - Stealth Payment Demo                  ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // Step 1: Alice generates her stealth meta-address
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 1: Alice generates her stealth meta-address           │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let alice_meta = StealthMetaAddress::generate();
    let alice_public = alice_meta.public_meta_address();

    println!("  Alice's public meta-address (shareable):");
    println!("  {}", alice_public.to_string());
    println!();

    // =========================================================================
    // Step 2: Bob creates a stealth payment to Alice
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 2: Bob creates a stealth payment to Alice             │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let amount = 1_000_000_000; // 1 SOL in lamports
    let payment = StealthPayment::create(&alice_public, amount).unwrap();

    println!("  Payment created:");
    println!("  • Stealth address: {}", payment.stealth_address);
    println!("  • Ephemeral pubkey: {}", hex::encode(&payment.ephemeral_pubkey[..8]));
    println!("  • Amount: {} lamports (1 SOL)", amount);
    println!();

    // =========================================================================
    // Step 3: Alice scans and detects the payment
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 3: Alice scans and detects the payment                │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // Simulate an announcement (what would be on-chain)
    let announcement = cloak_sdk::Announcement {
        ephemeral_pubkey: payment.ephemeral_pubkey,
        stealth_address: payment.stealth_address,
        timestamp: 1234567890,
    };

    let scanner = Scanner::new(&alice_meta);
    let detected = scanner.scan_announcements_list(&[announcement.clone()]).unwrap();

    println!("  Scanning {} announcement(s)...", 1);
    println!("  Found {} payment(s) for Alice!", detected.len());

    if let Some(found) = detected.first() {
        println!("  • Detected address: {}", found.stealth_address);
        println!();
    }

    // =========================================================================
    // Step 4: Alice derives the spending keypair
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 4: Alice derives the spending keypair                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let stealth_keypair = StealthKeypair::derive(&alice_meta, &payment.ephemeral_pubkey).unwrap();
    let derived_address = stealth_keypair.address();

    println!("  Derived keypair address: {}", derived_address);
    println!("  Original stealth address: {}", payment.stealth_address);
    println!();

    // =========================================================================
    // Step 5: Verify the addresses match
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 5: Verification                                       │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let addresses_match = derived_address == payment.stealth_address;

    if addresses_match {
        println!("  ✓ SUCCESS: Derived address matches stealth address!");
        println!("  ✓ Alice can spend funds from this address.");
        println!();
    } else {
        println!("  ✗ FAILED: Addresses do not match!");
        std::process::exit(1);
    }

    // =========================================================================
    // Step 6: Verify Bob cannot detect Alice's payment
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Step 6: Privacy verification                               │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let bob_meta = StealthMetaAddress::generate();
    let bob_scanner = Scanner::new(&bob_meta);
    let bob_detected = bob_scanner.scan_announcements_list(&[announcement]).unwrap();

    println!("  Bob tries to scan the same announcement...");
    println!("  Payments detected by Bob: {}", bob_detected.len());

    if bob_detected.is_empty() {
        println!("  ✓ SUCCESS: Bob cannot detect Alice's payment!");
        println!("  ✓ Privacy preserved.");
    } else {
        println!("  ✗ FAILED: Privacy breach!");
        std::process::exit(1);
    }

    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  All verifications passed! Stealth payments work.          ║");
    println!("╚════════════════════════════════════════════════════════════╝");
}
