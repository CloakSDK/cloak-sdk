# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-21

### Added

- **Core SDK** (`cloak-sdk`)
  - `StealthMetaAddress` for generating and managing stealth keypairs
  - `PublicMetaAddress` for sharing receiving addresses publicly
  - `StealthPayment` for creating one-time stealth payments
  - `StealthKeypair` for deriving spendable keypairs from detected payments
  - `Scanner` for detecting incoming payments with timestamp filtering
  - File-based key storage with JSON serialization

- **Anchor Program** (`cloak-program`)
  - `initialize` instruction to create announcement registry (PDA)
  - `send_stealth` instruction for atomic transfer + announcement
  - `announce` instruction for registering payments without transfer
  - On-chain `Announcement` struct with ephemeral pubkey, stealth address, and timestamp

- **CLI** (`cloak`)
  - `init` - Generate new stealth meta-address
  - `address` - Display public meta-address
  - `send` - Send SOL to a stealth address
  - `scan` - Scan for incoming payments
  - `spend` - Spend from a stealth address
  - `balance` - Check address balance
  - `export` / `import` - Key backup and restore

[0.1.0]: https://github.com/CloakSDK/cloak/releases/tag/v0.1.0
