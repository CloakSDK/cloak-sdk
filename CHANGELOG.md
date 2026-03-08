# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-08

### Added

- **Relayer** (`cloak-relayer`)
  - Axum HTTP server for transaction privacy
  - Two-signer model: relayer pays rent, user signs transfer
  - Endpoints: `/build-relay`, `/relay`, `/health`

- **Zero-Knowledge Proofs** (`zk` module)
  - Groth16 on BN254 for hidden payment amounts
  - Pedersen commitments (`C = amount + blinding * H`)
  - R1CS circuit proving valid commitment and amount > 0
  - Proof generation, verification, and key serialization

- **On-chain Program Updates**
  - `send_stealth_relayed` instruction for relayer-submitted transactions
  - `send_stealth_private` instruction with zk-SNARK proofs
  - `close_announcement` instruction to reclaim rent
  - `PrivateAnnouncementAccount` with commitment + proof storage

- **CLI Updates**
  - `--private` flag for zk-SNARK hidden amounts
  - `--relayer` flag for transaction privacy
  - `init-program` command for on-chain initialization

- **Devnet Deployment**
  - Program ID: `AaJF9TTgTPqRTuXfnQnVvBihpYwYUAYroW984foWyVJ`
  - Counter PDA initialized and operational

### Changed

- Bumped version to 1.0.0
- Updated protocol version to v2

## [0.1.0] - 2026-01-01

### Added

- **Core SDK** (`cloak-sdk`)
  - `StealthMetaAddress` for generating and managing stealth keypairs
  - `PublicMetaAddress` for sharing receiving addresses publicly
  - `StealthPayment` for creating one-time stealth payments
  - `StealthKeypair` for deriving spendable keypairs from detected payments
  - `Scanner` for detecting incoming payments with timestamp filtering
  - `ViewingKey` and `ViewingKeyScanner` for watch-only wallets
  - `PaymentHistory` for local payment tracking with labels
  - File-based key storage with JSON serialization

- **Anchor Program** (`cloak-stealth`)
  - `initialize` instruction to create announcement counter PDA
  - `send_stealth` instruction for atomic transfer + announcement
  - `announce` instruction for registering payments without transfer
  - Per-announcement PDA design for unlimited scalability

- **CLI** (`cloak`)
  - `init` - Generate new stealth meta-address
  - `address` - Display public meta-address
  - `send` - Send SOL to a stealth address
  - `scan` - Scan for incoming payments
  - `spend` - Spend from a stealth address
  - `balance` - Check address balance
  - `export` / `import` - Key backup and restore
  - `export-view-key` / `view-scan` - Viewing key management
  - `history` - Payment history with filters

[1.0.0]: https://github.com/CloakSDK/cloak-sdk/releases/tag/v1.0.0
[0.1.0]: https://github.com/CloakSDK/cloak-sdk/releases/tag/v0.1.0
