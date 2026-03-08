# Cloak SDK

**Privacy-preserving stealth addresses for Solana.**

Cloak is a complete privacy protocol for Solana: stealth addresses, relayer network for sender privacy, and zero-knowledge proofs for hidden amounts. Deployed on Solana Devnet.

**Program ID:** `AaJF9TTgTPqRTuXfnQnVvBihpYwYUAYroW984foWyVJ`

## Features

- **Stealth Addresses** — ECDH-derived one-time addresses for every payment, completely unlinkable on-chain
- **Relayer Network** — Submit transactions through a relayer to hide your wallet address
- **Hidden Amounts** — Pedersen commitments + Groth16 zk-SNARKs (BN254) to hide payment amounts
- **View Key Delegation** — Share viewing keys for watch-only wallets without exposing spending keys
- **On-chain Registry** — Anchor program with per-announcement PDAs for unlimited scalability
- **Full CLI** — Init, send, scan, spend, history — with `--private` and `--relayer` modes

## Installation

```toml
[dependencies]
cloak-sdk = "1.0"
```

```bash
cargo add cloak-sdk
```

## Quick Start

### Generate a Stealth Identity

```rust
use cloak_sdk::StealthMetaAddress;

let meta = StealthMetaAddress::generate();
println!("Share this: {}", meta.to_public_string());
meta.save_to_file("~/.cloak/keys.json")?;
```

### Send a Stealth Payment

```rust
use cloak_sdk::{PublicMetaAddress, StealthPayment};

let recipient = PublicMetaAddress::from_string("stealth1...")?;
let payment = StealthPayment::create(&recipient, 1_000_000_000)?;

// payment.stealth_address  — where to send SOL
// payment.ephemeral_pubkey — publish on-chain for recipient detection
```

### Send with Hidden Amount (zk-SNARK)

```rust
use cloak_sdk::zk::{self, AmountCommitment};

let (pk, _pvk) = zk::setup()?;
let commitment = AmountCommitment::commit(amount);
let proof = zk::prove(&pk, amount, &commitment)?;

// commitment + proof go on-chain, amount stays private
```

### Scan and Spend

```rust
use cloak_sdk::{Scanner, ScannerConfig, StealthKeypair};

let scanner = Scanner::with_config(&meta, ScannerConfig {
    program_id,
    ..Default::default()
});
let payments = scanner.scan(rpc_url).await?;

for payment in payments {
    let keypair = StealthKeypair::derive(&meta, &payment.ephemeral_pubkey)?;
    let solana_kp = keypair.to_solana_keypair()?;
    // Sign transactions with solana_kp
}
```

## CLI

```bash
cargo install --path cli

# Generate stealth identity
cloak init

# Send SOL privately
cloak --program-id <PROGRAM_ID> send <meta-address> 0.5

# Send with hidden amount (zk-SNARK)
cloak --program-id <PROGRAM_ID> send <meta-address> 0.5 --private

# Send through relayer (hidden sender)
cloak --program-id <PROGRAM_ID> send <meta-address> 0.5 --relayer http://localhost:3000

# Scan for incoming payments
cloak --program-id <PROGRAM_ID> scan

# Spend from a stealth address
cloak --program-id <PROGRAM_ID> spend <stealth-address> <destination> all --ephemeral <hex>

# View payment history
cloak history --unspent
```

## Architecture

```
cloak-sdk/
├── crates/
│   ├── core/          # Main SDK library (cloak-sdk)
│   │   ├── address.rs     # Stealth address derivation (ECDH)
│   │   ├── keys.rs        # Meta-address generation & management
│   │   ├── scanner.rs     # On-chain payment detection
│   │   ├── spend.rs       # Spending key derivation
│   │   └── zk.rs          # Groth16 proofs & Pedersen commitments
│   └── program/       # Anchor on-chain program (cloak-stealth)
│       ├── lib.rs         # Instructions: send_stealth, send_stealth_relayed,
│       │                  #   send_stealth_private, announce, close_announcement
│       └── state.rs       # AnnouncementAccount, PrivateAnnouncementAccount,
│                          #   AnnouncementCounter
├── cli/               # Command-line interface (cloak)
├── relayer/           # Axum HTTP relayer server (cloak-relayer)
└── Anchor.toml        # Anchor config (devnet)
```

## On-chain Program

Anchor program with 5 instructions:

| Instruction | Description |
|---|---|
| `initialize` | Create the global announcement counter PDA |
| `send_stealth` | Transfer SOL + create announcement PDA |
| `send_stealth_relayed` | Relayer pays rent, user signs transfer (sender privacy) |
| `send_stealth_private` | Hidden amount with Pedersen commitment + Groth16 proof |
| `announce` | Publish ephemeral key without transferring SOL |
| `close_announcement` | Reclaim rent from processed announcements |

Each announcement is stored as its own PDA (`seeds = [b"announcement", index.to_le_bytes()]`), indexed by a global counter. No circular buffers, no limits.

## Relayer

The relayer is an HTTP server that submits transactions on behalf of users:

```bash
# Start the relayer
SOLANA_RPC_URL=https://api.devnet.solana.com \
CLOAK_PROGRAM_ID=AaJF9TTgTPqRTuXfnQnVvBihpYwYUAYroW984foWyVJ \
RELAYER_KEYPAIR=~/.config/solana/relayer.json \
cargo run --bin cloak-relayer
```

**How it works:** The relayer pays for the announcement PDA rent and submits the transaction. The user only signs the SOL transfer. On-chain, the transaction appears to come from the relayer, hiding the sender's identity.

Endpoints: `POST /build-relay`, `POST /relay`, `GET /health`

## Zero-Knowledge Proofs

Cloak uses Groth16 on BN254 to hide payment amounts:

- **Pedersen Commitment:** `C = amount + blinding * H` in the BN254 scalar field
- **R1CS Circuit:** Proves knowledge of `amount` and `blinding`, and that `amount > 0`
- **On-chain:** Only the 32-byte commitment and proof (up to 256 bytes) are stored
- **Verification:** Anyone can verify the proof without knowing the amount

## Security

- Private keys are never transmitted or stored on-chain
- Viewing keys allow detection without spending capability
- Spending keys are derived deterministically from ECDH shared secrets
- SHA-256 key derivation with domain separation
- Groth16 proofs are zero-knowledge: verifiers learn nothing about the amount

## License

MIT OR Apache-2.0
