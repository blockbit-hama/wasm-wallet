
# ===== README.md =====
# 🦀 Wasm-Wallet

High-performance Ethereum wallet library compiled to WebAssembly using Rust.

## ✨ Features

- 🔐 **Secure Key Management**: Hardware-grade random key generation
- 🎯 **Ethereum Native**: Full support for Ethereum transactions and smart contracts
- ⚡ **High Performance**: Rust-powered cryptographic operations
- 🛡️ **Memory Safe**: Zero buffer overflows, guaranteed by Rust
- 📱 **Cross Platform**: Runs in any modern browser or mobile webview
- 🔒 **AES-256-GCM Encryption**: Military-grade wallet encryption
- 🎭 **BIP39 Mnemonic**: Standard 12/24 word seed phrases
- 🚀 **Lightweight**: Minimal WASM bundle size

## 🚀 Quick Start

### Installation

```bash
npm install wasm-wallet
```

### Usage

```javascript
import init, { WalletCore } from 'wasm-wallet';

// Initialize WASM module
await init();

// Create wallet instance
const wallet = new WalletCore();

// Generate new mnemonic
const mnemonic = wallet.generate_mnemonic();
console.log('Mnemonic:', mnemonic);

// Create wallet from mnemonic
const address = wallet.create_wallet_from_mnemonic(mnemonic);
console.log('Ethereum Address:', address);

// Sign transaction
const signature = wallet.sign_transaction(privateKey, transactionHash);
console.log('Signature:', signature);
```

## 🛠️ Development

### Prerequisites

- Rust 1.70+
- wasm-pack
- Node.js 18+

### Build

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build WASM package
./scripts/build.sh

# Run tests
./scripts/test.sh
```

### Building for Production

```bash
wasm-pack build --target web --out-dir pkg --release
```

## 📚 API Reference

### WalletCore

Main wallet functionality.

#### Methods

- `generate_mnemonic()` - Generate BIP39 mnemonic phrase
- `create_wallet_from_mnemonic(mnemonic: string)` - Create wallet from mnemonic
- `generate_private_key()` - Generate random private key
- `private_key_to_address(private_key: Uint8Array)` - Get address from private key
- `sign_transaction(private_key: Uint8Array, tx_hash: Uint8Array)` - Sign transaction
- `sign_message(private_key: Uint8Array, message: string)` - Sign arbitrary message

### CryptoUtils

Cryptographic utilities.

#### Methods

- `keccak256(data: Uint8Array)` - Keccak-256 hash
- `sha256(data: Uint8Array)` - SHA-256 hash
- `encrypt_data(data: string, password: string)` - AES-256-GCM encryption
- `decrypt_data(encrypted: Uint8Array, password: string)` - AES-256-GCM decryption

### TransactionBuilder

Ethereum transaction building.

#### Methods

- `build_transaction(params: TransactionParams)` - Build raw transaction
- `calculate_transaction_hash(raw_tx: Uint8Array)` - Calculate transaction hash
- `parse_transaction(raw_tx: Uint8Array)` - Parse transaction data

## 🔒 Security

This library follows security best practices:

- ✅ Hardware random number generation
- ✅ Memory-safe operations (Rust guarantees)
- ✅ Zeroization of sensitive data
- ✅ Constant-time cryptographic operations
- ✅ Industry-standard cryptographic libraries

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Ethereum Foundation](https://ethereum.org/) for the ecosystem
- [RustCrypto](https://github.com/RustCrypto) for cryptographic primitives
- [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) for Rust-WASM bindings

---

Made with 🦀 and ❤️ for the Ethereum ecosystem