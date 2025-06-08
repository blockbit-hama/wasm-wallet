#!/bin/bash

set -e

echo "🦀 Building Wasm-Wallet..."

# Clean previous builds
rm -rf pkg/

# Build WASM package
wasm-pack build --target web --out-dir pkg --release

# Copy TypeScript definitions
cp pkg/wasm_wallet.d.ts pkg/index.d.ts

echo "✅ Build complete! Package available in ./pkg/"
echo "📦 Files generated:"
ls -la pkg/