#!/bin/bash

set -e

echo "🧪 Running Wasm-Wallet Tests..."

# Rust 네이티브 테스트 실행
echo "📋 Running Rust native tests..."
cargo test

# WASM 테스트 실행 (wasm-pack test 사용)
echo "🌐 Running WASM tests in browser..."
wasm-pack test --headless --chrome

echo "✅ All tests passed!"
