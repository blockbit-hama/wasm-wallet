/**
* filename : web
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use wasm_wallet::{WalletCore, CryptoUtils, EthereumUtils};

#[wasm_bindgen_test]
fn test_wallet_creation() {
  let wallet = WalletCore::new();
  
  // 니모닉 생성 테스트
  let mnemonic = wallet.generate_mnemonic().expect("Failed to generate mnemonic");
  assert_eq!(mnemonic.split_whitespace().count(), 12);
  
  // 니모닉 검증 테스트
  assert!(wallet.validate_mnemonic(&mnemonic));
  
  // 지갑 생성 테스트
  let wallet_info = wallet.create_wallet_from_mnemonic(&mnemonic)
    .expect("Failed to create wallet");
  
  assert!(wallet_info.address().starts_with("0x"));
  assert_eq!(wallet_info.address().len(), 42);
}

#[wasm_bindgen_test]
fn test_private_key_operations() {
  let wallet = WalletCore::new();
  
  // 개인키 생성
  let private_key = wallet.generate_private_key();
  assert_eq!(private_key.len(), 32);
  
  // 주소 생성
  let address = wallet.private_key_to_address(&private_key)
    .expect("Failed to generate address");
  assert!(address.starts_with("0x"));
  assert_eq!(address.len(), 42);
}

#[wasm_bindgen_test]
fn test_crypto_functions() {
  let crypto = CryptoUtils::new();
  
  let test_data = b"Hello, Ethereum!";
  
  // Keccak-256 테스트
  let hash = crypto.keccak256(test_data);
  assert_eq!(hash.len(), 32);
  
  // SHA-256 테스트
  let sha_hash = crypto.sha256(test_data);
  assert_eq!(sha_hash.len(), 32);
  
  // 암호화/복호화 테스트
  let password = "test_password";
  let encrypted = crypto.encrypt_data("test data", password)
    .expect("Failed to encrypt");
  
  let decrypted = crypto.decrypt_data(&encrypted, password)
    .expect("Failed to decrypt");
  
  assert_eq!(decrypted, "test data");
}

#[wasm_bindgen_test]
fn test_ethereum_functions() {
  let ethereum = EthereumUtils::new();
  
  // 주소 유효성 검증
  assert!(ethereum.is_valid_address("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31"));
  assert!(!ethereum.is_valid_address("invalid_address"));
  
  // Wei/Ether 변환
  let wei_amount = "1000000000000000000"; // 1 ETH in Wei
  let ether = ethereum.wei_to_ether(wei_amount)
    .expect("Failed to convert Wei to Ether");
  assert_eq!(ether, "1.000000");
  
  let wei_back = ethereum.ether_to_wei("1.0")
    .expect("Failed to convert Ether to Wei");
  assert_eq!(wei_back, wei_amount);
}

#[wasm_bindgen_test]
fn test_message_signing() {
  let wallet = WalletCore::new();
  let private_key = wallet.generate_private_key();
  
  let message = "Hello, Ethereum!";
  let signature = wallet.sign_message(&private_key, message)
    .expect("Failed to sign message");
  
  assert_eq!(signature.len(), 65); // r(32) + s(32) + v(1)
}