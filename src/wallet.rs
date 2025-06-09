/**
* filename : wallet
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use crate::crypto::CryptoUtils;
use crate::ethereum::EthereumUtils;
use crate::types::*;
use bip39::{Language, Mnemonic}

#[cfg(test)]
mod tests {
  use super::*;
  use wasm_bindgen_test::*;
  
  wasm_bindgen_test_configure!(run_in_browser);
  
  #[wasm_bindgen_test]
  fn test_wallet_core_creation() {
    let wallet = WalletCore::new();
    let version = wallet.version();
    assert!(version.contains("wasm-wallet"));
  }
  
  #[wasm_bindgen_test]
  fn test_mnemonic_generation() {
    let wallet = WalletCore::new();
    
    // 12단어 니모닉 테스트
    let mnemonic_12 = wallet.generate_mnemonic().expect("Failed to generate 12-word mnemonic");
    let words_12: Vec<&str> = mnemonic_12.split_whitespace().collect();
    assert_eq!(words_12.len(), 12);
    
    // 24단어 니모닉 테스트
    let mnemonic_24 = wallet.generate_mnemonic_24().expect("Failed to generate 24-word mnemonic");
    let words_24: Vec<&str> = mnemonic_24.split_whitespace().collect();
    assert_eq!(words_24.len(), 24);
    
    // 각 단어가 공백이 아닌지 확인
    for word in &words_12 {
      assert!(!word.is_empty());
      assert!(word.chars().all(|c| c.is_alphabetic()));
    }
  }
  
  #[wasm_bindgen_test]
  fn test_mnemonic_validation() {
    let wallet = WalletCore::new();
    
    // 유효한 니모닉 테스트
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(wallet.validate_mnemonic(valid_mnemonic));
    
    // 무효한 니모닉 테스트
    let invalid_mnemonic = "invalid mnemonic phrase that should not work";
    assert!(!wallet.validate_mnemonic(invalid_mnemonic));
    
    // 단어 개수가 맞지 않는 경우
    let short_mnemonic = "abandon abandon abandon";
    assert!(!wallet.validate_mnemonic(short_mnemonic));
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_creation_from_mnemonic() {
    let wallet = WalletCore::new();
    let mnemonic = wallet.generate_mnemonic().expect("Failed to generate mnemonic");
    
    let wallet_info = wallet.create_wallet_from_mnemonic(&mnemonic)
      .expect("Failed to create wallet from mnemonic");
    
    // 주소 형식 검증
    assert!(wallet_info.address().starts_with("0x"));
    assert_eq!(wallet_info.address().len(), 42);
    
    // 공개키 형식 검증 (압축되지 않은 형태: 130자 또는 132자)
    let public_key = wallet_info.public_key();
    assert!(public_key.len() >= 128); // 최소 64바이트 (128 hex chars)
  }
  
  #[wasm_bindgen_test]
  fn test_private_key_generation() {
    let wallet = WalletCore::new();
    
    // 개인키 생성
    let private_key1 = wallet.generate_private_key();
    let private_key2 = wallet.generate_private_key();
    
    // 길이 검증 (32바이트)
    assert_eq!(private_key1.len(), 32);
    assert_eq!(private_key2.len(), 32);
    
    // 서로 다른 키가 생성되는지 확인
    assert_ne!(private_key1, private_key2);
    
    // 모든 바이트가 0이 아닌지 확인 (매우 낮은 확률이지만 체크)
    assert!(private_key1.iter().any(|&b| b != 0));
  }
  
  #[wasm_bindgen_test]
  fn test_private_key_to_address() {
    let wallet = WalletCore::new();
    let private_key = wallet.generate_private_key();
    
    let address = wallet.private_key_to_address(&private_key)
      .expect("Failed to generate address from private key");
    
    // 주소 형식 검증
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
    
    // 16진수 문자만 포함하는지 확인
    let hex_part = &address[2..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
  }
  
  #[wasm_bindgen_test]
  fn test_message_signing() {
    let wallet = WalletCore::new();
    let private_key = wallet.generate_private_key();
    let message = "Hello, Ethereum World!";
    
    let signature = wallet.sign_message(&private_key, message)
      .expect("Failed to sign message");
    
    // 서명 길이 검증 (r: 32바이트 + s: 32바이트 + v: 1바이트)
    assert_eq!(signature.len(), 65);
    
    // 같은 메시지에 대해 같은 서명이 나오는지 확인
    let signature2 = wallet.sign_message(&private_key, message)
      .expect("Failed to sign message again");
    assert_eq!(signature, signature2);
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_signing() {
    let wallet = WalletCore::new();
    let private_key = wallet.generate_private_key();
    let tx_hash = vec![0u8; 32]; // 더미 트랜잭션 해시
    
    let signature = wallet.sign_transaction(&private_key, &tx_hash, Some(1))
      .expect("Failed to sign transaction");
    
    // 서명 길이 검증
    assert_eq!(signature.len(), 65);
    
    // 체인 ID 없이도 서명 가능한지 확인
    let signature_no_chain = wallet.sign_transaction(&private_key, &tx_hash, None)
      .expect("Failed to sign transaction without chain ID");
    assert_eq!(signature_no_chain.len(), 65);
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_encryption_decryption() {
    let wallet = WalletCore::new();
    let wallet_data = r#"{"address":"0x123","name":"test"}"#;
    let password = "strong_password_123";
    
    // 암호화
    let encrypted = wallet.encrypt_wallet(wallet_data, password)
      .expect("Failed to encrypt wallet");
    
    // 암호화된 데이터가 원본과 다른지 확인
    assert_ne!(encrypted, wallet_data.as_bytes());
    
    // 복호화
    let decrypted = wallet.decrypt_wallet(&encrypted, password)
      .expect("Failed to decrypt wallet");
    
    assert_eq!(decrypted, wallet_data);
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_decryption_wrong_password() {
    let wallet = WalletCore::new();
    let wallet_data = r#"{"address":"0x123","name":"test"}"#;
    let password = "correct_password";
    let wrong_password = "wrong_password";
    
    let encrypted = wallet.encrypt_wallet(wallet_data, password)
      .expect("Failed to encrypt wallet");
    
    // 잘못된 비밀번호로 복호화 시도
    let result = wallet.decrypt_wallet(&encrypted, wrong_password);
    assert!(result.is_err());
  }
  
  #[wasm_bindgen_test]
  fn test_get_wallet_info() {
    let wallet = WalletCore::new();
    let private_key = wallet.generate_private_key();
    
    let wallet_info = wallet.get_wallet_info(&private_key)
      .expect("Failed to get wallet info");
    
    // 주소 형식 검증
    assert!(wallet_info.address().starts_with("0x"));
    assert_eq!(wallet_info.address().len(), 42);
    
    // 공개키가 비어있지 않은지 확인
    assert!(!wallet_info.public_key().is_empty());
  }
  
  #[wasm_bindgen_test]
  fn test_deterministic_wallet_creation() {
    let wallet = WalletCore::new();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // 같은 니모닉으로 두 번 지갑 생성
    let wallet_info1 = wallet.create_wallet_from_mnemonic(mnemonic)
      .expect("Failed to create wallet 1");
    let wallet_info2 = wallet.create_wallet_from_mnemonic(mnemonic)
      .expect("Failed to create wallet 2");
    
    // 같은 주소와 공개키가 생성되어야 함
    assert_eq!(wallet_info1.address(), wallet_info2.address());
    assert_eq!(wallet_info1.public_key(), wallet_info2.public_key());
  }
};
use rand_core::OsRng;
use k256::{SecretKey};
use wasm_bindgen::prelude::*;

// console_log 매크로 import
use crate::console_log;

#[wasm_bindgen]
pub struct WalletCore {
  crypto: CryptoUtils,
  ethereum: EthereumUtils,
}

#[wasm_bindgen]
impl WalletCore {
  #[wasm_bindgen(constructor)]
  pub fn new() -> WalletCore {
    console_log!("🦀 Initializing WalletCore...");
    WalletCore {
      crypto: CryptoUtils::new(),
      ethereum: EthereumUtils::new(),
    }
  }
  
  /// BIP39 니모닉 생성 (12단어)
  #[wasm_bindgen]
  pub fn generate_mnemonic(&self) -> Result<String, JsValue> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)
      .map_err(|e| JsValue::from_str(&format!("Failed to generate mnemonic: {}", e)))?;
    
    console_log!("✅ Generated 12-word mnemonic");
    Ok(mnemonic.to_string())
  }
  
  /// 24단어 니모닉 생성
  #[wasm_bindgen]
  pub fn generate_mnemonic_24(&self) -> Result<String, JsValue> {
    let mnemonic = Mnemonic::generate_in(Language::English, 24)
      .map_err(|e| JsValue::from_str(&format!("Failed to generate mnemonic: {}", e)))?;
    
    console_log!("✅ Generated 24-word mnemonic");
    Ok(mnemonic.to_string())
  }
  
  /// 니모닉에서 지갑 생성
  #[wasm_bindgen]
  pub fn create_wallet_from_mnemonic(&self, mnemonic_phrase: &str) -> Result<WalletInfo, JsValue> {
    let mnemonic = Mnemonic::parse(mnemonic_phrase)
      .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {}", e)))?;
    
    // BIP39 시드 생성
    let seed = mnemonic.to_seed("");
    
    // BIP32 마스터 키 생성 (첫 32바이트 사용)
    let master_key = &seed[..32];
    
    let secret_key = SecretKey::from_slice(master_key)
      .map_err(|e| JsValue::from_str(&format!("Failed to create secret key: {}", e)))?;
    
    let public_key = secret_key.public_key();
    let address = self.ethereum.private_key_to_address(master_key)?;
    
    console_log!("✅ Created wallet from mnemonic: {}", address);
    
    Ok(WalletInfo::new(
      address,
      hex::encode(public_key.to_sec1_bytes()),
    ))
  }
  
  /// 랜덤 개인키 생성
  #[wasm_bindgen]
  pub fn generate_private_key(&self) -> Vec<u8> {
    let secret_key = SecretKey::random(&mut OsRng);
    console_log!("✅ Generated random private key");
    secret_key.to_bytes().to_vec()
  }
  
  /// 개인키에서 주소 생성
  #[wasm_bindgen]
  pub fn private_key_to_address(&self, private_key: &[u8]) -> Result<String, JsValue> {
    self.ethereum.private_key_to_address(private_key)
  }
  
  /// 트랜잭션 서명
  #[wasm_bindgen]
  pub fn sign_transaction(
    &self,
    private_key: &[u8],
    transaction_hash: &[u8],
    chain_id: Option<u64>,
  ) -> Result<Vec<u8>, JsValue> {
    console_log!("🔏 Signing transaction...");
    let signature = self.ethereum.sign_transaction(private_key, transaction_hash, chain_id)?;
    console_log!("✅ Transaction signed successfully");
    Ok(signature)
  }
  
  /// 메시지 서명
  #[wasm_bindgen]
  pub fn sign_message(&self, private_key: &[u8], message: &str) -> Result<Vec<u8>, JsValue> {
    console_log!("🔏 Signing message: {}", message);
    let signature = self.ethereum.sign_message(private_key, message)?;
    console_log!("✅ Message signed successfully");
    Ok(signature)
  }
  
  /// 지갑 데이터 암호화
  #[wasm_bindgen]
  pub fn encrypt_wallet(&self, wallet_json: &str, password: &str) -> Result<Vec<u8>, JsValue> {
    console_log!("🔐 Encrypting wallet data...");
    let encrypted = self.crypto.encrypt_data(wallet_json, password)?;
    console_log!("✅ Wallet encrypted successfully");
    Ok(encrypted)
  }
  
  /// 지갑 데이터 복호화
  #[wasm_bindgen]
  pub fn decrypt_wallet(&self, encrypted_data: &[u8], password: &str) -> Result<String, JsValue> {
    console_log!("🔓 Decrypting wallet data...");
    let decrypted = self.crypto.decrypt_data(encrypted_data, password)?;
    console_log!("✅ Wallet decrypted successfully");
    Ok(decrypted)
  }
  
  /// 니모닉 유효성 검증
  #[wasm_bindgen]
  pub fn validate_mnemonic(&self, mnemonic_phrase: &str) -> bool {
    Mnemonic::parse(mnemonic_phrase).is_ok()
  }
  
  /// 라이브러리 버전 정보
  #[wasm_bindgen]
  pub fn version(&self) -> String {
    "wasm-wallet v0.1.0 🦀".to_string()
  }
  
  /// 지갑 상태 정보
  #[wasm_bindgen]
  pub fn get_wallet_info(&self, private_key: &[u8]) -> Result<WalletInfo, JsValue> {
    let address = self.ethereum.private_key_to_address(private_key)?;
    let public_key = self.ethereum.private_key_to_public_key(private_key)?;
    
    Ok(WalletInfo::new(
      address,
      hex::encode(public_key),
    ))
  }
}