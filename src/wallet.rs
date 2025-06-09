/**
* filename : wallet
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use crate::crypto::CryptoUtils;
use crate::ethereum::EthereumUtils;
use crate::types::*;
use bip39::{Language, Mnemonic};
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