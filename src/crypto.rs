/**
* filename : crypto
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use tiny_keccak::{Hasher, Keccak};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[wasm_bindgen]
pub struct CryptoUtils;

#[wasm_bindgen]
impl CryptoUtils {
  #[wasm_bindgen(constructor)]
  pub fn new() -> CryptoUtils {
    CryptoUtils
  }
  
  /// Keccak-256 해시 계산 (이더리움 표준)
  #[wasm_bindgen]
  pub fn keccak256(&self, data: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output.to_vec()
  }
  
  /// SHA-256 해시 계산
  #[wasm_bindgen]
  pub fn sha256(&self, data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
  }
  
  /// AES-256-GCM으로 데이터 암호화
  #[wasm_bindgen]
  pub fn encrypt_data(&self, data: &str, password: &str) -> Result<Vec<u8>, JsValue> {
    use aes_gcm::{
      aead::{Aead, AeadCore, KeyInit, OsRng},
      Aes256Gcm, Key,
    };
    use argon2::{
      password_hash::{PasswordHasher, SaltString},
      Argon2,
    };
    
    // Argon2로 패스워드 해싱
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .map_err(|e| JsValue::from_str(&format!("Password hashing failed: {}", e)))?;
    
    let binding = password_hash.hash.unwrap();
    let key = Key::<Aes256Gcm>::from_slice(
      &binding.as_bytes()[..32]
    );
    
    // AES-GCM 암호화
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher
      .encrypt(&nonce, data.as_bytes())
      .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
    
    // nonce(12) + salt(22) + ciphertext 형태로 결합
    let mut result = Vec::new();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(salt.as_str().as_bytes());
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
  }
  
  /// AES-256-GCM으로 데이터 복호화
  #[wasm_bindgen]
  pub fn decrypt_data(&self, encrypted_data: &[u8], password: &str) -> Result<String, JsValue> {
    use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
    use argon2::{
      password_hash::{PasswordHasher, SaltString},
      Argon2,
    };
    
    if encrypted_data.len() < 34 {
      // nonce(12) + salt(22) 최소 크기
      return Err(JsValue::from_str("Invalid encrypted data"));
    }
    
    // 데이터 분리
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let salt_bytes = &encrypted_data[12..34];
    let ciphertext = &encrypted_data[34..];
    
    let salt_str = std::str::from_utf8(salt_bytes)
      .map_err(|_| JsValue::from_str("Invalid salt encoding"))?;
    let salt = SaltString::from_b64(salt_str)
      .map_err(|_| JsValue::from_str("Invalid salt format"))?;
    
    // 키 재생성
    let argon2 = Argon2::default();
    let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .map_err(|_| JsValue::from_str("Password verification failed"))?;
    
    let binding = password_hash.hash.unwrap();
    let key = Key::<Aes256Gcm>::from_slice(
      &binding.as_bytes()[..32]
    );
    
    // 복호화
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
      .decrypt(nonce, ciphertext)
      .map_err(|_| JsValue::from_str("Decryption failed - wrong password?"))?;
    
    String::from_utf8(plaintext)
      .map_err(|_| JsValue::from_str("Invalid UTF-8 in decrypted data"))
  }
  
  /// 민감한 데이터를 메모리에서 안전하게 지우기
  #[wasm_bindgen]
  pub fn secure_clear(&self, data: &mut [u8]) {
    data.zeroize();
  }
  
  /// 두 바이트 배열을 상수 시간에 비교 (타이밍 공격 방지)
  #[wasm_bindgen]
  pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
      return false;
    }
    
    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
      result |= byte_a ^ byte_b;
    }
    
    result == 0
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  
  // 순수 로직 테스트들 - 일반 #[test] 사용
  #[test]
  fn test_crypto_utils_creation() {
    let crypto = CryptoUtils::new();
    // 생성이 성공하면 OK
    assert!(true);
  }
  
  #[test]
  fn test_keccak256() {
    let crypto = CryptoUtils::new();
    let input = b"Hello, Ethereum!";
    
    let hash1 = crypto.keccak256(input);
    let hash2 = crypto.keccak256(input);
    
    // 해시 길이 검증 (32바이트)
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
    
    // 같은 입력에 대해 같은 해시가 나와야 함
    assert_eq!(hash1, hash2);
    
    // 다른 입력에 대해서는 다른 해시가 나와야 함
    let different_input = b"Different input";
    let hash3 = crypto.keccak256(different_input);
    assert_ne!(hash1, hash3);
  }
  
  #[test]
  fn test_sha256() {
    let crypto = CryptoUtils::new();
    let input = b"Hello, SHA-256!";
    
    let hash1 = crypto.sha256(input);
    let hash2 = crypto.sha256(input);
    
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash1, hash2);
  }
  
  #[test]
  fn test_encrypt_decrypt_data() {
    let crypto = CryptoUtils::new();
    let original_data = "Secret wallet data";
    let password = "strong_password";
    
    let encrypted = crypto.encrypt_data(original_data, password)
      .expect("Failed to encrypt data");
    
    assert_ne!(encrypted, original_data.as_bytes());
    assert!(!encrypted.is_empty());
    
    let decrypted = crypto.decrypt_data(&encrypted, password)
      .expect("Failed to decrypt data");
    
    assert_eq!(decrypted, original_data);
  }
  
  #[test]
  fn test_constant_time_eq() {
    let crypto = CryptoUtils::new();
    
    let data1 = b"Hello, World!";
    let data2 = b"Hello, World!";
    assert!(crypto.constant_time_eq(data1, data2));
    
    let data3 = b"Hello, Rust!";
    assert!(!crypto.constant_time_eq(data1, data3));
  }
}