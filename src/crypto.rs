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
  use wasm_bindgen_test::*;
  
  wasm_bindgen_test_configure!(run_in_browser);
  
  #[wasm_bindgen_test]
  fn test_crypto_utils_creation() {
    let crypto = CryptoUtils::new();
    // 생성이 성공하면 OK
    assert!(true);
  }
  
  #[wasm_bindgen_test]
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
  
  #[wasm_bindgen_test]
  fn test_keccak256_empty_input() {
    let crypto = CryptoUtils::new();
    let empty_input = b"";
    
    let hash = crypto.keccak256(empty_input);
    assert_eq!(hash.len(), 32);
    
    // 빈 문자열의 Keccak-256 해시는 항상 같아야 함
    let expected_empty_hash = [
      0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
      0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
      0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
      0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    ];
    assert_eq!(hash, expected_empty_hash.to_vec());
  }
  
  #[wasm_bindgen_test]
  fn test_sha256() {
    let crypto = CryptoUtils::new();
    let input = b"Hello, SHA-256!";
    
    let hash1 = crypto.sha256(input);
    let hash2 = crypto.sha256(input);
    
    // 해시 길이 검증 (32바이트)
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
    
    // 같은 입력에 대해 같은 해시가 나와야 함
    assert_eq!(hash1, hash2);
    
    // 다른 입력에 대해서는 다른 해시가 나와야 함
    let different_input = b"Different SHA input";
    let hash3 = crypto.sha256(different_input);
    assert_ne!(hash1, hash3);
  }
  
  #[wasm_bindgen_test]
  fn test_sha256_empty_input() {
    let crypto = CryptoUtils::new();
    let empty_input = b"";
    
    let hash = crypto.sha256(empty_input);
    assert_eq!(hash.len(), 32);
    
    // 빈 문자열의 SHA-256 해시 (알려진 값)
    let expected_empty_hash = [
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ];
    assert_eq!(hash, expected_empty_hash.to_vec());
  }
  
  #[wasm_bindgen_test]
  fn test_encrypt_decrypt_data() {
    let crypto = CryptoUtils::new();
    let original_data = "This is secret wallet data that needs encryption";
    let password = "very_strong_password_123!@#";
    
    // 암호화
    let encrypted = crypto.encrypt_data(original_data, password)
      .expect("Failed to encrypt data");
    
    // 암호화된 데이터는 원본과 달라야 함
    assert_ne!(encrypted, original_data.as_bytes());
    
    // 암호화된 데이터가 비어있지 않아야 함
    assert!(!encrypted.is_empty());
    
    // 복호화
    let decrypted = crypto.decrypt_data(&encrypted, password)
      .expect("Failed to decrypt data");
    
    // 복호화된 데이터는 원본과 같아야 함
    assert_eq!(decrypted, original_data);
  }
  
  #[wasm_bindgen_test]
  fn test_encrypt_decrypt_empty_data() {
    let crypto = CryptoUtils::new();
    let empty_data = "";
    let password = "password";
    
    let encrypted = crypto.encrypt_data(empty_data, password)
      .expect("Failed to encrypt empty data");
    
    let decrypted = crypto.decrypt_data(&encrypted, password)
      .expect("Failed to decrypt empty data");
    
    assert_eq!(decrypted, empty_data);
  }
  
  #[wasm_bindgen_test]
  fn test_encrypt_decrypt_unicode_data() {
    let crypto = CryptoUtils::new();
    let unicode_data = "안녕하세요! 🚀 This is Unicode: ñáéíóú";
    let password = "unicode_password_测试";
    
    let encrypted = crypto.encrypt_data(unicode_data, password)
      .expect("Failed to encrypt Unicode data");
    
    let decrypted = crypto.decrypt_data(&encrypted, password)
      .expect("Failed to decrypt Unicode data");
    
    assert_eq!(decrypted, unicode_data);
  }
  
  #[wasm_bindgen_test]
  fn test_decrypt_with_wrong_password() {
    let crypto = CryptoUtils::new();
    let data = "Secret data";
    let correct_password = "correct123";
    let wrong_password = "wrong456";
    
    let encrypted = crypto.encrypt_data(data, correct_password)
      .expect("Failed to encrypt");
    
    // 잘못된 비밀번호로 복호화 시도
    let result = crypto.decrypt_data(&encrypted, wrong_password);
    assert!(result.is_err());
  }
  
  #[wasm_bindgen_test]
  fn test_encrypt_different_passwords() {
    let crypto = CryptoUtils::new();
    let data = "Same data";
    let password1 = "password1";
    let password2 = "password2";
    
    let encrypted1 = crypto.encrypt_data(data, password1)
      .expect("Failed to encrypt with password1");
    let encrypted2 = crypto.encrypt_data(data, password2)
      .expect("Failed to encrypt with password2");
    
    // 같은 데이터라도 다른 비밀번호로 암호화하면 다른 결과가 나와야 함
    assert_ne!(encrypted1, encrypted2);
  }
  
  #[wasm_bindgen_test]
  fn test_constant_time_eq() {
    let crypto = CryptoUtils::new();
    
    // 같은 데이터
    let data1 = b"Hello, World!";
    let data2 = b"Hello, World!";
    assert!(crypto.constant_time_eq(data1, data2));
    
    // 다른 데이터
    let data3 = b"Hello, Rust!";
    assert!(!crypto.constant_time_eq(data1, data3));
    
    // 길이가 다른 데이터
    let data4 = b"Hello";
    assert!(!crypto.constant_time_eq(data1, data4));
    
    // 빈 데이터
    let empty1 = b"";
    let empty2 = b"";
    assert!(crypto.constant_time_eq(empty1, empty2));
  }
  
  #[wasm_bindgen_test]
  fn test_secure_clear() {
    let crypto = CryptoUtils::new();
    let mut sensitive_data = vec![1, 2, 3, 4, 5];
    let original_data = sensitive_data.clone();
    
    // 데이터가 원래 값을 가지고 있는지 확인
    assert_eq!(sensitive_data, original_data);
    
    // 보안 지우기 실행
    crypto.secure_clear(&mut sensitive_data);
    
    // 모든 바이트가 0으로 지워졌는지 확인
    assert_eq!(sensitive_data, vec![0, 0, 0, 0, 0]);
    assert_ne!(sensitive_data, original_data);
  }
  
  #[wasm_bindgen_test]
  fn test_large_data_encryption() {
    let crypto = CryptoUtils::new();
    let large_data = "A".repeat(10000); // 10KB 데이터
    let password = "large_data_password";
    
    let encrypted = crypto.encrypt_data(&large_data, password)
      .expect("Failed to encrypt large data");
    
    let decrypted = crypto.decrypt_data(&encrypted, password)
      .expect("Failed to decrypt large data");
    
    assert_eq!(decrypted, large_data);
  }
  
  #[wasm_bindgen_test]
  fn test_encryption_nonce_uniqueness() {
    let crypto = CryptoUtils::new();
    let data = "Same data for nonce test";
    let password = "same_password";
    
    // 같은 데이터와 비밀번호로 여러 번 암호화
    let encrypted1 = crypto.encrypt_data(data, password)
      .expect("Failed to encrypt 1");
    let encrypted2 = crypto.encrypt_data(data, password)
      .expect("Failed to encrypt 2");
    
    // nonce가 다르므로 암호화 결과가 달라야 함
    assert_ne!(encrypted1, encrypted2);
    
    // 하지만 복호화하면 같은 결과가 나와야 함
    let decrypted1 = crypto.decrypt_data(&encrypted1, password)
      .expect("Failed to decrypt 1");
    let decrypted2 = crypto.decrypt_data(&encrypted2, password)
      .expect("Failed to decrypt 2");
    
    assert_eq!(decrypted1, data);
    assert_eq!(decrypted2, data);
    assert_eq!(decrypted1, decrypted2);
  }
}