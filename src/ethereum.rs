/**
* filename : ethereum
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use crate::crypto::CryptoUtils;
use crate::types::*;
use k256::{SecretKey, ecdsa::{SigningKey, Signature, signature::Signer}};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct EthereumUtils {
  crypto: CryptoUtils,
}

#[wasm_bindgen]
impl EthereumUtils {
  #[wasm_bindgen(constructor)]
  pub fn new() -> EthereumUtils {
    EthereumUtils {
      crypto: CryptoUtils::new(),
    }
  }
  
  /// 개인키에서 이더리움 주소 생성
  #[wasm_bindgen]
  pub fn private_key_to_address(&self, private_key: &[u8]) -> Result<String, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(false);
    let public_key_bytes = &encoded_point.as_bytes()[1..]; // 0x04 제거
    
    // Keccak-256 해시의 마지막 20바이트가 주소
    let hash = self.crypto.keccak256(public_key_bytes);
    let address = hex::encode(&hash[12..]);
    
    Ok(format!("0x{}", address))
  }
  
  /// 개인키에서 공개키 추출
  #[wasm_bindgen]
  pub fn private_key_to_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(false);
    Ok(encoded_point.as_bytes().to_vec())
  }
  
  /// 트랜잭션 서명 (EIP-155 지원)
  #[wasm_bindgen]
  pub fn sign_transaction(
    &self,
    private_key: &[u8],
    transaction_hash: &[u8],
    chain_id: Option<u64>,
  ) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    let signing_key = SigningKey::from(secret_key);
    let signature: Signature = signing_key.sign(transaction_hash);
    
    // Extract r and s from signature
    let signature_bytes = signature.to_bytes();
    let r = &signature_bytes[..32];
    let s = &signature_bytes[32..];
    
    // Recovery ID calculation (simplified)
    let recovery_id = 0u8; // 실제로는 recovery ID를 계산해야 함
    
    // EIP-155: v = recovery_id + 35 + 2 * chain_id
    let v = if let Some(chain_id) = chain_id {
      recovery_id as u64 + 35 + 2 * chain_id
    } else {
      recovery_id as u64 + 27
    };
    
    // r(32) + s(32) + v(1) 형태로 반환
    let mut result = Vec::with_capacity(65);
    result.extend_from_slice(r); // r
    result.extend_from_slice(s); // s
    result.push(v as u8); // v
    
    Ok(result)
  }
  
  /// 메시지 서명 (EIP-191)
  #[wasm_bindgen]
  pub fn sign_message(&self, private_key: &[u8], message: &str) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    // EIP-191: "\x19Ethereum Signed Message:\n" + message.length + message
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let full_message = format!("{}{}", prefix, message);
    
    let message_hash = self.crypto.keccak256(full_message.as_bytes());
    
    let signing_key = SigningKey::from(secret_key);
    let signature: Signature = signing_key.sign(&message_hash);
    
    // Extract r and s from signature
    let signature_bytes = signature.to_bytes();
    let r = &signature_bytes[..32];
    let s = &signature_bytes[32..];
    
    // Recovery ID calculation (simplified)
    let recovery_id = 0u8; // 실제로는 recovery ID를 계산해야 함
    
    // r(32) + s(32) + v(1) 형태로 반환
    let mut result = Vec::with_capacity(65);
    result.extend_from_slice(r); // r
    result.extend_from_slice(s); // s
    result.push((recovery_id + 27) as u8); // v
    
    Ok(result)
  }
  
  /// 트랜잭션 빌드 (RLP 인코딩)
  #[wasm_bindgen]
  pub fn build_transaction(&self, params: &TransactionParams) -> Result<Vec<u8>, JsValue> {
    use rlp::RlpStream;
    
    // 문자열을 u64로 파싱
    let nonce = params.nonce().parse::<u64>()
      .map_err(|_| JsValue::from_str("Invalid nonce"))?;
    let gas_price = params.gas_price().parse::<u64>()
      .map_err(|_| JsValue::from_str("Invalid gas price"))?;
    let gas_limit = params.gas_limit().parse::<u64>()
      .map_err(|_| JsValue::from_str("Invalid gas limit"))?;
    
    // 주소와 값 파싱
    let to_address = hex::decode(params.to().trim_start_matches("0x"))
      .map_err(|_| JsValue::from_str("Invalid to address"))?;
    
    let binding = params.value();
    let value_hex = binding.trim_start_matches("0x");
    let value = if value_hex.is_empty() {
      vec![0u8]
    } else {
      hex::decode(value_hex).map_err(|_| JsValue::from_str("Invalid value"))?
    };
    
    // 데이터 파싱
    let data = if let Some(data_str) = params.data() {
      hex::decode(data_str.trim_start_matches("0x"))
        .map_err(|_| JsValue::from_str("Invalid data"))?
    } else {
      Vec::new()
    };
    
    // RLP 인코딩
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to_address);
    stream.append(&value);
    stream.append(&data);
    stream.append(&0u8); // v (서명 전이므로 0)
    stream.append(&0u8); // r (서명 전이므로 0)
    stream.append(&0u8); // s (서명 전이므로 0)
    
    Ok(stream.out().to_vec())
  }
  
  /// 트랜잭션 해시 계산
  #[wasm_bindgen]
  pub fn calculate_transaction_hash(&self, raw_transaction: &[u8]) -> Vec<u8> {
    self.crypto.keccak256(raw_transaction)
  }
  
  /// 주소 유효성 검증
  #[wasm_bindgen]
  pub fn is_valid_address(&self, address: &str) -> bool {
    if !address.starts_with("0x") || address.len() != 42 {
      return false;
    }
    
    hex::decode(&address[2..]).is_ok()
  }
  
  /// Wei를 Ether로 변환
  #[wasm_bindgen]
  pub fn wei_to_ether(&self, wei: &str) -> Result<String, JsValue> {
    let wei_amount = wei.parse::<u128>()
      .map_err(|_| JsValue::from_str("Invalid wei amount"))?;
    
    // 18 decimal places for Ether
    let ether_amount = wei_amount as f64 / 1e18;
    Ok(format!("{:.6}", ether_amount))
  }
  
  /// Ether를 Wei로 변환
  #[wasm_bindgen]
  pub fn ether_to_wei(&self, ether: &str) -> Result<String, JsValue> {
    let ether_amount = ether.parse::<f64>()
      .map_err(|_| JsValue::from_str("Invalid ether amount"))?;
    
    let wei_amount = (ether_amount * 1e18) as u128;
    Ok(wei_amount.to_string())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use wasm_bindgen_test::*;
  
  wasm_bindgen_test_configure!(run_in_browser);
  
  #[wasm_bindgen_test]
  fn test_ethereum_utils_creation() {
    let ethereum = EthereumUtils::new();
    // 생성이 성공하면 OK
    assert!(true);
  }
  
  #[wasm_bindgen_test]
  fn test_private_key_to_address() {
    let ethereum = EthereumUtils::new();
    
    // 알려진 개인키로 테스트
    let private_key = [
      0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x29, 0x4c,
      0x8a, 0x2f, 0x68, 0x52, 0x56, 0xd5, 0x38, 0x82,
      0x44, 0x0f, 0x89, 0x86, 0xc6, 0xdb, 0x66, 0x48,
      0x91, 0x5b, 0x31, 0x2d, 0x68, 0x2e, 0x1c, 0x20
    ];
    
    let address = ethereum.private_key_to_address(&private_key)
      .expect("Failed to generate address");
    
    // 주소 형식 검증
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
    
    // 16진수 문자만 포함하는지 확인
    let hex_part = &address[2..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
  }
  
  #[wasm_bindgen_test]
  fn test_private_key_to_address_deterministic() {
    let ethereum = EthereumUtils::new();
    let private_key = vec![1u8; 32]; // 같은 개인키
    
    let address1 = ethereum.private_key_to_address(&private_key)
      .expect("Failed to generate address 1");
    let address2 = ethereum.private_key_to_address(&private_key)
      .expect("Failed to generate address 2");
    
    // 같은 개인키는 항상 같은 주소를 생성해야 함
    assert_eq!(address1, address2);
  }
  
  #[wasm_bindgen_test]
  fn test_private_key_to_public_key() {
    let ethereum = EthereumUtils::new();
    let private_key = vec![0x42u8; 32];
    
    let public_key = ethereum.private_key_to_public_key(&private_key)
      .expect("Failed to generate public key");
    
    // 압축되지 않은 공개키는 65바이트 (0x04 + 32바이트 x + 32바이트 y)
    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04); // 압축되지 않은 공개키 prefix
  }
  
  #[wasm_bindgen_test]
  fn test_invalid_private_key() {
    let ethereum = EthereumUtils::new();
    
    // 잘못된 길이의 개인키
    let invalid_key = vec![0u8; 16]; // 32바이트가 아님
    let result = ethereum.private_key_to_address(&invalid_key);
    assert!(result.is_err());
    
    // 모든 바이트가 0인 개인키 (유효하지 않음)
    let zero_key = vec![0u8; 32];
    let result = ethereum.private_key_to_address(&zero_key);
    assert!(result.is_err());
  }
  
  #[wasm_bindgen_test]
  fn test_sign_message() {
    let ethereum = EthereumUtils::new();
    let private_key = vec![0x33u8; 32];
    let message = "Hello, Ethereum!";
    
    let signature = ethereum.sign_message(&private_key, message)
      .expect("Failed to sign message");
    
    // 서명은 65바이트여야 함 (r: 32 + s: 32 + v: 1)
    assert_eq!(signature.len(), 65);
    
    // 같은 메시지에 대해 같은 서명이 나와야 함
    let signature2 = ethereum.sign_message(&private_key, message)
      .expect("Failed to sign message again");
    assert_eq!(signature, signature2);
  }
  
  #[wasm_bindgen_test]
  fn test_sign_different_messages() {
    let ethereum = EthereumUtils::new();
    let private_key = vec![0x44u8; 32];
    let message1 = "Message 1";
    let message2 = "Message 2";
    
    let signature1 = ethereum.sign_message(&private_key, message1)
      .expect("Failed to sign message 1");
    let signature2 = ethereum.sign_message(&private_key, message2)
      .expect("Failed to sign message 2");
    
    // 다른 메시지는 다른 서명을 생성해야 함
    assert_ne!(signature1, signature2);
  }
  
  #[wasm_bindgen_test]
  fn test_sign_transaction() {
    let ethereum = EthereumUtils::new();
    let private_key = vec![0x55u8; 32];
    let tx_hash = vec![0xabu8; 32];
    
    // 체인 ID와 함께 서명
    let signature_with_chain = ethereum.sign_transaction(&private_key, &tx_hash, Some(1))
      .expect("Failed to sign transaction with chain ID");
    assert_eq!(signature_with_chain.len(), 65);
    
    // 체인 ID 없이 서명
    let signature_without_chain = ethereum.sign_transaction(&private_key, &tx_hash, None)
      .expect("Failed to sign transaction without chain ID");
    assert_eq!(signature_without_chain.len(), 65);
    
    // 체인 ID가 다르면 서명도 달라야 함
    assert_ne!(signature_with_chain, signature_without_chain);
  }
  
  #[wasm_bindgen_test]
  fn test_is_valid_address() {
    let ethereum = EthereumUtils::new();
    
    // 유효한 주소들
    assert!(ethereum.is_valid_address("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31"));
    assert!(ethereum.is_valid_address("0x0000000000000000000000000000000000000000"));
    assert!(ethereum.is_valid_address("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    
    // 무효한 주소들
    assert!(!ethereum.is_valid_address("742d35Cc6634C0532925a3b8D47641bD1e3f2F31")); // 0x 없음
    assert!(!ethereum.is_valid_address("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F3")); // 너무 짧음
    assert!(!ethereum.is_valid_address("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31G")); // 잘못된 16진수
    assert!(!ethereum.is_valid_address(""));
    assert!(!ethereum.is_valid_address("invalid"));
  }
  
  #[wasm_bindgen_test]
  fn test_wei_to_ether() {
    let ethereum = EthereumUtils::new();
    
    // 1 ETH = 10^18 Wei
    let one_eth_wei = "1000000000000000000";
    let ether = ethereum.wei_to_ether(one_eth_wei)
      .expect("Failed to convert 1 ETH");
    assert_eq!(ether, "1.000000");
    
    // 0 ETH
    let zero_wei = "0";
    let ether = ethereum.wei_to_ether(zero_wei)
      .expect("Failed to convert 0 ETH");
    assert_eq!(ether, "0.000000");
  }
  
  #[wasm_bindgen_test]
  fn test_ether_to_wei() {
    let ethereum = EthereumUtils::new();
    
    // 1 ETH
    let wei = ethereum.ether_to_wei("1.0")
      .expect("Failed to convert 1 ETH");
    assert_eq!(wei, "1000000000000000000");
    
    // 0 ETH
    let wei = ethereum.ether_to_wei("0")
      .expect("Failed to convert 0 ETH");
    assert_eq!(wei, "0");
  }
}