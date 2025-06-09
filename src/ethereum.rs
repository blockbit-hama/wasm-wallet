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
  
  /// WASM 바인딩용 - 바이트 배열에서 주소 생성
  #[wasm_bindgen]
  pub fn private_key_to_address(&self, private_key: &[u8]) -> Result<String, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    self.private_key_to_address_internal(&secret_key)
      .map_err(|e| JsValue::from_str(&e))
  }
  
  /// WASM 바인딩용 - 바이트 배열에서 공개키 추출
  #[wasm_bindgen]
  pub fn private_key_to_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    Ok(self.private_key_to_public_key_internal(&secret_key))
  }
  
  /// WASM 바인딩용 - 메시지 서명
  #[wasm_bindgen]
  pub fn sign_message(&self, private_key: &[u8], message: &str) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    self.sign_message_internal(&secret_key, message)
      .map_err(|e| JsValue::from_str(&e))
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
    
    self.sign_transaction_internal(&secret_key, transaction_hash, chain_id)
      .map_err(|e| JsValue::from_str(&e))
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

// 내부 함수들 - 타입 안전한 버전
impl EthereumUtils {
  /// 내부용 - 타입 안전한 주소 생성
  pub fn private_key_to_address_internal(&self, secret_key: &SecretKey) -> Result<String, String> {
    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(false);
    let public_key_bytes = &encoded_point.as_bytes()[1..]; // 0x04 제거
    
    // Keccak-256 해시의 마지막 20바이트가 주소
    let hash = self.crypto.keccak256(public_key_bytes);
    let address = hex::encode(&hash[12..]);
    
    Ok(format!("0x{}", address))
  }
  
  /// 내부용 - 타입 안전한 공개키 추출
  pub fn private_key_to_public_key_internal(&self, secret_key: &SecretKey) -> Vec<u8> {
    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(false);
    encoded_point.as_bytes().to_vec()
  }
  
  /// 내부용 - 타입 안전한 메시지 서명 (EIP-191)
  pub fn sign_message_internal(&self, secret_key: &SecretKey, message: &str) -> Result<Vec<u8>, String> {
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
  
  /// 내부용 - 타입 안전한 트랜잭션 서명 (EIP-155)
  pub fn sign_transaction_internal(
    &self,
    secret_key: &SecretKey,
    transaction_hash: &[u8],
    chain_id: Option<u64>,
  ) -> Result<Vec<u8>, String> {
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
}

#[cfg(test)]
mod tests {
  use super::*;
  
  #[test]
  fn test_ethereum_utils_creation() {
    let ethereum = EthereumUtils::new();
    assert!(true);
  }
  
  #[test]
  fn test_private_key_to_address() {
    let ethereum = EthereumUtils::new();
    
    let private_key = [
      0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x29, 0x4c,
      0x8a, 0x2f, 0x68, 0x52, 0x56, 0xd5, 0x38, 0x82,
      0x44, 0x0f, 0x89, 0x86, 0xc6, 0xdb, 0x66, 0x48,
      0x91, 0x5b, 0x31, 0x2d, 0x68, 0x2e, 0x1c, 0x20
    ];
    
    let address = ethereum.private_key_to_address(&private_key)
      .expect("Failed to generate address");
    
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
  }
  
  #[test]
  fn test_is_valid_address() {
    let ethereum = EthereumUtils::new();
    
    assert!(ethereum.is_valid_address("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31"));
    assert!(!ethereum.is_valid_address("invalid_address"));
  }
  
  #[test]
  fn test_wei_to_ether() {
    let ethereum = EthereumUtils::new();
    
    let one_eth_wei = "1000000000000000000";
    let ether = ethereum.wei_to_ether(one_eth_wei)
      .expect("Failed to convert 1 ETH");
    assert_eq!(ether, "1.000000");
  }
}
