/**
* filename : ethereum
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use crate::crypto::CryptoUtils;
use crate::types::*;
use crate::utils::*;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct EthereumUtils {
  secp: Secp256k1<secp256k1::All>,
  crypto: CryptoUtils,
}

#[wasm_bindgen]
impl EthereumUtils {
  #[wasm_bindgen(constructor)]
  pub fn new() -> EthereumUtils {
    EthereumUtils {
      secp: Secp256k1::new(),
      crypto: CryptoUtils::new(),
    }
  }
  
  /// 개인키에서 이더리움 주소 생성
  #[wasm_bindgen]
  pub fn private_key_to_address(&self, private_key: &[u8]) -> Result<String, JsValue> {
    let secret_key = SecretKey::from_slice(private_key)
      .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
    
    let public_key = secret_key.public_key(&self.secp);
    let public_key_bytes = &public_key.serialize_uncompressed()[1..]; // 0x04 제거
    
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
    
    let public_key = secret_key.public_key(&self.secp);
    Ok(public_key.serialize_uncompressed().to_vec())
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
    
    let message = Message::from_slice(transaction_hash)
      .map_err(|e| JsValue::from_str(&format!("Invalid message hash: {}", e)))?;
    
    let signature = self.secp.sign_ecdsa_recoverable(&message, &secret_key);
    let (recovery_id, signature_bytes) = signature.serialize_compact();
    
    // EIP-155: v = recovery_id + 35 + 2 * chain_id
    let v = if let Some(chain_id) = chain_id {
      recovery_id.to_i32() as u64 + 35 + 2 * chain_id
    } else {
      recovery_id.to_i32() as u64 + 27
    };
    
    // r(32) + s(32) + v(1) 형태로 반환
    let mut result = Vec::with_capacity(65);
    result.extend_from_slice(&signature_bytes[..32]); // r
    result.extend_from_slice(&signature_bytes[32..]); // s
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
    let message = Message::from_slice(&message_hash)
      .map_err(|e| JsValue::from_str(&format!("Invalid message hash: {}", e)))?;
    
    let signature = self.secp.sign_ecdsa_recoverable(&message, &secret_key);
    let (recovery_id, signature_bytes) = signature.serialize_compact();
    
    // r(32) + s(32) + v(1) 형태로 반환
    let mut result = Vec::with_capacity(65);
    result.extend_from_slice(&signature_bytes[..32]); // r
    result.extend_from_slice(&signature_bytes[32..]); // s
    result.push((recovery_id.to_i32() + 27) as u8); // v
    
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
    
    let value_hex = params.value().trim_start_matches("0x");
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
    use ethers_core::utils::parse_units;
    
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