/**
* filename : types
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
  address: String,
  public_key: String,
}

#[wasm_bindgen]
impl WalletInfo {
  #[wasm_bindgen(getter)]
  pub fn address(&self) -> String {
    self.address.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn public_key(&self) -> String {
    self.public_key.clone()
  }
}

impl WalletInfo {
  pub fn new(address: String, public_key: String) -> Self {
    Self { address, public_key }
  }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionParams {
  to: String,
  value: String,
  gas_limit: String,
  gas_price: String,
  nonce: String,
  data: Option<String>,
}

#[wasm_bindgen]
impl TransactionParams {
  #[wasm_bindgen(constructor)]
  pub fn new(
    to: String,
    value: String,
    gas_limit: String,
    gas_price: String,
    nonce: String,
    data: Option<String>,
  ) -> TransactionParams {
    TransactionParams {
      to,
      value,
      gas_limit,
      gas_price,
      nonce,
      data,
    }
  }
  
  #[wasm_bindgen(getter)]
  pub fn to(&self) -> String {
    self.to.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn value(&self) -> String {
    self.value.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn gas_limit(&self) -> String {
    self.gas_limit.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn gas_price(&self) -> String {
    self.gas_price.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn nonce(&self) -> String {
    self.nonce.clone()
  }
  
  #[wasm_bindgen(getter)]
  pub fn data(&self) -> Option<String> {
    self.data.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use wasm_bindgen_test::*;
  
  wasm_bindgen_test_configure!(run_in_browser);
  
  #[wasm_bindgen_test]
  fn test_wallet_info_creation() {
    let wallet_info = WalletInfo::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "04a1b2c3d4e5f6...".to_string(),
    );
    
    assert_eq!(wallet_info.address(), "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31");
    assert_eq!(wallet_info.public_key(), "04a1b2c3d4e5f6...");
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_info_empty_values() {
    let wallet_info = WalletInfo::new(
      String::new(),
      String::new(),
    );
    
    assert_eq!(wallet_info.address(), "");
    assert_eq!(wallet_info.public_key(), "");
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_info_clone() {
    let wallet_info1 = WalletInfo::new(
      "0x123456789".to_string(),
      "pubkey123".to_string(),
    );
    
    let wallet_info2 = wallet_info1.clone();
    
    assert_eq!(wallet_info1.address(), wallet_info2.address());
    assert_eq!(wallet_info1.public_key(), wallet_info2.public_key());
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_creation() {
    let params = TransactionParams::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "1000000000000000000".to_string(), // 1 ETH
      "21000".to_string(),
      "20000000000".to_string(), // 20 Gwei
      "42".to_string(),
      Some("0xa9059cbb".to_string()),
    );
    
    assert_eq!(params.to(), "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31");
    assert_eq!(params.value(), "1000000000000000000");
    assert_eq!(params.gas_limit(), "21000");
    assert_eq!(params.gas_price(), "20000000000");
    assert_eq!(params.nonce(), "42");
    assert_eq!(params.data(), Some("0xa9059cbb".to_string()));
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_no_data() {
    let params = TransactionParams::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "0".to_string(),
      "21000".to_string(),
      "1000000000".to_string(),
      "0".to_string(),
      None,
    );
    
    assert_eq!(params.to(), "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31");
    assert_eq!(params.value(), "0");
    assert_eq!(params.gas_limit(), "21000");
    assert_eq!(params.gas_price(), "1000000000");
    assert_eq!(params.nonce(), "0");
    assert_eq!(params.data(), None);
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_with_empty_data() {
    let params = TransactionParams::new(
      "0x0000000000000000000000000000000000000000".to_string(),
      "999999999999999999".to_string(),
      "100000".to_string(),
      "5000000000".to_string(),
      "1".to_string(),
      Some("".to_string()),
    );
    
    assert_eq!(params.data(), Some("".to_string()));
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_clone() {
    let params1 = TransactionParams::new(
      "0x123".to_string(),
      "456".to_string(),
      "789".to_string(),
      "101112".to_string(),
      "131415".to_string(),
      Some("0xdata".to_string()),
    );
    
    let params2 = params1.clone();
    
    assert_eq!(params1.to(), params2.to());
    assert_eq!(params1.value(), params2.value());
    assert_eq!(params1.gas_limit(), params2.gas_limit());
    assert_eq!(params1.gas_price(), params2.gas_price());
    assert_eq!(params1.nonce(), params2.nonce());
    assert_eq!(params1.data(), params2.data());
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_large_values() {
    let large_value = "999999999999999999999999999999"; // 매우 큰 값
    let large_gas = "10000000"; // 높은 가스 한도
    let large_gas_price = "100000000000"; // 높은 가스 가격
    let large_nonce = "18446744073709551615"; // u64 최대값
    
    let params = TransactionParams::new(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string(),
      large_value.to_string(),
      large_gas.to_string(),
      large_gas_price.to_string(),
      large_nonce.to_string(),
      Some("0x1234567890abcdef".to_string()),
    );
    
    assert_eq!(params.value(), large_value);
    assert_eq!(params.gas_limit(), large_gas);
    assert_eq!(params.gas_price(), large_gas_price);
    assert_eq!(params.nonce(), large_nonce);
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_info_serialization() {
    use serde_json;
    
    let wallet_info = WalletInfo::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "04a1b2c3d4e5f6789012345678901234567890abcdef".to_string(),
    );
    
    // JSON 직렬화 테스트
    let serialized = serde_json::to_string(&wallet_info)
      .expect("Failed to serialize WalletInfo");
    
    // JSON에 주소와 공개키가 포함되어 있는지 확인
    assert!(serialized.contains("0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31"));
    assert!(serialized.contains("04a1b2c3d4e5f6789012345678901234567890abcdef"));
    
    // 역직렬화 테스트
    let deserialized: WalletInfo = serde_json::from_str(&serialized)
      .expect("Failed to deserialize WalletInfo");
    
    assert_eq!(deserialized.address(), wallet_info.address());
    assert_eq!(deserialized.public_key(), wallet_info.public_key());
  }
  
  #[wasm_bindgen_test]
  fn test_transaction_params_serialization() {
    use serde_json;
    
    let params = TransactionParams::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "1000000000000000000".to_string(),
      "21000".to_string(),
      "20000000000".to_string(),
      "42".to_string(),
      Some("0xa9059cbb".to_string()),
    );
    
    // JSON 직렬화 테스트
    let serialized = serde_json::to_string(&params)
      .expect("Failed to serialize TransactionParams");
    
    // 역직렬화 테스트
    let deserialized: TransactionParams = serde_json::from_str(&serialized)
      .expect("Failed to deserialize TransactionParams");
    
    assert_eq!(deserialized.to(), params.to());
    assert_eq!(deserialized.value(), params.value());
    assert_eq!(deserialized.gas_limit(), params.gas_limit());
    assert_eq!(deserialized.gas_price(), params.gas_price());
    assert_eq!(deserialized.nonce(), params.nonce());
    assert_eq!(deserialized.data(), params.data());
  }
  
  #[wasm_bindgen_test]
  fn test_wallet_info_debug_format() {
    let wallet_info = WalletInfo::new(
      "0x123".to_string(),
      "pubkey123".to_string(),
    );
    
    let debug_string = format!("{:?}", wallet_info);
    
    // Debug 출력에 필요한 정보가 포함되어 있는지 확인
    assert!(debug_string.contains("WalletInfo"));
    assert!(debug_string.contains("0x123"));
    assert!(debug_string.contains("pubkey123"));
  }
}