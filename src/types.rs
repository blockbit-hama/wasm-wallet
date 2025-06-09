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
  
  #[test]
  fn test_wallet_info_creation() {
    let wallet_info = WalletInfo::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "04a1b2c3d4e5f6...".to_string(),
    );
    
    assert_eq!(wallet_info.address(), "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31");
    assert_eq!(wallet_info.public_key(), "04a1b2c3d4e5f6...");
  }
  
  #[test]
  fn test_transaction_params_creation() {
    let params = TransactionParams::new(
      "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31".to_string(),
      "1000000000000000000".to_string(),
      "21000".to_string(),
      "20000000000".to_string(),
      "42".to_string(),
      Some("0xa9059cbb".to_string()),
    );
    
    assert_eq!(params.to(), "0x742d35Cc6634C0532925a3b8D47641bD1e3f2F31");
    assert_eq!(params.value(), "1000000000000000000");
    assert_eq!(params.data(), Some("0xa9059cbb".to_string()));
  }
}