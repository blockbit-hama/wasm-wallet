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