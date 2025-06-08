/**
* filename : lib
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

mod crypto;
mod ethereum;
mod types;
mod utils;
mod wallet;

use wasm_bindgen::prelude::*;

// WASM 콘솔 로그 설정
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = console)]
  fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

// WASM 모듈 초기화
#[wasm_bindgen(start)]
pub fn main() {
  console_log!("🦀 Wasm-Wallet initialized!");
}

// 모든 public 구조체와 함수들을 re-export
pub use crypto::CryptoUtils;
pub use ethereum::EthereumUtils;
pub use types::*;
pub use wallet::WalletCore;