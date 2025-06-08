/**
* filename : utils
* author : HAMA
* date: 2025. 6. 8.
* description: 
**/

use wasm_bindgen::prelude::*;

/// 헥스 문자열을 바이트 배열로 변환
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
  let clean_hex = hex_str.trim_start_matches("0x");
  hex::decode(clean_hex).map_err(|e| format!("Invalid hex string: {}", e))
}

/// 바이트 배열을 헥스 문자열로 변환
pub fn bytes_to_hex(bytes: &[u8]) -> String {
  format!("0x{}", hex::encode(bytes))
}

/// 안전한 랜덤 바이트 생성
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
  use rand_core::RngCore;
  let mut bytes = vec![0u8; length];
  rand_core::OsRng.fill_bytes(&mut bytes);
  bytes
}

/// 현재 타임스탬프 (초)
#[wasm_bindgen]
pub fn current_timestamp() -> u64 {
  js_sys::Date::now() as u64 / 1000
}

/// 에러 로깅을 위한 헬퍼
pub fn log_error(context: &str, error: &str) {
  web_sys::console::error_2(
    &format!("❌ {}", context).into(),
    &error.into(),
  );
}
