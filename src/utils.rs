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

/// 현재 타임스탬프 (초) - WASM 환경에서만 사용
#[wasm_bindgen]
pub fn current_timestamp() -> u64 {
  js_sys::Date::now() as u64 / 1000
}

/// 네이티브 환경에서 테스트용 타임스탬프 함수
#[cfg(not(target_arch = "wasm32"))]
pub fn current_timestamp_native() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs()
}

/// 에러 로깅을 위한 헬퍼 - WASM 환경에서만 사용
pub fn log_error(context: &str, error: &str) {
  web_sys::console::error_2(
    &format!("❌ {}", context).into(),
    &error.into(),
  );
}

#[cfg(test)]
mod tests {
  use super::*;
  
  // 순수 로직 테스트들 - 일반 #[test] 사용
  #[test]
  fn test_hex_to_bytes_valid() {
    let hex_with_prefix = "0x48656c6c6f";
    let bytes = hex_to_bytes(hex_with_prefix).expect("Failed to convert hex");
    assert_eq!(bytes, b"Hello");
    
    let hex_without_prefix = "48656c6c6f";
    let bytes = hex_to_bytes(hex_without_prefix).expect("Failed to convert hex");
    assert_eq!(bytes, b"Hello");
    
    let empty_hex = "";
    let bytes = hex_to_bytes(empty_hex).expect("Failed to convert empty hex");
    assert_eq!(bytes, Vec::<u8>::new());
  }
  
  #[test]
  fn test_hex_to_bytes_invalid() {
    let invalid_hex = "0xGGGG";
    let result = hex_to_bytes(invalid_hex);
    assert!(result.is_err());
    
    let odd_length = "0x123";
    let result = hex_to_bytes(odd_length);
    assert!(result.is_err());
  }
  
  #[test]
  fn test_bytes_to_hex() {
    let bytes = b"Hello";
    let hex_string = bytes_to_hex(bytes);
    assert_eq!(hex_string, "0x48656c6c6f");
    
    let empty_bytes = &[];
    let hex_string = bytes_to_hex(empty_bytes);
    assert_eq!(hex_string, "0x");
  }
  
  #[test]
  fn test_hex_roundtrip() {
    let original_bytes = b"Test roundtrip conversion";
    let hex_string = bytes_to_hex(original_bytes);
    let converted_bytes = hex_to_bytes(&hex_string).expect("Failed to convert back");
    
    assert_eq!(original_bytes.to_vec(), converted_bytes);
  }
  
  #[test]
  fn test_generate_random_bytes() {
    let random_bytes_32 = generate_random_bytes(32);
    assert_eq!(random_bytes_32.len(), 32);
    
    let random_bytes_0 = generate_random_bytes(0);
    assert_eq!(random_bytes_0.len(), 0);
    
    // 두 번 생성한 랜덤 바이트가 다른지 확인
    let random1 = generate_random_bytes(32);
    let random2 = generate_random_bytes(32);
    assert_ne!(random1, random2);
  }
  
  #[test]
  fn test_generate_random_bytes_distribution() {
    let random_bytes = generate_random_bytes(1000);
    
    // 모든 바이트가 0일 확률은 매우 낮음
    let all_zeros = random_bytes.iter().all(|&b| b == 0);
    assert!(!all_zeros);
    
    // 최소한 10개 이상의 서로 다른 값이 있어야 함
    let unique_values: std::collections::HashSet<_> = random_bytes.iter().collect();
    assert!(unique_values.len() > 10);
  }
  
  #[cfg(not(target_arch = "wasm32"))]
  #[test]
  fn test_current_timestamp_native() {
    let timestamp1 = current_timestamp_native();
    
    // 타임스탬프가 합리적인 범위에 있는지 확인
    assert!(timestamp1 > 1577836800); // 2020년 이후
    assert!(timestamp1 < 2524608000); // 2050년 이전
    
    std::thread::sleep(std::time::Duration::from_millis(10));
    let timestamp2 = current_timestamp_native();
    assert!(timestamp2 >= timestamp1);
  }
  
  // WASM 환경에서만 필요한 테스트들
  #[cfg(target_arch = "wasm32")]
  mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    #[wasm_bindgen_test]
    fn test_current_timestamp() {
      let timestamp1 = current_timestamp();
      
      assert!(timestamp1 > 1577836800); // 2020년 이후
      assert!(timestamp1 < 2524608000); // 2050년 이전
    }
    
    #[wasm_bindgen_test]
    fn test_log_error() {
      // 브라우저 콘솔 로깅 테스트
      log_error("테스트 컨텍스트", "테스트 에러 메시지");
      assert!(true); // 패닉 없이 실행되면 성공
    }
  }
}
