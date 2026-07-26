#![forbid(unsafe_code)]

use wasm_bindgen::prelude::wasm_bindgen;

const PROBE_SCHEMA_VERSION: u32 = 1;

/// Exercise a typed-array argument across the JavaScript/Wasm boundary.
#[wasm_bindgen]
pub fn byte_sum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

/// Let the browser test prove it called this build rather than a JS fallback.
#[wasm_bindgen]
pub fn probe_schema_version() -> u32 {
    PROBE_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::{byte_sum, probe_schema_version};

    #[test]
    fn sums_the_synthetic_probe_bytes() {
        assert_eq!(byte_sum(&[1, 2, 3, 4, 255]), 265);
    }

    #[test]
    fn exposes_a_stable_probe_schema() {
        assert_eq!(probe_schema_version(), 1);
    }
}
