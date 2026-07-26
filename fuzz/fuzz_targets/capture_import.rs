#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_core::{CaptureImporter, ImportLimits, ImportProgress, ImportStep};

const HEX_PREFIX: &[u8] = b"hex:";
const MAX_CAPTURE_BYTES: usize = 4_096;
const MAX_ENCODED_BYTES: usize = HEX_PREFIX.len() + (MAX_CAPTURE_BYTES * 2) + 128;
const MAX_DRIVER_STEPS: usize = (MAX_CAPTURE_BYTES / 4) + 8;
const STEP_RECORD_BUDGET: u32 = 4;
const INITIAL_STEP_BYTE_BUDGET: u64 = 31;

fn fuzz_limits() -> ImportLimits {
    ImportLimits {
        max_capture_bytes: u64::try_from(MAX_CAPTURE_BYTES)
            .expect("the fuzz input bound fits in u64"),
        max_block_bytes: 1_024,
        max_decoded_items_per_block: 64,
        max_decoded_items_per_step: 64,
        max_packets: 256,
        max_sections: 32,
        max_interfaces: 64,
        max_diagnostics: 64,
        max_string_bytes: 4_096,
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_text_seed(data: &[u8]) -> Option<Vec<u8>> {
    let encoded = data.strip_prefix(HEX_PREFIX)?;
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let mut high_nibble = None;
    for &byte in encoded {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = hex_value(byte)?;
        if let Some(high) = high_nibble.take() {
            if decoded.len() == MAX_CAPTURE_BYTES {
                return None;
            }
            decoded.push((high << 4) | nibble);
        } else {
            high_nibble = Some(nibble);
        }
    }
    if high_nibble.is_some() {
        return None;
    }
    Some(decoded)
}

fn bounded_capture(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_ENCODED_BYTES {
        return None;
    }
    if data.starts_with(HEX_PREFIX) {
        if let Some(decoded) = decode_text_seed(data) {
            return Some(decoded);
        }
    }
    (data.len() <= MAX_CAPTURE_BYTES).then(|| data.to_vec())
}

fn assert_monotonic(previous: ImportProgress, current: ImportProgress) {
    assert_eq!(current.total_bytes, previous.total_bytes);
    assert!(current.consumed_bytes >= previous.consumed_bytes);
    assert!(current.consumed_bytes <= current.total_bytes);
    assert!(current.records_processed >= previous.records_processed);
    assert!(current.packets_retained >= previous.packets_retained);
    assert!(current.packets_retained <= current.records_processed);
    assert!(current.diagnostics >= previous.diagnostics);
}

fn exercise_cancellation(bytes: &[u8]) {
    // Cancellation consumes its importer. A second, separately bounded owner
    // lets the same input also exercise terminal processing without retaining
    // parser views or making an unbounded capture copy.
    let Ok(mut importer) = CaptureImporter::new(bytes.to_vec().into_boxed_slice(), fuzz_limits())
    else {
        return;
    };
    let before = importer.progress();
    let _ = importer.step(1, INITIAL_STEP_BYTE_BUDGET);
    let cancelled = importer.cancel();
    assert_monotonic(before, cancelled);
}

fn exercise_to_terminal(bytes: Vec<u8>) {
    let Ok(mut importer) = CaptureImporter::new(bytes.into_boxed_slice(), fuzz_limits()) else {
        return;
    };
    let mut previous = importer.progress();
    let mut byte_budget = INITIAL_STEP_BYTE_BUDGET;

    for _ in 0..MAX_DRIVER_STEPS {
        let outcome = match importer.step(STEP_RECORD_BUDGET, byte_budget) {
            Ok(outcome) => outcome,
            Err(_) => {
                assert_monotonic(previous, importer.cancel());
                return;
            }
        };

        match outcome {
            ImportStep::NeedsBudget {
                progress,
                minimum_bytes,
            } => {
                assert_eq!(progress, previous);
                assert!(minimum_bytes > byte_budget);
                assert!(minimum_bytes <= u64::from(fuzz_limits().max_block_bytes));
                byte_budget = minimum_bytes;
            }
            ImportStep::Progress(progress) => {
                assert_monotonic(previous, progress);
                assert!(progress.consumed_bytes > previous.consumed_bytes);
                assert!(progress.consumed_bytes - previous.consumed_bytes <= byte_budget);
                assert!(
                    progress.records_processed - previous.records_processed
                        <= u64::from(STEP_RECORD_BUDGET)
                );
                previous = progress;
                byte_budget = INITIAL_STEP_BYTE_BUDGET;
            }
            ImportStep::Ready(progress) => {
                assert_monotonic(previous, progress);
                assert!(importer.is_complete());
                assert_eq!(
                    importer
                        .step(STEP_RECORD_BUDGET, INITIAL_STEP_BYTE_BUDGET)
                        .expect("a completed importer remains ready"),
                    ImportStep::Ready(progress)
                );
                let _ = importer.finish();
                return;
            }
        }
    }

    panic!("bounded importer did not reach a terminal result");
}

fuzz_target!(|data: &[u8]| {
    let Some(bytes) = bounded_capture(data) else {
        return;
    };
    exercise_cancellation(&bytes);
    exercise_to_terminal(bytes);
});
