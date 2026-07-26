#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_core::{CaptureDataset, CaptureImporter, ImportLimits, ImportProgress, ImportStep};
use protocol_decoders::LinkLayerDecoder;

const HEX_PREFIX: &[u8] = b"hex:";
const MAX_CAPTURE_BYTES: usize = 4_096;
const MAX_ENCODED_BYTES: usize = HEX_PREFIX.len() + (MAX_CAPTURE_BYTES * 2) + 128;
const MAX_DRIVER_STEPS: usize = (MAX_CAPTURE_BYTES / 4) + 8;
const STEP_RECORD_BUDGET: u32 = 4;
const INITIAL_STEP_BYTE_BUDGET: u64 = 31;

fn fuzz_limits() -> ImportLimits {
    let mut limits = ImportLimits::default();
    limits.max_capture_bytes =
        u64::try_from(MAX_CAPTURE_BYTES).expect("the fuzz input bound fits in u64");
    limits.max_block_bytes = 1_024;
    limits.max_decoded_items_per_block = 64;
    limits.max_decoded_items_per_step = 64;
    limits.max_packets = 256;
    limits.max_sections = 32;
    limits.max_interfaces = 64;
    limits.max_diagnostics = 256;
    limits.max_layers = 1_024;
    limits.max_layers_per_packet = 8;
    limits.max_fields = 8_192;
    limits.max_fields_per_packet = 64;
    limits.max_field_children = 16_384;
    limits.max_field_children_per_packet = 128;
    limits.max_string_bytes = 8_192;
    limits
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

fn decoded_importer(bytes: Box<[u8]>) -> Option<CaptureImporter> {
    CaptureImporter::new_with_decoder(bytes, fuzz_limits(), Box::new(LinkLayerDecoder::default()))
        .ok()
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

fn assert_valid_dataset(dataset: &CaptureDataset) {
    dataset
        .validate()
        .expect("a completed decoded import preserves canonical model invariants");

    for packet in dataset.packets() {
        let layers =
            &dataset.layers()[packet.layers.start() as usize..packet.layers.end() as usize];
        for layer in layers {
            assert!(layer.byte_range.start() >= packet.data.start());
            assert!(layer.byte_range.end() <= packet.data.end());
        }
    }
}

fn exercise_cancellation(bytes: &[u8]) {
    let Some(mut importer) = decoded_importer(bytes.to_vec().into_boxed_slice()) else {
        return;
    };
    let before = importer.progress();
    let _ = importer.step(1, INITIAL_STEP_BYTE_BUDGET);
    let cancelled = importer.cancel();
    assert_monotonic(before, cancelled);
}

fn exercise_to_terminal(bytes: Vec<u8>) {
    let Some(mut importer) = decoded_importer(bytes.into_boxed_slice()) else {
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
                let dataset = importer
                    .finish()
                    .expect("a ready decoded import finalizes into a valid dataset");
                assert_valid_dataset(&dataset);
                return;
            }
        }
    }

    panic!("bounded decoded importer did not reach a terminal result");
}

fuzz_target!(|data: &[u8]| {
    let Some(bytes) = bounded_capture(data) else {
        return;
    };
    exercise_cancellation(&bytes);
    exercise_to_terminal(bytes);
});
