use packet_core::{CaptureImporter, ImportLimits, ImportProgress, ImportStep};
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, RngAlgorithm, TestCaseError, TestCaseResult, TestRng, TestRunner},
};

const MAX_GENERATED_BYTES: usize = 768;
const MAX_DRIVER_STEPS: usize = MAX_GENERATED_BYTES + 4;
const STEP_RECORD_BUDGET: u32 = 3;
const INITIAL_STEP_BYTE_BUDGET: u64 = 17;

fn property_limits() -> ImportLimits {
    ImportLimits {
        max_capture_bytes: u64::try_from(MAX_GENERATED_BYTES)
            .expect("the generated input bound fits in u64"),
        max_block_bytes: 512,
        max_decoded_items_per_block: 64,
        max_decoded_items_per_step: 64,
        max_packets: 128,
        max_sections: 16,
        max_interfaces: 32,
        max_diagnostics: 32,
        max_layers: 512,
        max_layers_per_packet: 8,
        max_fields: 2_048,
        max_fields_per_packet: 32,
        max_field_children: 2_048,
        max_field_children_per_packet: 64,
        max_string_bytes: 4_096,
    }
}

fn seeded_runner(seed: [u8; 32], cases: u32) -> TestRunner {
    let config = Config {
        cases,
        failure_persistence: None,
        max_shrink_iters: 4_096,
        ..Config::default()
    };
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    TestRunner::new_with_rng(config, rng)
}

fn assert_progress_invariants(previous: ImportProgress, current: ImportProgress) -> TestCaseResult {
    prop_assert_eq!(current.total_bytes, previous.total_bytes);
    prop_assert!(current.consumed_bytes >= previous.consumed_bytes);
    prop_assert!(current.consumed_bytes <= current.total_bytes);
    prop_assert!(current.records_processed >= previous.records_processed);
    prop_assert!(current.packets_retained >= previous.packets_retained);
    prop_assert!(current.packets_retained <= current.records_processed);
    prop_assert!(current.diagnostics >= previous.diagnostics);
    Ok(())
}

fn drive_importer(bytes: Vec<u8>) -> TestCaseResult {
    let expected_length =
        u64::try_from(bytes.len()).expect("the generated input length fits in u64");
    let Ok(mut importer) = CaptureImporter::new(bytes.into_boxed_slice(), property_limits()) else {
        return Ok(());
    };

    let initial = importer.progress();
    prop_assert_eq!(initial.total_bytes, expected_length);
    prop_assert_eq!(initial.consumed_bytes, 0);
    prop_assert_eq!(initial.records_processed, 0);

    let mut previous = initial;
    let mut byte_budget = INITIAL_STEP_BYTE_BUDGET;
    for _ in 0..MAX_DRIVER_STEPS {
        let Ok(outcome) = importer.step(STEP_RECORD_BUDGET, byte_budget) else {
            let cancelled = importer.cancel();
            assert_progress_invariants(previous, cancelled)?;
            return Ok(());
        };

        match outcome {
            ImportStep::NeedsBudget {
                progress,
                minimum_bytes,
            } => {
                prop_assert_eq!(progress, previous);
                prop_assert!(minimum_bytes > byte_budget);
                prop_assert!(minimum_bytes <= u64::from(property_limits().max_block_bytes));
                byte_budget = minimum_bytes;
            }
            ImportStep::Progress(progress) => {
                assert_progress_invariants(previous, progress)?;
                prop_assert!(progress.consumed_bytes > previous.consumed_bytes);
                prop_assert!(progress.consumed_bytes - previous.consumed_bytes <= byte_budget);
                prop_assert!(
                    progress.records_processed - previous.records_processed
                        <= u64::from(STEP_RECORD_BUDGET)
                );
                previous = progress;
                byte_budget = INITIAL_STEP_BYTE_BUDGET;
            }
            ImportStep::Ready(progress) => {
                assert_progress_invariants(previous, progress)?;
                prop_assert!(importer.is_complete());
                prop_assert_eq!(
                    importer
                        .step(STEP_RECORD_BUDGET, INITIAL_STEP_BYTE_BUDGET)
                        .map_err(|error| TestCaseError::fail(error.to_string()))?,
                    ImportStep::Ready(progress)
                );
                let _ = importer.finish();
                return Ok(());
            }
        }
    }

    Err(TestCaseError::fail(format!(
        "import did not terminate within {MAX_DRIVER_STEPS} bounded steps"
    )))
}

fn legacy_capture(with_packet: bool) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, // little-endian PCAP magic
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // timezone and timestamp accuracy
        0xff, 0xff, 0, 0, // snap length
        0x01, 0, 0, 0, // Ethernet link type
    ];
    if with_packet {
        bytes.extend([
            1, 0, 0, 0, // seconds
            2, 0, 0, 0, // microseconds
            4, 0, 0, 0, // captured length
            4, 0, 0, 0, // original length
            0, 1, 2, 3, // synthetic payload
        ]);
    }
    bytes
}

fn pcapng_capture(with_interface: bool) -> Vec<u8> {
    let mut bytes = vec![
        0x0a, 0x0d, 0x0d, 0x0a, // section header block
        0x1c, 0, 0, 0, // block length
        0x4d, 0x3c, 0x2b, 0x1a, // little-endian byte-order magic
        1, 0, 0, 0, // version 1.0
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // unknown section length
        0x1c, 0, 0, 0, // repeated block length
    ];
    if with_interface {
        bytes.extend([
            1, 0, 0, 0, // interface description block
            0x14, 0, 0, 0, // block length
            1, 0, 0, 0, // Ethernet link type and reserved bytes
            0xff, 0xff, 0, 0, // snap length
            0x14, 0, 0, 0, // repeated block length
        ]);
    }
    bytes
}

fn capture_shaped_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        0_u8..5,
        any::<bool>(),
        0_usize..=MAX_GENERATED_BYTES,
        vec((any::<usize>(), any::<u8>()), 0..=16),
        vec(any::<u8>(), 0..=96),
    )
        .prop_map(|(shape, truncate, cut, mutations, suffix)| {
            let mut bytes = match shape {
                0 => legacy_capture(false),
                1 => legacy_capture(true),
                2 => pcapng_capture(false),
                3 => pcapng_capture(true),
                _ => vec![0x0a, 0x0d, 0x0d, 0x0a],
            };
            bytes.extend(suffix);
            bytes.truncate(MAX_GENERATED_BYTES);

            for (index, value) in mutations {
                if !bytes.is_empty() {
                    let index = index % bytes.len();
                    bytes[index] ^= value;
                }
            }

            if truncate {
                bytes.truncate(cut.min(bytes.len()));
            }
            bytes
        })
}

#[test]
fn parser_is_total_for_deterministic_arbitrary_bytes() {
    let strategy = vec(any::<u8>(), 0..=MAX_GENERATED_BYTES);
    seeded_runner(*b"wirelens-totality-seed-000000000", 384)
        .run(&strategy, drive_importer)
        .expect("deterministic arbitrary-byte property");
}

#[test]
fn progress_is_monotonic_for_deterministic_capture_mutations() {
    seeded_runner(*b"wirelens-progress-seed-000000000", 512)
        .run(&capture_shaped_bytes(), drive_importer)
        .expect("deterministic capture-mutation property");
}
