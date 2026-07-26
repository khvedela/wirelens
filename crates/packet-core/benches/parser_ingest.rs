//! Directional parser-ingest benchmark using a generated legacy PCAP.
//!
//! This is intentionally dependency-free and prints local measurements only;
//! it is not a product throughput claim.

use std::{hint::black_box, time::Instant};

use packet_core::{CaptureImporter, ImportLimits, ImportStep};

const PACKET_COUNT: u32 = 100_000;
const PAYLOAD_LENGTH: usize = 64;

fn main() {
    let capture = synthetic_capture(PACKET_COUNT);
    let input_bytes = capture.len();
    let started = Instant::now();
    let mut importer = CaptureImporter::new(capture.into_boxed_slice(), ImportLimits::default())
        .expect("benchmark capture header must be valid");
    loop {
        match importer
            .step(4_096, 4 * 1024 * 1024)
            .expect("benchmark import step must succeed")
        {
            ImportStep::Progress(_) => {}
            ImportStep::NeedsBudget { minimum_bytes, .. } => {
                importer
                    .step(1, minimum_bytes)
                    .expect("reported minimum must make progress");
            }
            ImportStep::Ready(_) => break,
        }
    }
    let dataset = black_box(
        importer
            .finish()
            .expect("benchmark finalization must succeed"),
    );
    let elapsed = started.elapsed();
    assert_eq!(dataset.metadata().packet_count, u64::from(PACKET_COUNT));
    let input_bytes = u32::try_from(input_bytes).expect("benchmark capture fits in u32");
    let mebibytes = f64::from(input_bytes) / (1024.0 * 1024.0);
    eprintln!(
        "parser_ingest: {PACKET_COUNT} packets, {mebibytes:.2} MiB, {elapsed:?}, {:.2} MiB/s",
        mebibytes / elapsed.as_secs_f64()
    );
}

fn synthetic_capture(packet_count: u32) -> Vec<u8> {
    let record_length = 16 + PAYLOAD_LENGTH;
    let capacity = 24 + packet_count as usize * record_length;
    let mut output = Vec::with_capacity(capacity);
    output.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    output.extend(2_u16.to_le_bytes());
    output.extend(4_u16.to_le_bytes());
    output.extend(0_i32.to_le_bytes());
    output.extend(0_u32.to_le_bytes());
    output.extend(65_535_u32.to_le_bytes());
    output.extend(1_u32.to_le_bytes());
    for packet in 0..packet_count {
        output.extend(packet.to_le_bytes());
        output.extend((packet % 1_000_000).to_le_bytes());
        let payload_length = u32::try_from(PAYLOAD_LENGTH).expect("payload length fits in u32");
        output.extend(payload_length.to_le_bytes());
        output.extend(payload_length.to_le_bytes());
        output.extend([0x5a; PAYLOAD_LENGTH]);
    }
    output
}
