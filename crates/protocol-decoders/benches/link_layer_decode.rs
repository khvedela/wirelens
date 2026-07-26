//! Directional decoder-through-import benchmark using generated Ethernet data.
//!
//! This dependency-free harness prints local measurements only. It is not a
//! product throughput claim and its synthetic packets contain no captured data.

use std::{hint::black_box, time::Instant};

use packet_core::{CaptureImporter, ImportLimits, ImportStep};
use protocol_decoders::LinkLayerDecoder;

const PACKET_COUNT: u32 = 50_000;
const AVERAGE_RECORD_LENGTH: usize = 16 + 44;

fn main() {
    let capture = synthetic_capture(PACKET_COUNT);
    let input_bytes = capture.len();
    let started = Instant::now();
    let mut importer = CaptureImporter::new_with_decoder(
        capture.into_boxed_slice(),
        ImportLimits::default(),
        Box::new(LinkLayerDecoder::new()),
    )
    .expect("generated benchmark capture is valid");
    loop {
        match importer
            .step(4_096, 4 * 1024 * 1024)
            .expect("benchmark import step succeeds")
        {
            ImportStep::Progress(_) => {}
            ImportStep::NeedsBudget { minimum_bytes, .. } => {
                importer
                    .step(1, minimum_bytes)
                    .expect("reported minimum makes progress");
            }
            ImportStep::Ready(_) => break,
        }
    }
    let dataset = black_box(importer.finish().expect("benchmark dataset validates"));
    let elapsed = started.elapsed();
    let tagged_packets = PACKET_COUNT / 2;
    let untagged_packets = PACKET_COUNT - tagged_packets;
    let expected_layers = u64::from(untagged_packets) * 2 + u64::from(tagged_packets) * 3;
    let expected_fields = u64::from(untagged_packets) * 16 + u64::from(tagged_packets) * 23;
    assert_eq!(dataset.metadata().packet_count, u64::from(PACKET_COUNT));
    assert_eq!(dataset.layers().len() as u64, expected_layers);
    assert_eq!(dataset.fields().len() as u64, expected_fields);
    assert!(dataset.diagnostics().is_empty());

    let input_bytes = u32::try_from(input_bytes).expect("benchmark capture fits u32");
    let mebibytes = f64::from(input_bytes) / (1024.0 * 1024.0);
    eprintln!(
        "link_layer_decode: {PACKET_COUNT} packets, {mebibytes:.2} MiB, {elapsed:?}, {:.2} MiB/s, {} layers, {} fields",
        mebibytes / elapsed.as_secs_f64(),
        dataset.layers().len(),
        dataset.fields().len(),
    );
}

fn synthetic_capture(packet_count: u32) -> Vec<u8> {
    let request = ethernet_arp(1, None);
    let reply = ethernet_arp(2, Some(100));
    let mut output = Vec::with_capacity(24 + packet_count as usize * AVERAGE_RECORD_LENGTH);
    output.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    output.extend(2_u16.to_le_bytes());
    output.extend(4_u16.to_le_bytes());
    output.extend(0_i32.to_le_bytes());
    output.extend(0_u32.to_le_bytes());
    output.extend(65_535_u32.to_le_bytes());
    output.extend(1_u32.to_le_bytes());
    for packet_index in 0..packet_count {
        let packet = if packet_index % 2 == 0 {
            &request
        } else {
            &reply
        };
        let packet_length = u32::try_from(packet.len()).expect("generated packet length fits u32");
        output.extend(packet_index.to_le_bytes());
        output.extend((packet_index % 1_000_000).to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(packet);
    }
    output
}

fn ethernet_arp(operation: u16, vlan_identifier: Option<u16>) -> Vec<u8> {
    let mut output = Vec::with_capacity(if vlan_identifier.is_some() { 46 } else { 42 });
    output.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    output.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    if let Some(identifier) = vlan_identifier {
        output.extend(0x8100_u16.to_be_bytes());
        output.extend((identifier & 0x0fff).to_be_bytes());
    }
    output.extend(0x0806_u16.to_be_bytes());
    output.extend(1_u16.to_be_bytes());
    output.extend(0x0800_u16.to_be_bytes());
    output.extend([6, 4]);
    output.extend(operation.to_be_bytes());
    output.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    output.extend([192, 0, 2, 1]);
    output.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    output.extend([192, 0, 2, 2]);
    output
}
