//! Directional framing-versus-network-decode benchmark using generated packets.
//!
//! This dependency-free harness prints local measurements only. It is not a
//! product throughput claim and its synthetic packets contain no captured data.

use std::{hint::black_box, time::Instant};

use packet_core::{CaptureDataset, CaptureImporter, ImportLimits, ImportStep};
use protocol_decoders::LinkLayerDecoder;

const PACKET_COUNT: u32 = 20_000;
const NETWORK_PACKET_LENGTH: usize = 1_500;
const ETHERNET_PACKET_LENGTH: usize = 14 + NETWORK_PACKET_LENGTH;
const RECORD_LENGTH: usize = 16 + ETHERNET_PACKET_LENGTH;

fn main() {
    let capture = synthetic_capture(PACKET_COUNT);
    let framing_input = capture.clone().into_boxed_slice();
    let decoded_input = capture.into_boxed_slice();
    let input_bytes = decoded_input.len();

    let (framing, framing_elapsed) = import(framing_input, false);
    let (decoded, decoded_elapsed) = import(decoded_input, true);
    assert_eq!(framing.metadata().packet_count, u64::from(PACKET_COUNT));
    assert_eq!(decoded.metadata().packet_count, u64::from(PACKET_COUNT));
    assert!(framing.layers().is_empty());
    assert!(framing.fields().is_empty());
    assert!(decoded.layers().len() > usize::try_from(PACKET_COUNT).expect("count fits usize"));
    assert!(decoded.fields().len() > decoded.layers().len());
    assert!(decoded.diagnostics().is_empty());

    let input_bytes = u32::try_from(input_bytes).expect("benchmark capture fits u32");
    let mebibytes = f64::from(input_bytes) / (1024.0 * 1024.0);
    let framing_rate = mebibytes / framing_elapsed.as_secs_f64();
    let decoded_rate = mebibytes / decoded_elapsed.as_secs_f64();
    eprintln!(
        "network_layer_decode: {PACKET_COUNT} packets, {mebibytes:.2} MiB; framing {framing_elapsed:?} ({framing_rate:.2} MiB/s); full decode {decoded_elapsed:?} ({decoded_rate:.2} MiB/s, {} layers, {} fields); decode/framing {:.2}x",
        decoded.layers().len(),
        decoded.fields().len(),
        decoded_elapsed.as_secs_f64() / framing_elapsed.as_secs_f64(),
    );
}

fn import(bytes: Box<[u8]>, decode: bool) -> (CaptureDataset, std::time::Duration) {
    let started = Instant::now();
    let mut importer = if decode {
        CaptureImporter::new_with_decoder(
            bytes,
            ImportLimits::default(),
            Box::new(LinkLayerDecoder::new()),
        )
    } else {
        CaptureImporter::new(bytes, ImportLimits::default())
    }
    .expect("generated benchmark capture is valid");
    loop {
        match importer
            .step(4_096, 16 * 1024 * 1024)
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
    (dataset, started.elapsed())
}

fn synthetic_capture(packet_count: u32) -> Vec<u8> {
    let ipv4 = ethernet(0x0800, &maximal_ipv4_packet());
    let ipv6 = ethernet(0x86dd, &extension_dense_ipv6_packet());
    assert_eq!(ipv4.len(), ETHERNET_PACKET_LENGTH);
    assert_eq!(ipv6.len(), ETHERNET_PACKET_LENGTH);

    let packet_count_usize = usize::try_from(packet_count).expect("packet count fits usize");
    let mut output = Vec::with_capacity(24 + packet_count_usize * RECORD_LENGTH);
    output.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    output.extend(2_u16.to_le_bytes());
    output.extend(4_u16.to_le_bytes());
    output.extend(0_i32.to_le_bytes());
    output.extend(0_u32.to_le_bytes());
    output.extend(65_535_u32.to_le_bytes());
    output.extend(1_u32.to_le_bytes());
    for packet_index in 0..packet_count {
        let packet = if packet_index % 2 == 0 { &ipv4 } else { &ipv6 };
        let packet_length = u32::try_from(packet.len()).expect("generated packet length fits u32");
        output.extend(packet_index.to_le_bytes());
        output.extend((packet_index % 1_000_000).to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(packet);
    }
    output
}

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(14 + payload.len());
    output.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    output.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    output.extend(ether_type.to_be_bytes());
    output.extend(payload);
    output
}

fn maximal_ipv4_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(NETWORK_PACKET_LENGTH);
    packet.extend([0x4f, 0]);
    packet.extend(1_500_u16.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([64, 17]);
    packet.extend(0_u16.to_be_bytes());
    packet.extend([192, 0, 2, 1]);
    packet.extend([198, 51, 100, 2]);
    for _ in 0..20 {
        packet.extend([0x1e, 2]);
    }
    packet.resize(NETWORK_PACKET_LENGTH, 0xa5);
    let checksum = ipv4_checksum(&packet[..60]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

fn extension_dense_ipv6_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(NETWORK_PACKET_LENGTH);
    packet.extend(0x6000_0000_u32.to_be_bytes());
    packet.extend(1_460_u16.to_be_bytes());
    packet.extend([60, 64]);
    packet.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    for index in 0..8 {
        let next_header = if index == 7 { 17 } else { 60 };
        packet.extend([next_header, 0, 0, 0, 0, 0, 0, 0]);
    }
    packet.resize(NETWORK_PACKET_LENGTH, 0x5a);
    packet
}
