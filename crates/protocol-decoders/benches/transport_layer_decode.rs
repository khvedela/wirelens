//! Directional framing-versus-transport-decode benchmark using generated TCP packets.
//!
//! This dependency-free harness prints local measurements only. It is not a
//! product throughput claim and its synthetic packets contain no captured data.

use std::{hint::black_box, time::Instant};

use packet_core::{CaptureDataset, CaptureImporter, ImportLimits, ImportStep};
use protocol_decoders::LinkLayerDecoder;

const PACKET_COUNT: u32 = 10_000;
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
    assert_eq!(
        decoded.layers().len(),
        usize::try_from(PACKET_COUNT).expect("count fits usize") * 3
    );
    assert!(decoded.fields().len() > decoded.layers().len());
    assert!(decoded.diagnostics().is_empty());

    let input_bytes = u32::try_from(input_bytes).expect("benchmark capture fits u32");
    let mebibytes = f64::from(input_bytes) / (1024.0 * 1024.0);
    let framing_rate = mebibytes / framing_elapsed.as_secs_f64();
    let decoded_rate = mebibytes / decoded_elapsed.as_secs_f64();
    eprintln!(
        "transport_layer_decode: {PACKET_COUNT} packets, {mebibytes:.2} MiB; framing {framing_elapsed:?} ({framing_rate:.2} MiB/s); TCP decode {decoded_elapsed:?} ({decoded_rate:.2} MiB/s, {} fields); decode/framing {:.2}x",
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
    let packet = ethernet(&tcp_ipv4_packet());
    assert_eq!(packet.len(), ETHERNET_PACKET_LENGTH);

    let packet_count = usize::try_from(packet_count).expect("packet count fits usize");
    let mut output = Vec::with_capacity(24 + packet_count * RECORD_LENGTH);
    output.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    output.extend(2_u16.to_le_bytes());
    output.extend(4_u16.to_le_bytes());
    output.extend(0_i32.to_le_bytes());
    output.extend(0_u32.to_le_bytes());
    output.extend(65_535_u32.to_le_bytes());
    output.extend(1_u32.to_le_bytes());
    for packet_index in 0..u32::try_from(packet_count).expect("count fits u32") {
        let packet_length = u32::try_from(packet.len()).expect("packet length fits u32");
        output.extend(packet_index.to_le_bytes());
        output.extend((packet_index % 1_000_000).to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(packet_length.to_le_bytes());
        output.extend(&packet);
    }
    output
}

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(14 + payload.len());
    output.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    output.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    output.extend(0x0800_u16.to_be_bytes());
    output.extend(payload);
    output
}

fn tcp_ipv4_packet() -> Vec<u8> {
    const IPV4_HEADER_LENGTH: usize = 20;
    const TCP_HEADER_LENGTH: usize = 40;
    const TCP_LENGTH: usize = NETWORK_PACKET_LENGTH - IPV4_HEADER_LENGTH;
    const SOURCE: [u8; 4] = [192, 0, 2, 1];
    const DESTINATION: [u8; 4] = [198, 51, 100, 2];

    let mut packet = Vec::with_capacity(NETWORK_PACKET_LENGTH);
    packet.extend([0x45, 0]);
    packet.extend(1_500_u16.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([64, 6]);
    packet.extend(0_u16.to_be_bytes());
    packet.extend(SOURCE);
    packet.extend(DESTINATION);
    let ipv4_checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let tcp_start = packet.len();
    packet.extend(12_345_u16.to_be_bytes());
    packet.extend(443_u16.to_be_bytes());
    packet.extend(0x0102_0304_u32.to_be_bytes());
    packet.extend(0x0506_0708_u32.to_be_bytes());
    packet.extend([0xa0, 0x18]);
    packet.extend(32_768_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([2, 4, 0x05, 0xb4]);
    packet.extend([1, 3, 3, 7]);
    packet.extend([4, 2]);
    packet.extend([8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
    assert_eq!(packet.len(), tcp_start + TCP_HEADER_LENGTH);
    packet.resize(NETWORK_PACKET_LENGTH, 0xa5);

    let pseudo_protocol = [0, 6];
    let tcp_length = u16::try_from(TCP_LENGTH)
        .expect("synthetic TCP length fits u16")
        .to_be_bytes();
    let tcp_checksum = checksum(&[
        &SOURCE,
        &DESTINATION,
        &pseudo_protocol,
        &tcp_length,
        &packet[tcp_start..],
    ]);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u64;
    let mut high = None;
    for part in parts {
        for &byte in *part {
            if let Some(high) = high.take() {
                sum += u64::from(u16::from_be_bytes([high, byte]));
            } else {
                high = Some(byte);
            }
        }
    }
    if let Some(high) = high {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}
