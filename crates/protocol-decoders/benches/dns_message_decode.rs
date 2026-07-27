//! Directional framing-versus-DNS-decode benchmark using generated packets.
//!
//! This dependency-free harness prints local measurements only. It is not a
//! product throughput claim and its synthetic packets contain no captured data.

use std::{hint::black_box, time::Instant};

use packet_core::{CaptureDataset, CaptureImporter, ImportLimits, ImportStep};
use protocol_decoders::LinkLayerDecoder;

const PACKET_COUNT: u32 = 10_000;

fn main() {
    run_case("compressed_response", &compressed_response());
    run_case("accepted_item_limits", &accepted_item_limits());
}

fn run_case(name: &str, dns: &[u8]) {
    let packet = ethernet(&udp_ipv4_packet(dns));
    let capture = synthetic_capture(PACKET_COUNT, &packet);
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
        usize::try_from(PACKET_COUNT).expect("count fits usize") * 4
    );
    assert!(decoded.fields().len() > decoded.layers().len());
    assert!(decoded.diagnostics().is_empty());

    let input_bytes = u32::try_from(input_bytes).expect("benchmark capture fits u32");
    let mebibytes = f64::from(input_bytes) / (1024.0 * 1024.0);
    let framing_rate = mebibytes / framing_elapsed.as_secs_f64();
    let decoded_rate = mebibytes / decoded_elapsed.as_secs_f64();
    eprintln!(
        "dns_message_decode/{name}: {PACKET_COUNT} packets, {mebibytes:.2} MiB; framing {framing_elapsed:?} ({framing_rate:.2} MiB/s); DNS decode {decoded_elapsed:?} ({decoded_rate:.2} MiB/s, {} fields); decode/framing {:.2}x",
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

fn synthetic_capture(packet_count: u32, packet: &[u8]) -> Vec<u8> {
    let packet_count = usize::try_from(packet_count).expect("packet count fits usize");
    let record_length = 16 + packet.len();
    let mut output = Vec::with_capacity(24 + packet_count * record_length);
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
        output.extend(packet);
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

fn udp_ipv4_packet(dns: &[u8]) -> Vec<u8> {
    let udp_length = u16::try_from(8 + dns.len()).expect("synthetic UDP length fits u16");
    let ipv4_length = udp_length
        .checked_add(20)
        .expect("synthetic IPv4 length fits u16");
    let mut packet = Vec::with_capacity(usize::from(ipv4_length));
    packet.extend([0x45, 0]);
    packet.extend(ipv4_length.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([64, 17]);
    packet.extend(0_u16.to_be_bytes());
    packet.extend([192, 0, 2, 1]);
    packet.extend([198, 51, 100, 2]);
    let ipv4_checksum = checksum(&packet);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());
    packet.extend(53_000_u16.to_be_bytes());
    packet.extend(53_u16.to_be_bytes());
    packet.extend(udp_length.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend(dns);
    packet
}

fn compressed_response() -> Vec<u8> {
    let mut message = dns_header(1, 2);
    push_example_name(&mut message);
    message.extend(1_u16.to_be_bytes());
    message.extend(1_u16.to_be_bytes());

    push_record_header(&mut message, 1, 4);
    message.extend([192, 0, 2, 10]);
    push_record_header(&mut message, 28, 16);
    message.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
    message
}

fn accepted_item_limits() -> Vec<u8> {
    const QUESTIONS: u16 = 16;
    const ANSWERS: u16 = 16;

    let mut message = dns_header(QUESTIONS, ANSWERS);
    push_example_name(&mut message);
    message.extend(6_u16.to_be_bytes());
    message.extend(1_u16.to_be_bytes());
    for _ in 1..QUESTIONS {
        message.extend([0xc0, 0x0c]);
        message.extend(6_u16.to_be_bytes());
        message.extend(1_u16.to_be_bytes());
    }
    for serial in 0..u32::from(ANSWERS) {
        message.extend([0xc0, 0x0c]);
        message.extend(6_u16.to_be_bytes());
        message.extend(1_u16.to_be_bytes());
        message.extend(60_u32.to_be_bytes());
        message.extend(24_u16.to_be_bytes());
        message.extend([0xc0, 0x0c]);
        message.extend([0xc0, 0x0c]);
        message.extend(serial.to_be_bytes());
        message.extend(3_600_u32.to_be_bytes());
        message.extend(600_u32.to_be_bytes());
        message.extend(86_400_u32.to_be_bytes());
        message.extend(300_u32.to_be_bytes());
    }
    message
}

fn dns_header(question_count: u16, answer_count: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend(0x1234_u16.to_be_bytes());
    message.extend(0x8180_u16.to_be_bytes());
    message.extend(question_count.to_be_bytes());
    message.extend(answer_count.to_be_bytes());
    message.extend(0_u16.to_be_bytes());
    message.extend(0_u16.to_be_bytes());
    message
}

fn push_example_name(message: &mut Vec<u8>) {
    message.extend([3, b'w', b'w', b'w']);
    message.extend([7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    message.extend([3, b'c', b'o', b'm', 0]);
}

fn push_record_header(message: &mut Vec<u8>, record_type: u16, data_length: u16) {
    message.extend([0xc0, 0x0c]);
    message.extend(record_type.to_be_bytes());
    message.extend(1_u16.to_be_bytes());
    message.extend(300_u32.to_be_bytes());
    message.extend(data_length.to_be_bytes());
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}
