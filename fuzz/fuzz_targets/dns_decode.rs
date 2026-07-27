#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_core::{
    CaptureDataset, CaptureImporter, DiagnosticScope, FieldValue, ImportLimits, ImportProgress,
    ImportStep,
};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, DECODER_VOCABULARY_COUNT_UPPER_BOUND, LinkLayerDecoder,
};

const HEX_PREFIX: &[u8] = b"hex:";
const MAX_DNS_BYTES: usize = 4_096;
const MAX_FUZZ_INPUT_BYTES: usize = MAX_DNS_BYTES + 1;
const MAX_ENCODED_BYTES: usize = HEX_PREFIX.len() + (MAX_FUZZ_INPUT_BYTES * 2) + 128;
const ETHERNET_HEADER_BYTES: usize = 14;
const IPV4_HEADER_BYTES: usize = 20;
const UDP_HEADER_BYTES: usize = 8;
const TCP_HEADER_BYTES: usize = 20;
const TCP_DNS_LENGTH_BYTES: usize = 2;
const LEGACY_HEADER_BYTES: usize = 24;
const LEGACY_RECORD_HEADER_BYTES: usize = 16;
const MAX_TRANSPORT_BYTES: usize = TCP_HEADER_BYTES + TCP_DNS_LENGTH_BYTES + MAX_DNS_BYTES;
const MAX_FRAME_BYTES: usize = ETHERNET_HEADER_BYTES + IPV4_HEADER_BYTES + MAX_TRANSPORT_BYTES;
const MAX_RECORD_BYTES: usize = LEGACY_RECORD_HEADER_BYTES + MAX_FRAME_BYTES;
const MAX_CAPTURE_BYTES: usize = LEGACY_HEADER_BYTES + LEGACY_RECORD_HEADER_BYTES + MAX_FRAME_BYTES;
const MAX_DRIVER_STEPS: usize = 8;
const INITIAL_STEP_BYTE_BUDGET: u64 = 31;
const DNS_PORT: u16 = 53;
const SOURCE_PORT: u16 = 53_000;
const SOURCE_ADDRESS: [u8; 4] = [192, 0, 2, 1];
const DESTINATION_ADDRESS: [u8; 4] = [198, 51, 100, 2];

#[derive(Clone, Copy)]
enum Framing {
    Udp,
    TcpExact,
    TcpTrailing,
    TcpPartial,
}

impl Framing {
    const fn from_selector(selector: u8) -> Self {
        match selector & 3 {
            0 => Self::Udp,
            1 => Self::TcpExact,
            2 => Self::TcpTrailing,
            _ => Self::TcpPartial,
        }
    }
}

fn fuzz_limits() -> ImportLimits {
    ImportLimits {
        max_capture_bytes: MAX_CAPTURE_BYTES as u64,
        max_block_bytes: MAX_RECORD_BYTES as u32,
        max_decoded_items_per_block: 16,
        max_decoded_items_per_step: 16,
        max_packets: 1,
        max_sections: 1,
        max_interfaces: 1,
        max_diagnostics: 1,
        max_layers: DECODER_MAX_LAYERS_PER_PACKET,
        max_layers_per_packet: DECODER_MAX_LAYERS_PER_PACKET,
        max_fields: DECODER_MAX_FIELDS_PER_PACKET,
        max_fields_per_packet: DECODER_MAX_FIELDS_PER_PACKET,
        max_field_children: DECODER_MAX_FIELD_CHILDREN_PER_PACKET,
        max_field_children_per_packet: DECODER_MAX_FIELD_CHILDREN_PER_PACKET,
        max_string_bytes: 256 * 1024,
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
            if decoded.len() == MAX_FUZZ_INPUT_BYTES {
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

fn bounded_input(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_ENCODED_BYTES {
        return None;
    }
    if data.starts_with(HEX_PREFIX) {
        if let Some(decoded) = decode_text_seed(data) {
            return Some(decoded);
        }
    }
    (data.len() <= MAX_FUZZ_INPUT_BYTES).then(|| data.to_vec())
}

fn udp_segment(payload: &[u8]) -> Vec<u8> {
    let length = UDP_HEADER_BYTES + payload.len();
    let mut segment = Vec::with_capacity(length);
    segment.extend(SOURCE_PORT.to_be_bytes());
    segment.extend(DNS_PORT.to_be_bytes());
    segment.extend(
        u16::try_from(length)
            .expect("bounded UDP length fits u16")
            .to_be_bytes(),
    );
    // A zero checksum is valid for the synthetic IPv4 UDP path and avoids
    // coupling the DNS fuzz target to checksum mutation.
    segment.extend(0_u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn tcp_segment(payload: &[u8], framing: Framing) -> Vec<u8> {
    let exact_length = u16::try_from(payload.len()).expect("bounded DNS length fits u16");
    let declared_length = match framing {
        Framing::TcpExact => exact_length,
        Framing::TcpTrailing => exact_length.saturating_sub(1),
        Framing::TcpPartial => exact_length.saturating_add(1),
        Framing::Udp => unreachable!("UDP framing does not produce a TCP segment"),
    };
    let mut segment = Vec::with_capacity(TCP_HEADER_BYTES + TCP_DNS_LENGTH_BYTES + payload.len());
    segment.extend(SOURCE_PORT.to_be_bytes());
    segment.extend(DNS_PORT.to_be_bytes());
    segment.extend(0x0102_0304_u32.to_be_bytes());
    segment.extend(0x0506_0708_u32.to_be_bytes());
    segment.extend([0x50, 0x18]);
    segment.extend(32_768_u16.to_be_bytes());
    segment.extend(0_u16.to_be_bytes());
    segment.extend(0_u16.to_be_bytes());
    segment.extend(declared_length.to_be_bytes());
    segment.extend_from_slice(payload);

    let checksum = transport_checksum(6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

fn ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
    let total_length = IPV4_HEADER_BYTES + transport.len();
    let mut packet = Vec::with_capacity(total_length);
    packet.extend([0x45, 0]);
    packet.extend(
        u16::try_from(total_length)
            .expect("bounded IPv4 length fits u16")
            .to_be_bytes(),
    );
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([64, protocol]);
    packet.extend(0_u16.to_be_bytes());
    packet.extend(SOURCE_ADDRESS);
    packet.extend(DESTINATION_ADDRESS);
    let checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(transport);
    packet
}

fn transport_checksum(protocol: u8, segment: &[u8]) -> u16 {
    let protocol_bytes = [0, protocol];
    let length = u16::try_from(segment.len())
        .expect("bounded transport length fits u16")
        .to_be_bytes();
    checksum(&[
        &SOURCE_ADDRESS,
        &DESTINATION_ADDRESS,
        &protocol_bytes,
        &length,
        segment,
    ])
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

fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_BYTES + payload.len());
    frame.extend([0x02, 0, 0, 0, 0, 1]);
    frame.extend([0x02, 0, 0, 0, 0, 2]);
    frame.extend(0x0800_u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn legacy_pcap(frame: &[u8]) -> Vec<u8> {
    let frame_length = u32::try_from(frame.len()).expect("bounded frame length fits u32");
    let mut capture =
        Vec::with_capacity(LEGACY_HEADER_BYTES + LEGACY_RECORD_HEADER_BYTES + frame.len());
    capture.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    capture.extend(2_u16.to_le_bytes());
    capture.extend(4_u16.to_le_bytes());
    capture.extend(0_i32.to_le_bytes());
    capture.extend(0_u32.to_le_bytes());
    capture.extend(65_535_u32.to_le_bytes());
    capture.extend(1_u32.to_le_bytes());
    capture.extend(1_700_000_000_u32.to_le_bytes());
    capture.extend(123_456_u32.to_le_bytes());
    capture.extend(frame_length.to_le_bytes());
    capture.extend(frame_length.to_le_bytes());
    capture.extend_from_slice(frame);
    capture
}

fn wrapped_capture(input: &[u8]) -> Vec<u8> {
    let (selector, dns) = input
        .split_first()
        .map_or((0, &[][..]), |(&selector, bytes)| (selector, bytes));
    assert!(dns.len() <= MAX_DNS_BYTES);
    let framing = Framing::from_selector(selector);
    let (protocol, segment) = match framing {
        Framing::Udp => (17, udp_segment(dns)),
        Framing::TcpExact | Framing::TcpTrailing | Framing::TcpPartial => {
            (6, tcp_segment(dns, framing))
        }
    };
    let frame = ethernet_frame(&ipv4_packet(protocol, &segment));
    let capture = legacy_pcap(&frame);
    assert!(capture.len() <= MAX_CAPTURE_BYTES);
    capture
}

fn decoded_importer(bytes: Box<[u8]>) -> CaptureImporter {
    CaptureImporter::new_with_decoder(bytes, fuzz_limits(), Box::new(LinkLayerDecoder::new()))
        .expect("the deterministic capture wrapper is valid")
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
        .expect("a completed DNS decode preserves canonical model invariants");
    assert_eq!(dataset.metadata().packet_count, 1);
    assert_eq!(dataset.packets().len(), 1);
    assert_eq!(dataset.sections().len(), 1);
    assert_eq!(dataset.interfaces().len(), 1);
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
    assert!(dataset.diagnostics().len() <= 1);
    // Every capture-derived DNS string value owns at least one field, while
    // the remaining strings belong to the decoder's fixed safe vocabulary.
    assert!(
        dataset.interned_string_count()
            <= DECODER_VOCABULARY_COUNT_UPPER_BOUND as usize + dataset.fields().len()
    );
    assert!(
        dataset
            .interned_string_bytes()
            .is_some_and(|bytes| bytes <= u64::from(fuzz_limits().max_string_bytes))
    );

    let packet = dataset.packets()[0];
    assert_eq!(packet.layers.start(), 0);
    assert_eq!(packet.layers.end() as usize, dataset.layers().len());
    assert_eq!(packet.diagnostics.start(), 0);
    assert_eq!(
        packet.diagnostics.end() as usize,
        dataset.diagnostics().len()
    );
    let contains = |range: packet_core::ByteRange| {
        range.start() >= packet.data.start() && range.end() <= packet.data.end()
    };
    for layer in dataset.layers() {
        assert!(contains(layer.byte_range));
    }
    for field in dataset.fields() {
        assert!(contains(field.byte_range));
        if let FieldValue::Bytes(range) = field.value {
            assert!(contains(range));
        }
    }
    for child in dataset.field_children() {
        assert!((child.0 as usize) < dataset.fields().len());
    }
    for diagnostic in dataset.diagnostics() {
        assert_eq!(diagnostic.scope, DiagnosticScope::Packet(packet.id));
        if let Some(range) = diagnostic.byte_range {
            assert!(contains(range));
        }
    }
}

fn exercise_cancellation(bytes: &[u8]) {
    let mut importer = decoded_importer(bytes.to_vec().into_boxed_slice());
    let before = importer.progress();
    let _ = importer.step(1, INITIAL_STEP_BYTE_BUDGET);
    let cancelled = importer.cancel();
    assert_monotonic(before, cancelled);
}

fn exercise_to_terminal(bytes: Vec<u8>) {
    let mut importer = decoded_importer(bytes.into_boxed_slice());
    let mut previous = importer.progress();
    let mut byte_budget = INITIAL_STEP_BYTE_BUDGET;

    for _ in 0..MAX_DRIVER_STEPS {
        let outcome = importer
            .step(1, byte_budget)
            .expect("the bounded DNS decoder handles every message byte sequence");
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
                assert!(progress.records_processed - previous.records_processed <= 1);
                previous = progress;
                byte_budget = INITIAL_STEP_BYTE_BUDGET;
            }
            ImportStep::Ready(progress) => {
                assert_monotonic(previous, progress);
                assert!(importer.is_complete());
                assert_eq!(
                    importer
                        .step(1, INITIAL_STEP_BYTE_BUDGET)
                        .expect("a completed importer remains ready"),
                    ImportStep::Ready(progress)
                );
                let dataset = importer
                    .finish()
                    .expect("a ready DNS import finalizes into a valid dataset");
                assert_valid_dataset(&dataset);
                return;
            }
        }
    }

    panic!("bounded DNS importer did not reach a terminal result");
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = bounded_input(data) else {
        return;
    };
    let capture = wrapped_capture(&input);
    exercise_cancellation(&capture);
    exercise_to_terminal(capture);
});
