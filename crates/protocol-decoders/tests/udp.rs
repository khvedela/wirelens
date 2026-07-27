//! Synthetic UDP fixtures and hostile-length/checksum coverage.

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldValue, ImportLimits,
    ImportStep,
};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder,
};

const PACKET_OFFSET: u64 = 40;
const IPV4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const IPV4_DESTINATION: [u8; 4] = [198, 51, 100, 9];
const IPV6_SOURCE: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_DESTINATION: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const TEST_DESTINATION_PORT: u16 = 9;

fn legacy_capture(packet: &[u8]) -> Vec<u8> {
    let packet_length = u32::try_from(packet.len()).expect("synthetic packet length fits u32");
    let mut bytes = Vec::with_capacity(40 + packet.len());
    bytes.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend(2_u16.to_le_bytes());
    bytes.extend(4_u16.to_le_bytes());
    bytes.extend(0_i32.to_le_bytes());
    bytes.extend(0_u32.to_le_bytes());
    bytes.extend(65_535_u32.to_le_bytes());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(2_u32.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet);
    bytes
}

fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(12 + body.len()).expect("synthetic block length fits u32");
    assert_eq!(length % 4, 0);
    let mut bytes = Vec::with_capacity(length as usize);
    bytes.extend(block_type.to_le_bytes());
    bytes.extend(length.to_le_bytes());
    bytes.extend(body);
    bytes.extend(length.to_le_bytes());
    bytes
}

fn pcapng_capture_with_padding(packet: &[u8], padding: u8) -> Vec<u8> {
    let mut capture = Vec::new();
    let mut section = Vec::new();
    section.extend(0x1a2b_3c4d_u32.to_le_bytes());
    section.extend(1_u16.to_le_bytes());
    section.extend(0_u16.to_le_bytes());
    section.extend((-1_i64).to_le_bytes());
    capture.extend(block(0x0a0d_0d0a, &section));

    let mut interface = Vec::new();
    interface.extend(1_u16.to_le_bytes());
    interface.extend(0_u16.to_le_bytes());
    interface.extend(65_535_u32.to_le_bytes());
    capture.extend(block(1, &interface));

    let packet_length = u32::try_from(packet.len()).expect("synthetic packet length fits u32");
    let mut enhanced_packet = Vec::new();
    enhanced_packet.extend(0_u32.to_le_bytes());
    enhanced_packet.extend(0_u32.to_le_bytes());
    enhanced_packet.extend(123_u32.to_le_bytes());
    enhanced_packet.extend(packet_length.to_le_bytes());
    enhanced_packet.extend(packet_length.to_le_bytes());
    enhanced_packet.extend(packet);
    while enhanced_packet.len() % 4 != 0 {
        enhanced_packet.push(padding);
    }
    capture.extend(block(6, &enhanced_packet));
    capture
}

fn decode_capture(capture: Vec<u8>) -> CaptureDataset {
    let mut importer = CaptureImporter::new_with_decoder(
        capture.into_boxed_slice(),
        ImportLimits::default(),
        Box::new(LinkLayerDecoder::new()),
    )
    .expect("synthetic capture is valid");
    loop {
        match importer
            .step(64, 1024 * 1024)
            .expect("bounded synthetic import succeeds")
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
    importer.finish().expect("decoded dataset validates")
}

fn decode(packet: &[u8]) -> CaptureDataset {
    decode_capture(legacy_capture(packet))
}

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + payload.len());
    packet.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    packet.extend(ether_type.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv4(payload: &[u8], declared_payload_length: Option<usize>, flags_fragment: u16) -> Vec<u8> {
    let declared_payload_length = declared_payload_length.unwrap_or(payload.len());
    let total_length =
        u16::try_from(20 + declared_payload_length).expect("IPv4 fixture length fits u16");
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend([0x45, 0]);
    packet.extend(total_length.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(flags_fragment.to_be_bytes());
    packet.extend([64, 17]);
    packet.extend([0, 0]);
    packet.extend(IPV4_SOURCE);
    packet.extend(IPV4_DESTINATION);
    let checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv6(payload: &[u8], declared_payload_length: Option<usize>, next_header: u8) -> Vec<u8> {
    let payload_length = u16::try_from(declared_payload_length.unwrap_or(payload.len()))
        .expect("IPv6 fixture length fits u16");
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend([0x60, 0, 0, 0]);
    packet.extend(payload_length.to_be_bytes());
    packet.extend([next_header, 64]);
    packet.extend(IPV6_SOURCE);
    packet.extend(IPV6_DESTINATION);
    packet.extend(payload);
    packet
}

fn udp(payload: &[u8], declared_length: u16, checksum_value: u16) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend(53_000_u16.to_be_bytes());
    datagram.extend(TEST_DESTINATION_PORT.to_be_bytes());
    datagram.extend(declared_length.to_be_bytes());
    datagram.extend(checksum_value.to_be_bytes());
    datagram.extend(payload);
    datagram
}

fn checksummed_udp_v4(payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(8 + payload.len()).expect("UDP fixture length fits u16");
    let mut datagram = udp(payload, length, 0);
    let pseudo_protocol = [0, 17];
    let checksum_value = checksum(&[
        &IPV4_SOURCE,
        &IPV4_DESTINATION,
        &pseudo_protocol,
        &length.to_be_bytes(),
        &datagram,
    ]);
    datagram[6..8].copy_from_slice(&wire_checksum(checksum_value).to_be_bytes());
    datagram
}

fn checksummed_udp_v6(payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(8 + payload.len()).expect("UDP fixture length fits u16");
    let mut datagram = udp(payload, length, 0);
    let pseudo_length = u32::from(length).to_be_bytes();
    let pseudo_protocol = [0, 0, 0, 17];
    let checksum_value = checksum(&[
        &IPV6_SOURCE,
        &IPV6_DESTINATION,
        &pseudo_length,
        &pseudo_protocol,
        &datagram,
    ]);
    datagram[6..8].copy_from_slice(&wire_checksum(checksum_value).to_be_bytes());
    datagram
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

fn wire_checksum(value: u16) -> u16 {
    if value == 0 { u16::MAX } else { value }
}

fn fragment(next_header: u8, offset: u16, more_fragments: bool) -> [u8; 8] {
    let word = ((offset << 3) | u16::from(more_fragments)).to_be_bytes();
    [next_header, 0, word[0], word[1], 0x12, 0x34, 0x56, 0x78]
}

fn names(dataset: &CaptureDataset) -> Vec<&str> {
    dataset
        .layers()
        .iter()
        .map(|layer| dataset.string(layer.protocol).expect("valid protocol name"))
        .collect()
}

fn fields_named<'a>(
    dataset: &'a CaptureDataset,
    expected: &'a str,
) -> impl Iterator<Item = &'a packet_core::DecodedField> {
    dataset
        .fields()
        .iter()
        .filter(move |field| dataset.string(field.name) == Some(expected))
}

fn one_field<'a>(dataset: &'a CaptureDataset, expected: &'a str) -> &'a packet_core::DecodedField {
    let mut fields = fields_named(dataset, expected);
    let field = fields.next().expect("field exists");
    assert!(fields.next().is_none(), "field {expected} is unique");
    field
}

fn assert_relative_range(range: ByteRange, start: u64, length: u32) {
    assert_eq!(range.start(), PACKET_OFFSET + start);
    assert_eq!(range.length(), length);
}

fn assert_all_ranges_within_packet(dataset: &CaptureDataset) {
    let packet = dataset.packets()[0];
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
    for layer in dataset.layers() {
        assert!(layer.byte_range.start() >= packet.data.start());
        assert!(layer.byte_range.end() <= packet.data.end());
    }
    for field in dataset.fields() {
        assert!(field.byte_range.start() >= packet.data.start());
        assert!(field.byte_range.end() <= packet.data.end());
        if let FieldValue::Bytes(range) = field.value {
            assert_eq!(range, field.byte_range);
        }
    }
    for diagnostic in dataset.diagnostics() {
        if let Some(range) = diagnostic.byte_range {
            assert!(range.start() >= packet.data.start());
            assert!(range.end() <= packet.data.end());
        }
    }
}

fn diagnostic_code(dataset: &CaptureDataset) -> Option<DiagnosticCode> {
    assert!(dataset.diagnostics().len() <= 1);
    dataset
        .diagnostics()
        .first()
        .map(|diagnostic| diagnostic.code)
}

#[test]
fn decodes_ipv4_udp_and_limits_checksum_to_the_udp_length() {
    let datagram = checksummed_udp_v4(&[1, 2, 3]);
    let mut network_payload = datagram.clone();
    network_payload.extend([0xde, 0xad, 0xbe, 0xef]);
    let dataset = decode(&ethernet(0x0800, &ipv4(&network_payload, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "udp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[2].byte_range, 34, 8);
    assert_eq!(
        one_field(&dataset, "source_port").value,
        FieldValue::Unsigned(53_000)
    );
    assert_eq!(
        one_field(&dataset, "destination_port").value,
        FieldValue::Unsigned(u64::from(TEST_DESTINATION_PORT))
    );
    assert_eq!(
        one_field(&dataset, "length").value,
        FieldValue::Unsigned(11)
    );
    assert_relative_range(one_field(&dataset, "checksum").byte_range, 40, 2);
    assert_eq!(
        one_field(&dataset, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_relative_range(one_field(&dataset, "checksum_valid").byte_range, 40, 2);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn ipv4_zero_checksum_is_absent_metadata_without_a_false_warning() {
    let datagram = udp(&[1, 2, 3, 4], 12, 0);
    let dataset = decode(&ethernet(0x0800, &ipv4(&datagram, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "udp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "checksum_valid").count(), 0);
    assert_eq!(
        one_field(&dataset, "checksum").value,
        FieldValue::Unsigned(0)
    );
}

#[test]
fn validates_ipv6_udp_and_reports_zero_or_incorrect_checksums_cautiously() {
    let valid = checksummed_udp_v6(&[1, 2, 3, 4, 5]);
    let valid = decode(&ethernet(0x86dd, &ipv6(&valid, None, 17)));
    assert_eq!(names(&valid), ["ethernet", "ipv6", "udp"]);
    assert!(valid.diagnostics().is_empty());
    assert_eq!(
        one_field(&valid, "checksum_valid").value,
        FieldValue::Boolean(true)
    );

    let zero = udp(&[1, 2, 3, 4], 12, 0);
    let zero = decode(&ethernet(0x86dd, &ipv6(&zero, None, 17)));
    assert_eq!(
        diagnostic_code(&zero),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );
    assert_eq!(fields_named(&zero, "checksum_valid").count(), 0);

    let mut incorrect = checksummed_udp_v6(&[1, 2, 3, 4]);
    incorrect[7] ^= 1;
    let incorrect = decode(&ethernet(0x86dd, &ipv6(&incorrect, None, 17)));
    assert_eq!(
        diagnostic_code(&incorrect),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );
    assert_eq!(
        one_field(&incorrect, "checksum_valid").value,
        FieldValue::Boolean(false)
    );
}

#[test]
fn rejects_intrinsic_and_enclosing_length_contradictions() {
    let too_short = udp(&[], 7, 1);
    let too_short = decode(&ethernet(0x0800, &ipv4(&too_short, None, 0)));
    assert_eq!(
        diagnostic_code(&too_short),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(too_short.diagnostics()[0].byte_range.unwrap(), 38, 2);
    assert_eq!(fields_named(&too_short, "checksum_valid").count(), 0);

    let exceeds_network = udp(&[], 20, 1);
    let exceeds_network = decode(&ethernet(0x0800, &ipv4(&exceeds_network, None, 0)));
    assert_eq!(
        diagnostic_code(&exceeds_network),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(exceeds_network.diagnostics()[0].byte_range.unwrap(), 38, 2);
    assert_eq!(fields_named(&exceeds_network, "checksum_valid").count(), 0);
}

#[test]
fn distinguishes_a_truncated_datagram_from_an_invalid_declared_length() {
    let truncated = udp(&[1, 2], 12, 1);
    let dataset = decode(&ethernet(0x0800, &ipv4(&truncated, Some(12), 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "udp"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(fields_named(&dataset, "checksum_valid").count(), 0);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn every_udp_header_cutoff_is_bounded_and_truncated() {
    let full = udp(&[], 8, 1);
    for cutoff in 0..8 {
        let dataset = decode(&ethernet(0x0800, &ipv4(&full[..cutoff], Some(8), 0)));
        assert_eq!(names(&dataset), ["ethernet", "ipv4", "udp"]);
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::TRUNCATED_PROTOCOL),
            "cutoff {cutoff}"
        );
        assert_relative_range(
            dataset.layers()[2].byte_range,
            34,
            u32::try_from(cutoff).expect("cutoff fits u32"),
        );
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn fully_captured_short_datagrams_are_malformed_but_first_fragments_are_partial() {
    let full = udp(&[], 8, 1);
    let malformed = decode(&ethernet(0x0800, &ipv4(&full[..7], None, 0)));
    assert_eq!(
        diagnostic_code(&malformed),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(malformed.layers()[2].byte_range, 34, 7);

    let first_fragment = decode(&ethernet(0x0800, &ipv4(&full[..0], None, 0x2000)));
    assert!(first_fragment.diagnostics().is_empty());
    assert_relative_range(first_fragment.layers()[2].byte_range, 34, 0);
    assert_all_ranges_within_packet(&malformed);
    assert_all_ranges_within_packet(&first_fragment);
}

#[test]
fn first_fragments_expose_only_the_udp_header_without_whole_datagram_claims() {
    let fragment_payload = udp(&[0; 8], 40, 1);
    let ipv4_fragment = decode(&ethernet(0x0800, &ipv4(&fragment_payload, None, 0x2000)));
    assert_eq!(names(&ipv4_fragment), ["ethernet", "ipv4", "udp"]);
    assert!(ipv4_fragment.diagnostics().is_empty());
    assert_eq!(fields_named(&ipv4_fragment, "checksum_valid").count(), 0);

    let mut ipv6_fragment_payload = Vec::from(fragment(17, 0, true));
    // A zero checksum is visible in this first fragment but cannot support a
    // whole-datagram checksum conclusion before reassembly.
    ipv6_fragment_payload.extend(udp(&[0; 8], 40, 0));
    let ipv6_fragment = decode(&ethernet(0x86dd, &ipv6(&ipv6_fragment_payload, None, 44)));
    assert_eq!(
        names(&ipv6_fragment),
        ["ethernet", "ipv6", "ipv6_fragment", "udp"]
    );
    assert!(ipv6_fragment.diagnostics().is_empty());
    assert_eq!(fields_named(&ipv6_fragment, "checksum_valid").count(), 0);
}

#[test]
fn an_atomic_ipv6_fragment_has_a_complete_checksum_domain() {
    let datagram = checksummed_udp_v6(&[1, 2, 3, 4]);
    let mut payload = Vec::from(fragment(17, 0, false));
    payload.extend(datagram);
    let dataset = decode(&ethernet(0x86dd, &ipv6(&payload, None, 44)));

    assert_eq!(
        names(&dataset),
        ["ethernet", "ipv6", "ipv6_fragment", "udp"]
    );
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(
        one_field(&dataset, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
}

#[test]
fn pcapng_alignment_sentinels_never_enter_udp_evidence() {
    let datagram = checksummed_udp_v4(&[1]);
    let packet = ethernet(0x0800, &ipv4(&datagram, None, 0));
    assert_ne!(packet.len() % 4, 0);
    let dataset = decode_capture(pcapng_capture_with_padding(&packet, 0xee));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "udp"]);
    assert!(dataset.diagnostics().is_empty());
    let packet_range = dataset.packets()[0].data;
    assert_eq!(packet_range.length() as usize, packet.len());
    assert!(
        dataset
            .fields()
            .iter()
            .all(|field| field.byte_range.end() <= packet_range.end())
    );
    assert_eq!(
        one_field(&dataset, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
}
