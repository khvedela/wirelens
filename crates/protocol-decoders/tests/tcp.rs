//! Synthetic TCP fixtures and hostile length, option, fragment, and checksum coverage.

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldValue, ImportLimits,
    ImportStep,
};
use proptest::prelude::*;
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder,
};

const PACKET_OFFSET: u64 = 40;
const IPV4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const IPV4_DESTINATION: [u8; 4] = [198, 51, 100, 9];
const IPV6_SOURCE: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_DESTINATION: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const IPV4_TCP_OFFSET: u64 = 34;

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

fn decode(packet: &[u8]) -> CaptureDataset {
    let mut importer = CaptureImporter::new_with_decoder(
        legacy_capture(packet).into_boxed_slice(),
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

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + payload.len());
    packet.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    packet.extend(ether_type.to_be_bytes());
    packet.extend(payload);
    packet
}

fn vlan(inner_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(4 + payload.len());
    tagged.extend(4095_u16.to_be_bytes());
    tagged.extend(inner_type.to_be_bytes());
    tagged.extend(payload);
    ethernet(0x8100, &tagged)
}

fn ipv4(
    options: &[u8],
    payload: &[u8],
    declared_payload_length: Option<usize>,
    flags_fragment: u16,
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    assert!(options.len() <= 40);
    let header_length = 20 + options.len();
    let header_words = u8::try_from(header_length / 4).expect("IPv4 IHL fits");
    let declared_payload_length = declared_payload_length.unwrap_or(payload.len());
    let total_length = u16::try_from(header_length + declared_payload_length)
        .expect("IPv4 fixture length fits u16");
    let mut packet = Vec::with_capacity(header_length + payload.len());
    packet.extend([0x40 | header_words, 0]);
    packet.extend(total_length.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(flags_fragment.to_be_bytes());
    packet.extend([64, 6]);
    packet.extend([0, 0]);
    packet.extend(IPV4_SOURCE);
    packet.extend(IPV4_DESTINATION);
    packet.extend(options);
    let header_checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
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

fn tcp(options: &[u8], payload: &[u8], flags: u8, reserved: u8) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    assert!(options.len() <= 40);
    let header_length = 20 + options.len();
    let data_offset = u8::try_from(header_length / 4).expect("TCP data offset fits");
    let mut segment = Vec::with_capacity(header_length + payload.len());
    segment.extend(49_152_u16.to_be_bytes());
    segment.extend(443_u16.to_be_bytes());
    segment.extend(0x0102_0304_u32.to_be_bytes());
    segment.extend(0xa0b0_c0d0_u32.to_be_bytes());
    segment.push((data_offset << 4) | (reserved & 0x0f));
    segment.push(flags);
    segment.extend(0x4567_u16.to_be_bytes());
    segment.extend([0, 0]);
    segment.extend(0x3344_u16.to_be_bytes());
    segment.extend(options);
    segment.extend(payload);
    segment
}

fn checksummed_tcp_v4(options: &[u8], payload: &[u8], flags: u8, reserved: u8) -> Vec<u8> {
    let mut segment = tcp(options, payload, flags, reserved);
    set_tcp_checksum_v4(&mut segment);
    segment
}

fn set_tcp_checksum_v4(segment: &mut [u8]) {
    segment[16..18].copy_from_slice(&[0, 0]);
    let protocol = [0, 6];
    let length = u16::try_from(segment.len())
        .expect("TCP fixture length fits u16")
        .to_be_bytes();
    let value = checksum(&[&IPV4_SOURCE, &IPV4_DESTINATION, &protocol, &length, segment]);
    segment[16..18].copy_from_slice(&wire_checksum(value).to_be_bytes());
}

fn checksummed_tcp_v6(options: &[u8], payload: &[u8], flags: u8) -> Vec<u8> {
    let mut segment = tcp(options, payload, flags, 0);
    let length = u32::try_from(segment.len())
        .expect("TCP fixture length fits u32")
        .to_be_bytes();
    let protocol = [0, 0, 0, 6];
    let value = checksum(&[
        &IPV6_SOURCE,
        &IPV6_DESTINATION,
        &length,
        &protocol,
        &segment,
    ]);
    segment[16..18].copy_from_slice(&wire_checksum(value).to_be_bytes());
    segment
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

fn layer_child<'a>(
    dataset: &'a CaptureDataset,
    layer_index: usize,
    expected: &str,
) -> Option<&'a packet_core::DecodedField> {
    let root = dataset.layers()[layer_index]
        .root_field
        .expect("decoded layer has a root");
    let children = dataset.fields()[root.0 as usize].children;
    let children = &dataset.field_children()[children.start() as usize..children.end() as usize];
    let mut matches = children.iter().filter_map(|id| {
        let field = &dataset.fields()[id.0 as usize];
        (dataset.string(field.name) == Some(expected)).then_some(field)
    });
    let field = matches.next();
    assert!(matches.next().is_none(), "layer child {expected} is unique");
    field
}

fn required_layer_child<'a>(
    dataset: &'a CaptureDataset,
    layer_index: usize,
    expected: &str,
) -> &'a packet_core::DecodedField {
    layer_child(dataset, layer_index, expected).expect("layer child exists")
}

fn assert_relative_range(range: ByteRange, start: u64, length: u32) {
    assert_eq!(range.start(), PACKET_OFFSET + start);
    assert_eq!(range.length(), length);
}

fn diagnostic_code(dataset: &CaptureDataset) -> Option<DiagnosticCode> {
    assert!(dataset.diagnostics().len() <= 1);
    dataset
        .diagnostics()
        .first()
        .map(|diagnostic| diagnostic.code)
}

fn assert_all_ranges_within_packet(dataset: &CaptureDataset) {
    let packet = dataset.packets()[0];
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
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
}

#[test]
fn decodes_fixed_header_flags_and_ipv4_checksum_with_exact_ranges() {
    let segment = checksummed_tcp_v4(&[], &[0xde, 0xad, 0xbe, 0xef], 0xab, 0x0a);
    let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[2].byte_range, IPV4_TCP_OFFSET, 20);
    for (name, value, offset, length) in [
        ("source_port", 49_152, 0, 2),
        ("destination_port", 443, 2, 2),
        ("sequence_number", 0x0102_0304, 4, 4),
        ("acknowledgment_number", 0xa0b0_c0d0, 8, 4),
        ("data_offset_words", 5, 12, 1),
        ("header_length", 20, 12, 1),
        ("reserved", 10, 12, 1),
        ("flags", 0xab, 13, 1),
        ("window", 0x4567, 14, 2),
        ("urgent_pointer", 0x3344, 18, 2),
    ] {
        let field = required_layer_child(&dataset, 2, name);
        assert_eq!(field.value, FieldValue::Unsigned(value), "{name}");
        assert_relative_range(field.byte_range, IPV4_TCP_OFFSET + offset, length);
    }
    for (name, expected) in [
        ("cwr", true),
        ("ece", false),
        ("urg", true),
        ("ack", false),
        ("psh", true),
        ("rst", false),
        ("syn", true),
        ("fin", true),
    ] {
        let field = required_layer_child(&dataset, 2, name);
        assert_eq!(field.value, FieldValue::Boolean(expected), "{name}");
        assert_relative_range(field.byte_range, IPV4_TCP_OFFSET + 13, 1);
    }
    assert_relative_range(
        required_layer_child(&dataset, 2, "checksum").byte_range,
        IPV4_TCP_OFFSET + 16,
        2,
    );
    assert_eq!(
        required_layer_child(&dataset, 2, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn decodes_common_options_in_wire_order_and_bounds_eol_padding() {
    let mut options = vec![
        2, 4, 0x05, 0xb4, // MSS
        1,    // NOP
        3, 3, 7, // Window scale
        4, 2, // SACK permitted
        5, 10, 0, 0, 0, 10, 0, 0, 0, 20, // One SACK block
        8, 10, 1, 2, 3, 4, 5, 6, 7, 8, // Timestamps
        30, 4, 0xaa, 0xbb, // Unknown but structurally valid
        0,    // EOL
    ];
    options.extend([0; 5]);
    let segment = checksummed_tcp_v4(&options, &[], 0x12, 0);
    let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[2].byte_range, IPV4_TCP_OFFSET, 60);
    assert_relative_range(
        required_layer_child(&dataset, 2, "tcp_options").byte_range,
        IPV4_TCP_OFFSET + 20,
        40,
    );
    assert_eq!(
        fields_named(&dataset, "maximum_segment_size_option").count(),
        1
    );
    assert_eq!(
        one_field(&dataset, "maximum_segment_size").value,
        FieldValue::Unsigned(1460)
    );
    assert_eq!(fields_named(&dataset, "no_operation").count(), 1);
    assert_eq!(fields_named(&dataset, "window_scale_option").count(), 1);
    assert_eq!(
        one_field(&dataset, "window_scale_shift").value,
        FieldValue::Unsigned(7)
    );
    assert_eq!(fields_named(&dataset, "sack_permitted_option").count(), 1);
    assert_eq!(fields_named(&dataset, "sack_option").count(), 1);
    assert_eq!(fields_named(&dataset, "sack_block").count(), 1);
    assert_eq!(
        one_field(&dataset, "left_edge").value,
        FieldValue::Unsigned(10)
    );
    assert_eq!(
        one_field(&dataset, "right_edge").value,
        FieldValue::Unsigned(20)
    );
    assert_eq!(
        one_field(&dataset, "timestamp_value").value,
        FieldValue::Unsigned(0x0102_0304)
    );
    assert_eq!(
        one_field(&dataset, "timestamp_echo_reply").value,
        FieldValue::Unsigned(0x0506_0708)
    );
    assert_eq!(fields_named(&dataset, "tcp_option").count(), 1);
    assert_relative_range(
        one_field(&dataset, "data").byte_range,
        IPV4_TCP_OFFSET + 52,
        2,
    );
    assert_relative_range(
        one_field(&dataset, "padding").byte_range,
        IPV4_TCP_OFFSET + 55,
        5,
    );
    assert_eq!(
        required_layer_child(&dataset, 2, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn rejects_invalid_option_lengths_and_nonzero_eol_padding() {
    for (options, evidence_offset, evidence_length) in [
        (vec![2, 3, 0, 1], 21, 1),
        (vec![30, 0, 0, 0], 20, 2),
        (vec![30, 5, 0, 0], 20, 4),
        (vec![1, 1, 1, 30], 23, 1),
        (vec![0, 0, 1, 0], 21, 3),
    ] {
        let segment = checksummed_tcp_v4(&options, &[], 0x10, 0);
        let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, None, 0)));
        assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::MALFORMED_PROTOCOL)
        );
        assert_relative_range(
            dataset.diagnostics()[0]
                .byte_range
                .expect("TCP option diagnostic has evidence"),
            IPV4_TCP_OFFSET + evidence_offset,
            evidence_length,
        );
        assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn a_final_option_kind_never_borrows_its_length_from_application_payload() {
    let options = [1, 1, 1, 30];
    let segment = checksummed_tcp_v4(&options, &[4, 0xaa, 0xbb, 0xcc], 0x10, 0);
    let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        dataset.diagnostics()[0]
            .byte_range
            .expect("final option kind is exact evidence"),
        IPV4_TCP_OFFSET + 23,
        1,
    );
    assert_eq!(fields_named(&dataset, "option_kind").count(), 1);
    assert_eq!(fields_named(&dataset, "option_length").count(), 0);
    assert_eq!(fields_named(&dataset, "data").count(), 0);
    assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn distinguishes_invalid_offsets_enclosing_lengths_and_capture_truncation() {
    let mut short_offset = tcp(&[], &[], 0x10, 0);
    short_offset[12] = 0x40;
    set_tcp_checksum_v4(&mut short_offset);
    let short_offset = decode(&ethernet(0x0800, &ipv4(&[], &short_offset, None, 0)));
    assert_eq!(
        diagnostic_code(&short_offset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        short_offset.diagnostics()[0].byte_range.expect("evidence"),
        IPV4_TCP_OFFSET + 12,
        1,
    );

    let full = checksummed_tcp_v4(&[], &[], 0x10, 0);
    let short_enclosing = decode(&ethernet(0x0800, &ipv4(&[], &full, Some(16), 0)));
    assert_eq!(
        diagnostic_code(&short_enclosing),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(short_enclosing.layers()[2].byte_range, IPV4_TCP_OFFSET, 16);
    assert!(layer_child(&short_enclosing, 2, "checksum").is_none());
    assert!(layer_child(&short_enclosing, 2, "urgent_pointer").is_none());

    let mut offset_exceeds_segment = tcp(&[], &[], 0x10, 0);
    offset_exceeds_segment[12] = 0xf0;
    set_tcp_checksum_v4(&mut offset_exceeds_segment);
    let offset_exceeds_segment = decode(&ethernet(
        0x0800,
        &ipv4(&[], &offset_exceeds_segment, None, 0),
    ));
    assert_eq!(
        diagnostic_code(&offset_exceeds_segment),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        offset_exceeds_segment.layers()[2].byte_range,
        IPV4_TCP_OFFSET,
        20,
    );

    let truncated = decode(&ethernet(0x0800, &ipv4(&[], &full[..12], Some(20), 0)));
    assert_eq!(
        diagnostic_code(&truncated),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_relative_range(truncated.layers()[2].byte_range, IPV4_TCP_OFFSET, 12);
    assert_all_ranges_within_packet(&short_offset);
    assert_all_ranges_within_packet(&short_enclosing);
    assert_all_ranges_within_packet(&offset_exceeds_segment);
    assert_all_ranges_within_packet(&truncated);
}

#[test]
fn first_fragments_never_read_past_the_network_payload_or_claim_truncation() {
    let mut segment = tcp(&[], &[], 0x02, 0);
    segment[16..20].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, Some(16), 0x2000)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[2].byte_range, IPV4_TCP_OFFSET, 16);
    assert!(layer_child(&dataset, 2, "checksum").is_none());
    assert!(layer_child(&dataset, 2, "urgent_pointer").is_none());
    assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
    let network_payload_end = PACKET_OFFSET + IPV4_TCP_OFFSET + 16;
    assert!(
        dataset
            .fields()
            .iter()
            .filter(|field| field.byte_range.start() >= PACKET_OFFSET + IPV4_TCP_OFFSET)
            .all(|field| field.byte_range.end() <= network_payload_end)
    );

    let mut split_header = tcp(&[1; 40], &[], 0x02, 0);
    split_header.truncate(24);
    let split_header = decode(&ethernet(0x0800, &ipv4(&[], &split_header, None, 0x2000)));
    assert_eq!(names(&split_header), ["ethernet", "ipv4", "tcp"]);
    assert!(split_header.diagnostics().is_empty());
    assert_relative_range(split_header.layers()[2].byte_range, IPV4_TCP_OFFSET, 24);
    assert!(layer_child(&split_header, 2, "tcp_options").is_none());
    assert_all_ranges_within_packet(&dataset);
    assert_all_ranges_within_packet(&split_header);
}

#[test]
fn non_initial_fragments_do_not_dispatch_tcp() {
    let packet = ethernet(0x0800, &ipv4(&[], &[0; 8], None, 0x2001));
    let dataset = decode(&packet);

    assert_eq!(names(&dataset), ["ethernet", "ipv4"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "source_port").count(), 0);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn validates_ipv6_and_reports_invalid_checksums_with_an_offload_caveat() {
    let valid_segment = checksummed_tcp_v6(&[], &[1, 2, 3], 0x18);
    let valid = decode(&ethernet(0x86dd, &ipv6(&valid_segment, None, 6)));
    assert_eq!(names(&valid), ["ethernet", "ipv6", "tcp"]);
    assert!(valid.diagnostics().is_empty());
    assert_eq!(
        required_layer_child(&valid, 2, "checksum_valid").value,
        FieldValue::Boolean(true)
    );

    let mut damaged_segment = checksummed_tcp_v4(&[], &[1, 2, 3], 0x18, 0);
    damaged_segment[17] ^= 1;
    let damaged = decode(&ethernet(0x0800, &ipv4(&[], &damaged_segment, None, 0)));
    assert_eq!(
        diagnostic_code(&damaged),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );
    assert_eq!(
        required_layer_child(&damaged, 2, "checksum_valid").value,
        FieldValue::Boolean(false)
    );
    let message = damaged
        .string(damaged.diagnostics()[0].message)
        .expect("diagnostic message is interned");
    assert!(message.contains("offload"));
    assert!(!message.contains("192.0.2.1"));
    assert_all_ranges_within_packet(&valid);
    assert_all_ranges_within_packet(&damaged);
}

#[test]
fn traversed_ipv6_routing_headers_suppress_ambiguous_checksum_metadata() {
    let segment = checksummed_tcp_v6(&[], &[1, 2, 3, 4], 0x18);
    let mut payload = vec![6, 0, 0, 0, 0, 0, 0, 0];
    payload.extend(segment);
    let dataset = decode(&ethernet(0x86dd, &ipv6(&payload, None, 43)));

    assert_eq!(names(&dataset), ["ethernet", "ipv6", "ipv6_routing", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert!(layer_child(&dataset, 3, "checksum_valid").is_none());
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn ipv4_source_route_options_suppress_ambiguous_checksum_metadata() {
    let segment = checksummed_tcp_v4(&[], &[1, 2, 3, 4], 0x18, 0);
    let dataset = decode(&ethernet(0x0800, &ipv4(&[131, 3, 4, 0], &segment, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn exact_global_ceilings_cover_vlan_ipv4_and_tcp_maximum_options() {
    let mut ipv4_options = Vec::with_capacity(40);
    let mut tcp_options = Vec::with_capacity(40);
    for _ in 0..20 {
        ipv4_options.extend([0x1e, 2]);
        tcp_options.extend([30, 2]);
    }
    let segment = checksummed_tcp_v4(&tcp_options, &[], 0x10, 0);
    let dataset = decode(&vlan(0x0800, &ipv4(&ipv4_options, &segment, None, 0)));

    assert_eq!(names(&dataset), ["ethernet", "vlan", "ipv4", "tcp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(dataset.layers().len(), 4);
    assert_eq!(dataset.fields().len(), 173);
    assert_eq!(dataset.field_children().len(), 169);
    assert_eq!(fields_named(&dataset, "tcp_option").count(), 20);
    assert_eq!(fields_named(&dataset, "option_kind").count(), 20);
    assert_eq!(fields_named(&dataset, "option_length").count(), 40);
    assert_eq!(
        required_layer_child(&dataset, 3, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_all_ranges_within_packet(&dataset);
}

proptest! {
    #[test]
    fn arbitrary_maximum_tcp_options_never_escape_the_network_payload(options in any::<[u8; 40]>()) {
        let segment = checksummed_tcp_v4(&options, &[], 0x10, 0);
        let dataset = decode(&ethernet(0x0800, &ipv4(&[], &segment, None, 0)));
        prop_assert_eq!(names(&dataset), ["ethernet", "ipv4", "tcp"]);
        prop_assert!(dataset.diagnostics().len() <= 1);
        assert_all_ranges_within_packet(&dataset);
    }
}
