//! Synthetic ICMP and `ICMPv6` fixtures with hostile boundary coverage.

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldValue, ImportLimits,
    ImportStep,
};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder,
};

const PACKET_OFFSET: u64 = 40;
const IPV4_ICMP_OFFSET: u64 = 14 + 20;
const IPV6_ICMP_OFFSET: u64 = 14 + 40;
const IPV4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const IPV4_DESTINATION: [u8; 4] = [198, 51, 100, 9];
const IPV6_SOURCE: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_DESTINATION: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

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

fn ipv4(payload: &[u8], declared_payload_length: usize, flags_fragment: u16) -> Vec<u8> {
    let total_length = u16::try_from(20 + declared_payload_length).expect("IPv4 length fits u16");
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend([0x45, 0]);
    packet.extend(total_length.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(flags_fragment.to_be_bytes());
    packet.extend([64, 1]);
    packet.extend([0, 0]);
    packet.extend(IPV4_SOURCE);
    packet.extend(IPV4_DESTINATION);
    let checksum = checksum_value(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv6(next_header: u8, payload: &[u8], declared_payload_length: usize) -> Vec<u8> {
    let declared_payload_length =
        u16::try_from(declared_payload_length).expect("IPv6 payload length fits u16");
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend(0x6000_0000_u32.to_be_bytes());
    packet.extend(declared_payload_length.to_be_bytes());
    packet.extend([next_header, 64]);
    packet.extend(IPV6_SOURCE);
    packet.extend(IPV6_DESTINATION);
    packet.extend(payload);
    packet
}

fn fragment(next_header: u8, offset: u16, more_fragments: bool) -> [u8; 8] {
    let word = ((offset << 3) | u16::from(more_fragments)).to_be_bytes();
    [next_header, 0, word[0], word[1], 0x12, 0x34, 0x56, 0x78]
}

fn checksum_value(bytes: &[u8]) -> u16 {
    let mut sum = 0_u64;
    for pair in bytes.chunks_exact(2) {
        sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
        sum += u64::from(last) << 8;
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

fn icmpv4(message_type: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.extend([message_type, code, 0, 0]);
    message.extend(body);
    let checksum = checksum_value(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn icmpv6(message_type: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.extend([message_type, code, 0, 0]);
    message.extend(body);
    let mut checksum_input = Vec::with_capacity(40 + message.len());
    checksum_input.extend(IPV6_SOURCE);
    checksum_input.extend(IPV6_DESTINATION);
    checksum_input.extend(
        u32::try_from(message.len())
            .expect("message length fits u32")
            .to_be_bytes(),
    );
    checksum_input.extend([0, 0, 0, 58]);
    checksum_input.extend(&message);
    let checksum = checksum_value(&checksum_input);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn names(dataset: &CaptureDataset) -> Vec<&str> {
    dataset
        .layers()
        .iter()
        .map(|layer| dataset.string(layer.protocol).expect("valid protocol name"))
        .collect()
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

fn assert_ranges_within_icmp_layer(dataset: &CaptureDataset, layer_index: usize) {
    let layer = dataset.layers()[layer_index];
    let root = layer.root_field.expect("ICMP layer has a root");
    assert_eq!(
        dataset.fields()[root.0 as usize].byte_range,
        layer.byte_range
    );
    let children = dataset.fields()[root.0 as usize].children;
    for child in &dataset.field_children()[children.start() as usize..children.end() as usize] {
        let field = dataset.fields()[child.0 as usize];
        assert!(field.byte_range.start() >= layer.byte_range.start());
        assert!(field.byte_range.end() <= layer.byte_range.end());
        if let FieldValue::Bytes(range) = field.value {
            assert_eq!(range, field.byte_range);
        }
    }
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
}

#[test]
fn decodes_icmpv4_echo_with_exact_ranges_and_checksum() {
    let message = icmpv4(8, 0, &[0x12, 0x34, 0x56, 0x78]);
    let dataset = decode(&ethernet(0x0800, &ipv4(&message, message.len(), 0)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4", "icmp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[2].byte_range, IPV4_ICMP_OFFSET, 8);
    assert_eq!(
        required_layer_child(&dataset, 2, "type").value,
        FieldValue::Unsigned(8)
    );
    assert_eq!(
        required_layer_child(&dataset, 2, "identifier").value,
        FieldValue::Unsigned(0x1234)
    );
    assert_eq!(
        required_layer_child(&dataset, 2, "sequence_number").value,
        FieldValue::Unsigned(0x5678)
    );
    assert_eq!(
        required_layer_child(&dataset, 2, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_relative_range(
        required_layer_child(&dataset, 2, "identifier").byte_range,
        IPV4_ICMP_OFFSET + 4,
        2,
    );
    assert_relative_range(
        required_layer_child(&dataset, 2, "checksum_valid").byte_range,
        IPV4_ICMP_OFFSET,
        8,
    );
    assert_ranges_within_icmp_layer(&dataset, 2);
}

#[test]
fn decodes_icmpv4_destination_and_parameter_problem_bodies_without_recursion() {
    let mut unreachable = icmpv4(3, 1, &[0, 0, 0, 0]);
    unreachable.extend([0x45; 20]);
    unreachable[2..4].copy_from_slice(&[0, 0]);
    let checksum = checksum_value(&unreachable);
    unreachable[2..4].copy_from_slice(&checksum.to_be_bytes());
    let dataset = decode(&ethernet(0x0800, &ipv4(&unreachable, unreachable.len(), 0)));
    assert_eq!(names(&dataset), ["ethernet", "ipv4", "icmp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(
        required_layer_child(&dataset, 2, "rest_of_header").byte_range,
        IPV4_ICMP_OFFSET + 4,
        4,
    );

    let problem = icmpv4(12, 0, &[5, 0, 0, 0]);
    let dataset = decode(&ethernet(0x0800, &ipv4(&problem, problem.len(), 0)));
    assert_eq!(
        required_layer_child(&dataset, 2, "pointer").value,
        FieldValue::Unsigned(5)
    );
    assert_relative_range(
        required_layer_child(&dataset, 2, "pointer").byte_range,
        IPV4_ICMP_OFFSET + 4,
        1,
    );

    let exceeded = icmpv4(11, 0, &[0, 0, 0, 0]);
    let dataset = decode(&ethernet(0x0800, &ipv4(&exceeded, exceeded.len(), 0)));
    assert_relative_range(
        required_layer_child(&dataset, 2, "rest_of_header").byte_range,
        IPV4_ICMP_OFFSET + 4,
        4,
    );
}

#[test]
fn decodes_icmpv6_echo_mtu_destination_and_parameter_problem_bodies() {
    for (message, field, expected) in [
        (
            icmpv6(128, 0, &[0x12, 0x34, 0x56, 0x78]),
            "identifier",
            FieldValue::Unsigned(0x1234),
        ),
        (
            icmpv6(2, 0, &1280_u32.to_be_bytes()),
            "mtu",
            FieldValue::Unsigned(1280),
        ),
        (
            icmpv6(4, 0, &0x0102_0304_u32.to_be_bytes()),
            "pointer",
            FieldValue::Unsigned(0x0102_0304),
        ),
        (
            icmpv6(1, 4, &[0xde, 0xad, 0xbe, 0xef]),
            "rest_of_header",
            FieldValue::Bytes(
                ByteRange::new(PACKET_OFFSET + IPV6_ICMP_OFFSET + 4, 4).expect("range"),
            ),
        ),
        (
            icmpv6(3, 0, &[0, 0, 0, 0]),
            "rest_of_header",
            FieldValue::Bytes(
                ByteRange::new(PACKET_OFFSET + IPV6_ICMP_OFFSET + 4, 4).expect("range"),
            ),
        ),
    ] {
        let dataset = decode(&ethernet(0x86dd, &ipv6(58, &message, message.len())));
        assert_eq!(names(&dataset), ["ethernet", "ipv6", "icmpv6"]);
        assert!(dataset.diagnostics().is_empty());
        assert_eq!(required_layer_child(&dataset, 2, field).value, expected);
        assert_eq!(
            required_layer_child(&dataset, 2, "checksum_valid").value,
            FieldValue::Boolean(true)
        );
        assert_ranges_within_icmp_layer(&dataset, 2);
    }
}

#[test]
fn invalid_complete_checksums_are_metadata_and_one_bounded_warning() {
    let mut v4 = icmpv4(8, 0, &[0, 1, 0, 2]);
    v4[7] ^= 1;
    let v4 = decode(&ethernet(0x0800, &ipv4(&v4, v4.len(), 0)));
    assert_eq!(
        required_layer_child(&v4, 2, "checksum_valid").value,
        FieldValue::Boolean(false)
    );
    assert_eq!(
        diagnostic_code(&v4),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );

    let mut v6 = icmpv6(128, 0, &[0, 1, 0, 2]);
    v6[7] ^= 1;
    let v6 = decode(&ethernet(0x86dd, &ipv6(58, &v6, v6.len())));
    assert_eq!(
        required_layer_child(&v6, 2, "checksum_valid").value,
        FieldValue::Boolean(false)
    );
    assert_eq!(
        diagnostic_code(&v6),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );
}

#[test]
fn every_common_header_cutoff_is_truncated_and_range_bounded() {
    let v4 = icmpv4(8, 0, &[0x12, 0x34, 0x56, 0x78]);
    let v6 = icmpv6(128, 0, &[0x12, 0x34, 0x56, 0x78]);
    for captured in 0..8 {
        let dataset = decode(&ethernet(0x0800, &ipv4(&v4[..captured], 8, 0)));
        assert_eq!(names(&dataset), ["ethernet", "ipv4", "icmp"]);
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_relative_range(
            dataset.layers()[2].byte_range,
            IPV4_ICMP_OFFSET,
            u32::try_from(captured).expect("cutoff fits u32"),
        );
        assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
        assert_ranges_within_icmp_layer(&dataset, 2);

        let dataset = decode(&ethernet(0x86dd, &ipv6(58, &v6[..captured], 8)));
        assert_eq!(names(&dataset), ["ethernet", "ipv6", "icmpv6"]);
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_relative_range(
            dataset.layers()[2].byte_range,
            IPV6_ICMP_OFFSET,
            u32::try_from(captured).expect("cutoff fits u32"),
        );
        assert!(layer_child(&dataset, 2, "checksum_valid").is_none());
        assert_ranges_within_icmp_layer(&dataset, 2);
    }
}

#[test]
fn known_short_body_is_malformed_but_unknown_base_header_is_valid() {
    let echo_base = icmpv4(8, 0, &[]);
    let malformed = decode(&ethernet(0x0800, &ipv4(&echo_base, echo_base.len(), 0)));
    assert_eq!(
        diagnostic_code(&malformed),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert!(layer_child(&malformed, 2, "checksum_valid").is_none());

    let short_time_exceeded = icmpv4(11, 0, &[]);
    let short_time_exceeded = decode(&ethernet(
        0x0800,
        &ipv4(&short_time_exceeded, short_time_exceeded.len(), 0),
    ));
    assert_eq!(
        diagnostic_code(&short_time_exceeded),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );

    let short_time_exceeded = icmpv6(3, 0, &[]);
    let short_time_exceeded = decode(&ethernet(
        0x86dd,
        &ipv6(58, &short_time_exceeded, short_time_exceeded.len()),
    ));
    assert_eq!(
        diagnostic_code(&short_time_exceeded),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );

    let unknown = icmpv4(250, 199, &[]);
    let valid = decode(&ethernet(0x0800, &ipv4(&unknown, unknown.len(), 0)));
    assert!(valid.diagnostics().is_empty());
    assert_eq!(
        required_layer_child(&valid, 2, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
}

#[test]
fn fragments_gate_checksum_metadata_and_non_initial_dispatch() {
    let v4_message = icmpv4(8, 0, &[0x12, 0x34, 0x56, 0x78]);
    let first_v4 = decode(&ethernet(
        0x0800,
        &ipv4(&v4_message, v4_message.len(), 0x2000),
    ));
    assert_eq!(names(&first_v4), ["ethernet", "ipv4", "icmp"]);
    assert!(layer_child(&first_v4, 2, "checksum_valid").is_none());
    assert!(first_v4.diagnostics().is_empty());

    let v6_message = icmpv6(128, 0, &[0x12, 0x34, 0x56, 0x78]);
    let mut first_payload = Vec::from(fragment(58, 0, true));
    first_payload.extend(&v6_message);
    let first_v6 = decode(&ethernet(
        0x86dd,
        &ipv6(44, &first_payload, first_payload.len()),
    ));
    assert_eq!(
        names(&first_v6),
        ["ethernet", "ipv6", "ipv6_fragment", "icmpv6"]
    );
    assert!(layer_child(&first_v6, 3, "checksum_valid").is_none());

    let mut atomic_payload = Vec::from(fragment(58, 0, false));
    atomic_payload.extend(&v6_message);
    let atomic = decode(&ethernet(
        0x86dd,
        &ipv6(44, &atomic_payload, atomic_payload.len()),
    ));
    assert_eq!(
        required_layer_child(&atomic, 3, "checksum_valid").value,
        FieldValue::Boolean(true)
    );

    let mut non_initial_payload = Vec::from(fragment(58, 1, true));
    non_initial_payload.extend(&v6_message);
    let non_initial = decode(&ethernet(
        0x86dd,
        &ipv6(44, &non_initial_payload, non_initial_payload.len()),
    ));
    assert_eq!(names(&non_initial), ["ethernet", "ipv6", "ipv6_fragment"]);
}

#[test]
fn bytes_beyond_network_payload_never_complete_common_bodies() {
    let v4_message = icmpv4(8, 0, &[0x12, 0x34, 0x56, 0x78]);
    let v4 = decode(&ethernet(0x0800, &ipv4(&v4_message, 4, 0)));
    assert_relative_range(v4.layers()[2].byte_range, IPV4_ICMP_OFFSET, 4);
    assert!(layer_child(&v4, 2, "identifier").is_none());
    assert!(layer_child(&v4, 2, "sequence_number").is_none());
    assert_eq!(
        diagnostic_code(&v4),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_ranges_within_icmp_layer(&v4, 2);

    let v6_message = icmpv6(2, 0, &1280_u32.to_be_bytes());
    let v6 = decode(&ethernet(0x86dd, &ipv6(58, &v6_message, 4)));
    assert_relative_range(v6.layers()[2].byte_range, IPV6_ICMP_OFFSET, 4);
    assert!(layer_child(&v6, 2, "mtu").is_none());
    assert_eq!(
        diagnostic_code(&v6),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_ranges_within_icmp_layer(&v6, 2);
}

#[test]
fn ambiguous_ipv6_routing_destination_omits_checksum_validity() {
    let message = icmpv6(128, 0, &[0x12, 0x34, 0x56, 0x78]);
    let mut payload = vec![58, 0, 0, 0, 0, 0, 0, 0];
    payload.extend(message);
    let dataset = decode(&ethernet(0x86dd, &ipv6(43, &payload, payload.len())));

    assert_eq!(
        names(&dataset),
        ["ethernet", "ipv6", "ipv6_routing", "icmpv6"]
    );
    assert!(layer_child(&dataset, 3, "checksum_valid").is_none());
    assert!(dataset.diagnostics().is_empty());
}
