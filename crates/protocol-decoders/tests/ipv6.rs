//! Synthetic IPv6 decoder fixtures and hostile extension-chain coverage.

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
const IPV6_OFFSET: u64 = 14;
const IPV6_PAYLOAD_OFFSET: u64 = IPV6_OFFSET + 40;

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

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + payload.len());
    packet.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    packet.extend(0x86dd_u16.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv6(next_header: u8, payload: &[u8], declared_payload_length: Option<u16>) -> Vec<u8> {
    let default_length = u16::try_from(payload.len()).expect("fixture payload length fits u16");
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend([0x6a, 0xb1, 0x23, 0x45]);
    packet.extend(
        declared_payload_length
            .unwrap_or(default_length)
            .to_be_bytes(),
    );
    packet.extend([next_header, 64]);
    packet.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend(payload);
    packet
}

fn fragment(next_header: u8, offset: u16, more_fragments: bool, id: u32) -> [u8; 8] {
    let word = (offset << 3) | u16::from(more_fragments);
    let word = word.to_be_bytes();
    let id = id.to_be_bytes();
    [next_header, 0, word[0], word[1], id[0], id[1], id[2], id[3]]
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
) -> &'a packet_core::DecodedField {
    let root = dataset.layers()[layer_index]
        .root_field
        .expect("decoded layer has a root");
    let child_range = dataset.fields()[root.0 as usize].children;
    let children =
        &dataset.field_children()[child_range.start() as usize..child_range.end() as usize];
    let mut matches = children.iter().filter_map(|id| {
        let field = &dataset.fields()[id.0 as usize];
        (dataset.string(field.name) == Some(expected)).then_some(field)
    });
    let field = matches.next().expect("layer child exists");
    assert!(matches.next().is_none(), "layer child {expected} is unique");
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
fn decodes_fixed_header_with_exact_values_and_ranges() {
    let dataset = decode(&ethernet(&ipv6(59, &[1, 2, 3, 4], None)));

    assert_eq!(names(&dataset), ["ethernet", "ipv6"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[1].byte_range, IPV6_OFFSET, 40);
    assert_eq!(
        one_field(&dataset, "version").value,
        FieldValue::Unsigned(6)
    );
    assert_eq!(
        one_field(&dataset, "traffic_class").value,
        FieldValue::Unsigned(0xab)
    );
    assert_eq!(
        one_field(&dataset, "flow_label").value,
        FieldValue::Unsigned(0x1_2345)
    );
    assert_eq!(
        one_field(&dataset, "payload_length").value,
        FieldValue::Unsigned(4)
    );
    assert_eq!(
        one_field(&dataset, "next_header").value,
        FieldValue::Unsigned(59)
    );
    assert_relative_range(one_field(&dataset, "version").byte_range, IPV6_OFFSET, 1);
    assert_relative_range(
        one_field(&dataset, "traffic_class").byte_range,
        IPV6_OFFSET,
        2,
    );
    assert_relative_range(
        one_field(&dataset, "flow_label").byte_range,
        IPV6_OFFSET + 1,
        3,
    );
    assert_relative_range(
        one_field(&dataset, "source_address").byte_range,
        IPV6_OFFSET + 8,
        16,
    );
    assert_relative_range(
        one_field(&dataset, "destination_address").byte_range,
        IPV6_OFFSET + 24,
        16,
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn traverses_common_extensions_in_wire_order() {
    let mut payload = Vec::new();
    payload.extend([43, 0, 1, 0, 0, 0, 0, 0]);
    payload.extend([60, 0, 2, 1, 0xaa, 0xbb, 0xcc, 0xdd]);
    payload.extend([44, 0, 1, 2, 3, 4, 5, 6]);
    payload.extend(fragment(51, 0, true, 0x1234_5678));
    payload.extend([59, 2, 0, 0]);
    payload.extend(0x0102_0304_u32.to_be_bytes());
    payload.extend(0x0506_0708_u32.to_be_bytes());
    payload.extend([0xde, 0xad, 0xbe, 0xef]);
    let dataset = decode(&ethernet(&ipv6(0, &payload, None)));

    assert_eq!(
        names(&dataset),
        [
            "ethernet",
            "ipv6",
            "ipv6_hop_by_hop",
            "ipv6_routing",
            "ipv6_destination_options",
            "ipv6_fragment",
            "ipv6_authentication",
        ]
    );
    assert!(dataset.diagnostics().is_empty());
    for (index, start, length) in [
        (2, IPV6_PAYLOAD_OFFSET, 8),
        (3, IPV6_PAYLOAD_OFFSET + 8, 8),
        (4, IPV6_PAYLOAD_OFFSET + 16, 8),
        (5, IPV6_PAYLOAD_OFFSET + 24, 8),
        (6, IPV6_PAYLOAD_OFFSET + 32, 16),
    ] {
        assert_relative_range(dataset.layers()[index].byte_range, start, length);
    }
    assert_eq!(
        layer_child(&dataset, 3, "routing_type").value,
        FieldValue::Unsigned(2)
    );
    assert_eq!(
        layer_child(&dataset, 3, "segments_left").value,
        FieldValue::Unsigned(1)
    );
    assert_eq!(
        layer_child(&dataset, 5, "more_fragments").value,
        FieldValue::Boolean(true)
    );
    assert_eq!(
        layer_child(&dataset, 5, "identification").value,
        FieldValue::Unsigned(0x1234_5678)
    );
    assert_eq!(
        layer_child(&dataset, 6, "security_parameters_index").value,
        FieldValue::Unsigned(0x0102_0304)
    );
    assert_relative_range(
        layer_child(&dataset, 6, "authentication_data").byte_range,
        IPV6_PAYLOAD_OFFSET + 44,
        4,
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn stops_at_non_initial_fragment_but_continues_initial_and_atomic_fragments() {
    let mut non_initial = Vec::new();
    non_initial.extend(fragment(60, 3, true, 7));
    non_initial.extend([59, 0, 0, 0, 0, 0, 0, 0]);
    let dataset = decode(&ethernet(&ipv6(44, &non_initial, None)));
    assert_eq!(names(&dataset), ["ethernet", "ipv6", "ipv6_fragment"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(
        layer_child(&dataset, 2, "fragment_offset").value,
        FieldValue::Unsigned(3)
    );
    assert_eq!(
        layer_child(&dataset, 2, "fragment_offset_bytes").value,
        FieldValue::Unsigned(24)
    );

    for more_fragments in [false, true] {
        let mut first = Vec::new();
        first.extend(fragment(60, 0, more_fragments, 8));
        first.extend([59, 0, 0, 0, 0, 0, 0, 0]);
        let decoded = decode(&ethernet(&ipv6(44, &first, None)));
        assert_eq!(
            names(&decoded),
            [
                "ethernet",
                "ipv6",
                "ipv6_fragment",
                "ipv6_destination_options"
            ]
        );
        assert!(decoded.diagnostics().is_empty());
        assert_all_ranges_within_packet(&decoded);
    }
}

#[test]
fn every_fixed_header_cutoff_is_truncated_without_invalid_ranges() {
    let full = ethernet(&ipv6(59, &[], None));
    for captured_header_length in 0..40 {
        let dataset = decode(&full[..14 + captured_header_length]);
        assert_eq!(names(&dataset), ["ethernet", "ipv6"]);
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn malformed_declared_extension_and_captured_truncation_are_distinct() {
    let malformed = decode(&ethernet(&ipv6(0, &[59, 1, 0, 0, 0, 0, 0, 0], None)));
    assert_eq!(
        diagnostic_code(&malformed),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(names(&malformed), ["ethernet", "ipv6"]);
    assert_relative_range(
        malformed.diagnostics()[0]
            .byte_range
            .expect("malformed length has evidence"),
        IPV6_PAYLOAD_OFFSET + 1,
        1,
    );

    let truncated = decode(&ethernet(&ipv6(0, &[59, 1, 0, 0, 0, 0, 0, 0], Some(16))));
    assert_eq!(
        diagnostic_code(&truncated),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(names(&truncated), ["ethernet", "ipv6"]);

    let mut misplaced = Vec::new();
    misplaced.extend([0, 0, 0, 0, 0, 0, 0, 0]);
    misplaced.extend([59, 0, 0, 0, 0, 0, 0, 0]);
    let misplaced = decode(&ethernet(&ipv6(43, &misplaced, None)));
    assert_eq!(
        diagnostic_code(&misplaced),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(names(&misplaced), ["ethernet", "ipv6", "ipv6_routing"]);
    assert_all_ranges_within_packet(&malformed);
    assert_all_ranges_within_packet(&truncated);
    assert_all_ranges_within_packet(&misplaced);
}

#[test]
fn jumbogram_semantics_are_structurally_unsupported_not_malformed() {
    let hop_by_hop_with_jumbo_option = [59, 0, 0xc2, 4, 0, 1, 0, 0];
    let dataset = decode(&ethernet(&ipv6(0, &hop_by_hop_with_jumbo_option, Some(0))));

    assert_eq!(names(&dataset), ["ethernet", "ipv6", "unsupported"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::UNSUPPORTED_ENCAPSULATION)
    );
    assert_eq!(
        fields_named(&dataset, "unsupported_ipv6_jumbogram").count(),
        1
    );
    assert_relative_range(
        one_field(&dataset, "unsupported_ipv6_jumbogram").byte_range,
        IPV6_OFFSET + 6,
        1,
    );
    assert_eq!(
        layer_child(&dataset, 2, "next_header").value,
        FieldValue::Unsigned(0)
    );
    assert_relative_range(
        layer_child(&dataset, 2, "next_header").byte_range,
        IPV6_OFFSET + 6,
        1,
    );
    assert_all_ranges_within_packet(&dataset);

    let absent_hop_by_hop = decode(&ethernet(&ipv6(0, &[], Some(0))));
    assert_eq!(names(&absent_hop_by_hop), ["ethernet", "ipv6"]);
    assert_eq!(
        diagnostic_code(&absent_hop_by_hop),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        absent_hop_by_hop.diagnostics()[0]
            .byte_range
            .expect("missing Hop-by-Hop header has selector evidence"),
        IPV6_OFFSET + 6,
        1,
    );
    assert_all_ranges_within_packet(&absent_hop_by_hop);
}

#[test]
fn malformed_authentication_length_is_retained_then_stops() {
    let mut ah = vec![59, 1, 0, 0];
    ah.extend(0x0102_0304_u32.to_be_bytes());
    ah.extend(0x0506_0708_u32.to_be_bytes());
    let dataset = decode(&ethernet(&ipv6(51, &ah, None)));

    assert_eq!(names(&dataset), ["ethernet", "ipv6", "ipv6_authentication"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(dataset.layers()[2].byte_range, IPV6_PAYLOAD_OFFSET, 12);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn depth_and_cumulative_byte_caps_emit_visible_resource_markers() {
    let mut deep = Vec::new();
    for index in 0..9 {
        let next = if index == 8 { 59 } else { 44 };
        deep.extend(fragment(next, 0, false, index));
    }
    let deep = decode(&ethernet(&ipv6(44, &deep, None)));
    assert_eq!(
        names(&deep),
        [
            "ethernet",
            "ipv6",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "ipv6_fragment",
            "unsupported",
        ]
    );
    assert_eq!(diagnostic_code(&deep), Some(DiagnosticCode::RESOURCE_LIMIT));
    assert_eq!(
        fields_named(&deep, "unsupported_ipv6_extension_chain").count(),
        1
    );

    let mut wide = vec![0; 512];
    wide[0] = 44;
    wide[1] = 63;
    wide.extend(fragment(59, 0, false, 1));
    let wide = decode(&ethernet(&ipv6(0, &wide, None)));
    assert_eq!(
        names(&wide),
        ["ethernet", "ipv6", "ipv6_hop_by_hop", "unsupported"]
    );
    assert_eq!(diagnostic_code(&wide), Some(DiagnosticCode::RESOURCE_LIMIT));
    assert_relative_range(wide.layers()[2].byte_range, IPV6_PAYLOAD_OFFSET, 512);

    let mut esp_after_cap = vec![0; 512];
    esp_after_cap[0] = 50;
    esp_after_cap[1] = 63;
    esp_after_cap.extend([0; 8]);
    let esp_after_cap = decode(&ethernet(&ipv6(0, &esp_after_cap, None)));
    assert_eq!(
        names(&esp_after_cap),
        ["ethernet", "ipv6", "ipv6_hop_by_hop", "unsupported"]
    );
    assert_eq!(
        diagnostic_code(&esp_after_cap),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );
    assert_all_ranges_within_packet(&deep);
    assert_all_ranges_within_packet(&wide);
    assert_all_ranges_within_packet(&esp_after_cap);
}

#[test]
fn esp_is_a_structured_unsupported_terminal() {
    let mut esp = Vec::new();
    esp.extend(0x0102_0304_u32.to_be_bytes());
    esp.extend(0x0506_0708_u32.to_be_bytes());
    esp.extend([0xaa, 0xbb, 0xcc, 0xdd]);
    let dataset = decode(&ethernet(&ipv6(50, &esp, None)));

    assert_eq!(names(&dataset), ["ethernet", "ipv6", "ipv6_esp"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::UNSUPPORTED_ENCAPSULATION)
    );
    assert_relative_range(dataset.layers()[2].byte_range, IPV6_PAYLOAD_OFFSET, 12);
    assert_eq!(
        layer_child(&dataset, 2, "security_parameters_index").value,
        FieldValue::Unsigned(0x0102_0304)
    );
    assert_relative_range(
        layer_child(&dataset, 2, "data").byte_range,
        IPV6_PAYLOAD_OFFSET + 8,
        4,
    );
    assert_all_ranges_within_packet(&dataset);
}

proptest! {
    #[test]
    fn arbitrary_ipv6_payloads_never_escape_checked_ranges(
        bytes in proptest::collection::vec(any::<u8>(), 0..700),
    ) {
        let dataset = decode(&ethernet(&ipv6(0, &bytes, None)));
        prop_assert!(dataset.diagnostics().len() <= 1);
        assert_all_ranges_within_packet(&dataset);
    }
}
