//! Synthetic IPv4 decoder fixtures and hostile-input coverage.

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

fn pcapng_capture(packet: &[u8]) -> Vec<u8> {
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
        enhanced_packet.push(0);
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
    protocol: u8,
    flags_fragment: u16,
    total_length: Option<u16>,
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    assert!(options.len() <= 40);
    let header_length = 20 + options.len();
    let header_words = u8::try_from(header_length / 4).expect("IPv4 IHL fits");
    let default_total = u16::try_from(header_length + payload.len()).expect("fixture length fits");
    let mut packet = Vec::with_capacity(header_length + payload.len());
    packet.extend([0x40 | header_words, 0xb9]);
    packet.extend(total_length.unwrap_or(default_total).to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(flags_fragment.to_be_bytes());
    packet.extend([64, protocol]);
    packet.extend([0, 0]);
    packet.extend([192, 0, 2, 1]);
    packet.extend([198, 51, 100, 9]);
    packet.extend(options);
    let checksum = ipv4_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for word in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
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
    expected: &str,
) -> impl Iterator<Item = &'a packet_core::DecodedField> {
    dataset
        .fields()
        .iter()
        .filter(move |field| dataset.string(field.name) == Some(expected))
}

fn one_field<'a>(dataset: &'a CaptureDataset, expected: &str) -> &'a packet_core::DecodedField {
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
            assert!(range.start() >= packet.data.start());
            assert!(range.end() <= packet.data.end());
        }
    }
    for diagnostic in dataset.diagnostics() {
        if let Some(range) = diagnostic.byte_range {
            assert!(range.start() >= packet.data.start());
            assert!(range.end() <= packet.data.end());
        }
    }
}

fn has_diagnostic(dataset: &CaptureDataset, code: DiagnosticCode) -> bool {
    dataset
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

#[test]
fn decodes_ipv4_fixed_header_fragment_metadata_and_checksum() {
    let packet = ethernet(0x0800, &ipv4(&[], &[0; 8], 17, 0x2000, None));
    let dataset = decode(&packet);

    assert_eq!(names(&dataset), ["ethernet", "ipv4"]);
    assert!(dataset.diagnostics().is_empty());
    assert_relative_range(dataset.layers()[1].byte_range, 14, 20);
    assert_eq!(
        one_field(&dataset, "version").value,
        FieldValue::Unsigned(4)
    );
    assert_eq!(
        one_field(&dataset, "header_length").value,
        FieldValue::Unsigned(20)
    );
    assert_eq!(
        one_field(&dataset, "differentiated_services").value,
        FieldValue::Unsigned(46)
    );
    assert_eq!(
        one_field(&dataset, "explicit_congestion_notification").value,
        FieldValue::Unsigned(1)
    );
    assert_eq!(
        one_field(&dataset, "total_length").value,
        FieldValue::Unsigned(28)
    );
    assert_eq!(
        one_field(&dataset, "protocol").value,
        FieldValue::Unsigned(17)
    );
    assert_eq!(
        one_field(&dataset, "more_fragments").value,
        FieldValue::Boolean(true)
    );
    assert_eq!(
        one_field(&dataset, "fragment_offset").value,
        FieldValue::Unsigned(0)
    );
    assert_eq!(
        one_field(&dataset, "header_checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_relative_range(one_field(&dataset, "source_address").byte_range, 26, 4);
    assert_relative_range(one_field(&dataset, "destination_address").byte_range, 30, 4);
    assert_relative_range(
        one_field(&dataset, "header_checksum_valid").byte_range,
        14,
        20,
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn decodes_bounded_ipv4_options_in_wire_order() {
    let options = [1, 0x82, 4, 0xaa, 0, 0, 0, 0];
    let dataset = decode(&ethernet(0x0800, &ipv4(&options, &[], 6, 0, None)));

    assert_eq!(names(&dataset), ["ethernet", "ipv4"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(
        fields_named(&dataset, "no_operation").count(),
        1,
        "one NOP option is retained"
    );
    assert_eq!(fields_named(&dataset, "ipv4_option").count(), 1);
    assert_eq!(fields_named(&dataset, "end_of_options").count(), 1);
    assert_eq!(fields_named(&dataset, "padding").count(), 1);
    assert_eq!(
        one_field(&dataset, "option_type").value,
        FieldValue::Unsigned(0x82)
    );
    assert_eq!(
        one_field(&dataset, "option_length").value,
        FieldValue::Unsigned(4)
    );
    assert_relative_range(one_field(&dataset, "data").byte_range, 37, 2);
    assert_relative_range(one_field(&dataset, "padding").byte_range, 40, 2);
    assert_relative_range(dataset.layers()[1].byte_range, 14, 28);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn advertised_global_field_and_child_ceilings_cover_ipv4_options() {
    let mut options = Vec::with_capacity(40);
    for _ in 0..20 {
        options.extend([0x1e, 2]);
    }
    let dataset = decode(&vlan(0x0800, &ipv4(&options, &[], 6, 0, None)));

    assert_eq!(names(&dataset), ["ethernet", "vlan", "ipv4"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(
        dataset.fields().len(),
        DECODER_MAX_FIELDS_PER_PACKET as usize
    );
    assert_eq!(
        dataset.field_children().len(),
        DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize
    );
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert_eq!(fields_named(&dataset, "ipv4_option").count(), 20);
    assert_eq!(fields_named(&dataset, "option_type").count(), 20);
    assert_eq!(fields_named(&dataset, "option_length").count(), 20);
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn every_ipv4_header_cutoff_is_truncated_without_invalid_ranges() {
    let fixed = ethernet(0x0800, &ipv4(&[], &[], 6, 0, None));
    for captured_header_length in 0..20 {
        let dataset = decode(&fixed[..14 + captured_header_length]);
        assert_eq!(names(&dataset), ["ethernet", "ipv4"]);
        assert!(has_diagnostic(&dataset, DiagnosticCode::TRUNCATED_PROTOCOL));
        assert_all_ranges_within_packet(&dataset);
    }

    let with_options = ethernet(0x0800, &ipv4(&[1; 8], &[], 6, 0, None));
    for captured_header_length in 20..28 {
        let dataset = decode(&with_options[..14 + captured_header_length]);
        assert_eq!(names(&dataset), ["ethernet", "ipv4"]);
        assert!(has_diagnostic(&dataset, DiagnosticCode::TRUNCATED_PROTOCOL));
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn malformed_version_lengths_options_and_fragments_are_distinguished() {
    let mut wrong_version = ipv4(&[], &[], 6, 0, None);
    wrong_version[0] = 0x65;
    let wrong_version = decode(&ethernet(0x0800, &wrong_version));
    assert!(has_diagnostic(
        &wrong_version,
        DiagnosticCode::MALFORMED_PROTOCOL
    ));

    let mut short_ihl = ipv4(&[], &[], 6, 0, None);
    short_ihl[0] = 0x44;
    let short_ihl = decode(&ethernet(0x0800, &short_ihl));
    assert!(has_diagnostic(
        &short_ihl,
        DiagnosticCode::MALFORMED_PROTOCOL
    ));

    let short_total = decode(&ethernet(0x0800, &ipv4(&[1; 4], &[], 6, 0, Some(20))));
    assert!(has_diagnostic(
        &short_total,
        DiagnosticCode::MALFORMED_PROTOCOL
    ));

    for options in [[0x82, 1, 0, 0], [0x82, 10, 0, 0], [1, 1, 1, 0x82]] {
        let malformed = decode(&ethernet(0x0800, &ipv4(&options, &[], 6, 0, None)));
        assert!(has_diagnostic(
            &malformed,
            DiagnosticCode::MALFORMED_PROTOCOL
        ));
        assert_all_ranges_within_packet(&malformed);
    }

    let payload_after_terminal_option =
        decode(&ethernet(0x0800, &ipv4(&[1, 1, 1, 0x82], &[2], 6, 0, None)));
    assert!(has_diagnostic(
        &payload_after_terminal_option,
        DiagnosticCode::MALFORMED_PROTOCOL
    ));
    assert_all_ranges_within_packet(&payload_after_terminal_option);

    for flags in [0x8000, 0x6001] {
        let malformed = decode(&ethernet(0x0800, &ipv4(&[], &[0; 8], 6, flags, None)));
        assert!(has_diagnostic(
            &malformed,
            DiagnosticCode::MALFORMED_PROTOCOL
        ));
        assert_all_ranges_within_packet(&malformed);
    }

    let non_aligned_fragment = decode(&ethernet(0x0800, &ipv4(&[], &[0; 7], 6, 0x2000, None)));
    assert!(has_diagnostic(
        &non_aligned_fragment,
        DiagnosticCode::MALFORMED_PROTOCOL
    ));
}

#[test]
fn payload_truncation_outranks_checksum_warning_and_checksum_message_is_safe() {
    let truncated = decode(&ethernet(0x0800, &ipv4(&[], &[], 17, 0, Some(100))));
    assert_eq!(truncated.diagnostics().len(), 1);
    assert_eq!(
        truncated.diagnostics()[0].code,
        DiagnosticCode::TRUNCATED_PROTOCOL
    );

    let mut damaged = ipv4(&[], &[], 17, 0, None);
    damaged[10] ^= 0xff;
    let damaged = decode(&ethernet(0x0800, &damaged));
    assert_eq!(damaged.diagnostics().len(), 1);
    let diagnostic = damaged.diagnostics()[0];
    assert_eq!(diagnostic.code, DiagnosticCode::INVALID_PROTOCOL_CHECKSUM);
    let message = damaged
        .string(diagnostic.message)
        .expect("diagnostic message is interned");
    assert!(message.contains("offload"));
    assert!(!message.contains("192.0.2.1"));
    assert_all_ranges_within_packet(&damaged);
}

#[test]
fn ipv4_decode_is_identical_through_pcapng_framing() {
    let packet = vlan(0x0800, &ipv4(&[1, 1, 1, 0], &[], 58, 0x0012, None));
    let dataset = decode_capture(pcapng_capture(&packet));

    assert_eq!(names(&dataset), ["ethernet", "vlan", "ipv4"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(
        one_field(&dataset, "protocol").value,
        FieldValue::Unsigned(58)
    );
    assert_eq!(
        one_field(&dataset, "fragment_offset").value,
        FieldValue::Unsigned(18)
    );
    assert_eq!(
        one_field(&dataset, "fragment_offset_bytes").value,
        FieldValue::Unsigned(144)
    );
    assert_all_ranges_within_packet(&dataset);
}

proptest! {
    #[test]
    fn arbitrary_ipv4_payloads_never_escape_checked_ranges(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let dataset = decode(&ethernet(0x0800, &bytes));
        prop_assert!(dataset.diagnostics().len() <= 1);
        assert_all_ranges_within_packet(&dataset);
    }

    #[test]
    fn every_ipv4_protocol_value_is_preserved_for_transport_dispatch(protocol in any::<u8>()) {
        let dataset = decode(&ethernet(0x0800, &ipv4(&[], &[], protocol, 0, None)));
        prop_assert_eq!(
            one_field(&dataset, "protocol").value,
            FieldValue::Unsigned(u64::from(protocol))
        );
        prop_assert!(!has_diagnostic(
            &dataset,
            DiagnosticCode::INVALID_PROTOCOL_CHECKSUM
        ));
        assert_all_ranges_within_packet(&dataset);
    }
}
