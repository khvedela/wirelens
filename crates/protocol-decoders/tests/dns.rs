//! Synthetic DNS fixtures, compression safety, framing, and resource-bound coverage.

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldValue, ImportLimits,
    ImportStep,
};
use proptest::prelude::*;
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder, MAX_DNS_NAMES_PER_PACKET,
};

const PACKET_OFFSET: u64 = 40;
const UDP_DNS_OFFSET: u64 = 42;
const TCP_DNS_OFFSET: u64 = 56;
const IPV6_UDP_DNS_OFFSET: u64 = 62;
const IPV6_TCP_DNS_OFFSET: u64 = 76;
const IPV4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const IPV4_DESTINATION: [u8; 4] = [198, 51, 100, 9];
const IPV6_SOURCE: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_DESTINATION: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const DNS_PORT: u16 = 53;
const CLIENT_PORT: u16 = 53_000;
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const CLASS_CHAOS: u16 = 3;

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
    ethernet_with_type(0x0800, payload)
}

fn ethernet_with_type(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + payload.len());
    packet.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    packet.extend(ether_type.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv4(payload: &[u8], protocol: u8) -> Vec<u8> {
    let total_length = u16::try_from(20 + payload.len()).expect("IPv4 fixture length fits u16");
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend([0x45, 0]);
    packet.extend(total_length.to_be_bytes());
    packet.extend(0x1234_u16.to_be_bytes());
    packet.extend(0_u16.to_be_bytes());
    packet.extend([64, protocol]);
    packet.extend([0, 0]);
    packet.extend(IPV4_SOURCE);
    packet.extend(IPV4_DESTINATION);
    let checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend(payload);
    packet
}

fn ipv6(payload: &[u8], next_header: u8) -> Vec<u8> {
    let payload_length = u16::try_from(payload.len()).expect("IPv6 fixture length fits u16");
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend([0x60, 0, 0, 0]);
    packet.extend(payload_length.to_be_bytes());
    packet.extend([next_header, 64]);
    packet.extend(IPV6_SOURCE);
    packet.extend(IPV6_DESTINATION);
    packet.extend(payload);
    packet
}

fn udp(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    udp_with_declared_payload(payload, source_port, destination_port, payload.len())
}

fn udp_with_declared_payload(
    payload: &[u8],
    source_port: u16,
    destination_port: u16,
    declared_payload_length: usize,
) -> Vec<u8> {
    let length = u16::try_from(8 + declared_payload_length).expect("UDP fixture length fits u16");
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend(source_port.to_be_bytes());
    datagram.extend(destination_port.to_be_bytes());
    datagram.extend(length.to_be_bytes());
    datagram.extend(0_u16.to_be_bytes());
    datagram.extend(payload);
    datagram
}

fn tcp(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend(source_port.to_be_bytes());
    segment.extend(destination_port.to_be_bytes());
    segment.extend(0x0102_0304_u32.to_be_bytes());
    segment.extend(0xa0b0_c0d0_u32.to_be_bytes());
    segment.extend([0x50, 0x18]);
    segment.extend(0x4567_u16.to_be_bytes());
    segment.extend([0, 0]);
    segment.extend(0_u16.to_be_bytes());
    segment.extend(payload);
    set_tcp_checksum(&mut segment);
    segment
}

fn set_tcp_checksum(segment: &mut [u8]) {
    segment[16..18].copy_from_slice(&[0, 0]);
    let length = u16::try_from(segment.len())
        .expect("TCP fixture length fits u16")
        .to_be_bytes();
    let protocol = [0, 6];
    let value = checksum(&[&IPV4_SOURCE, &IPV4_DESTINATION, &protocol, &length, segment]);
    segment[16..18].copy_from_slice(&wire_checksum(value).to_be_bytes());
}

fn set_tcp_checksum_v6(segment: &mut [u8]) {
    segment[16..18].copy_from_slice(&[0, 0]);
    let length = u32::try_from(segment.len())
        .expect("TCP fixture length fits u32")
        .to_be_bytes();
    let protocol = [0, 0, 0, 6];
    let value = checksum(&[&IPV6_SOURCE, &IPV6_DESTINATION, &length, &protocol, segment]);
    segment[16..18].copy_from_slice(&wire_checksum(value).to_be_bytes());
}

fn set_udp_checksum_v6(datagram: &mut [u8]) {
    datagram[6..8].copy_from_slice(&[0, 0]);
    let length = u32::try_from(datagram.len())
        .expect("UDP fixture length fits u32")
        .to_be_bytes();
    let protocol = [0, 0, 0, 17];
    let value = checksum(&[
        &IPV6_SOURCE,
        &IPV6_DESTINATION,
        &length,
        &protocol,
        datagram,
    ]);
    datagram[6..8].copy_from_slice(&wire_checksum(value).to_be_bytes());
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

fn udp_packet(message: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    ethernet(&ipv4(&udp(message, source_port, destination_port), 17))
}

fn tcp_packet(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    ethernet(&ipv4(&tcp(payload, source_port, destination_port), 6))
}

fn ipv6_udp_packet(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let mut datagram = udp(payload, source_port, destination_port);
    set_udp_checksum_v6(&mut datagram);
    ethernet_with_type(0x86dd, &ipv6(&datagram, 17))
}

fn ipv6_tcp_packet(payload: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let mut segment = tcp(payload, source_port, destination_port);
    set_tcp_checksum_v6(&mut segment);
    ethernet_with_type(0x86dd, &ipv6(&segment, 6))
}

fn tcp_frame(message: &[u8]) -> Vec<u8> {
    let length = u16::try_from(message.len()).expect("DNS message length fits TCP prefix");
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend(length.to_be_bytes());
    frame.extend(message);
    frame
}

fn dns_header(
    flags: u16,
    questions: u16,
    answers: u16,
    authorities: u16,
    additional: u16,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);
    header.extend(0x1234_u16.to_be_bytes());
    header.extend(flags.to_be_bytes());
    header.extend(questions.to_be_bytes());
    header.extend(answers.to_be_bytes());
    header.extend(authorities.to_be_bytes());
    header.extend(additional.to_be_bytes());
    header
}

fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut name = Vec::new();
    for label in labels {
        assert!(label.len() <= 63);
        name.push(u8::try_from(label.len()).expect("label length fits u8"));
        name.extend(*label);
    }
    name.push(0);
    name
}

fn pointer(offset: usize) -> [u8; 2] {
    let offset = u16::try_from(offset).expect("DNS compression offset fits u16");
    assert!(offset <= 0x3fff);
    (0xc000 | offset).to_be_bytes()
}

fn prefixed_pointer(label: &[u8], offset: usize) -> Vec<u8> {
    assert!(label.len() <= 63);
    let mut name = Vec::with_capacity(3 + label.len());
    name.push(u8::try_from(label.len()).expect("label length fits u8"));
    name.extend(label);
    name.extend(pointer(offset));
    name
}

fn append_question(message: &mut Vec<u8>, name: &[u8], qtype: u16, qclass: u16) {
    message.extend(name);
    message.extend(qtype.to_be_bytes());
    message.extend(qclass.to_be_bytes());
}

fn append_record(message: &mut Vec<u8>, owner: &[u8], rtype: u16, rdata: &[u8]) {
    append_record_with_class_and_length(
        message,
        owner,
        rtype,
        CLASS_IN,
        u16::try_from(rdata.len()).expect("RDATA length fits u16"),
        rdata,
    );
}

fn append_record_with_length(
    message: &mut Vec<u8>,
    owner: &[u8],
    rtype: u16,
    declared_length: u16,
    rdata: &[u8],
) {
    append_record_with_class_and_length(message, owner, rtype, CLASS_IN, declared_length, rdata);
}

fn append_record_with_class_and_length(
    message: &mut Vec<u8>,
    owner: &[u8],
    rtype: u16,
    class: u16,
    declared_length: u16,
    rdata: &[u8],
) {
    message.extend(owner);
    message.extend(rtype.to_be_bytes());
    message.extend(class.to_be_bytes());
    message.extend(300_u32.to_be_bytes());
    message.extend(declared_length.to_be_bytes());
    message.extend(rdata);
}

fn simple_query() -> Vec<u8> {
    let mut message = dns_header(0x0100, 1, 0, 0, 0);
    append_question(
        &mut message,
        &wire_name(&[b"www", b"Example", b"com"]),
        TYPE_A,
        CLASS_IN,
    );
    message
}

fn layer_names(dataset: &CaptureDataset) -> Vec<&str> {
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

fn field_children<'a>(
    dataset: &'a CaptureDataset,
    parent: &packet_core::DecodedField,
) -> impl Iterator<Item = &'a packet_core::DecodedField> {
    let children = parent.children;
    dataset.field_children()[children.start() as usize..children.end() as usize]
        .iter()
        .map(|id| &dataset.fields()[id.0 as usize])
}

fn child_named<'a>(
    dataset: &'a CaptureDataset,
    parent: &packet_core::DecodedField,
    expected: &str,
) -> &'a packet_core::DecodedField {
    let mut children = field_children(dataset, parent)
        .filter(|field| dataset.string(field.name) == Some(expected));
    let field = children.next().expect("named child exists");
    assert!(children.next().is_none(), "child {expected} is unique");
    field
}

fn dns_root(dataset: &CaptureDataset) -> &packet_core::DecodedField {
    let layer = dataset
        .layers()
        .iter()
        .find(|layer| dataset.string(layer.protocol) == Some("dns"))
        .expect("DNS layer exists");
    &dataset.fields()[layer.root_field.expect("DNS layer has a root").0 as usize]
}

fn string_value<'a>(dataset: &'a CaptureDataset, field: &packet_core::DecodedField) -> &'a str {
    let FieldValue::String(value) = field.value else {
        panic!("field contains an interned string");
    };
    dataset.string(value).expect("field string is valid")
}

fn record_with_type<'a>(
    dataset: &'a CaptureDataset,
    root_name: &'a str,
    rtype: u16,
) -> &'a packet_core::DecodedField {
    fields_named(dataset, root_name)
        .find(|record| {
            child_named(dataset, record, "type").value == FieldValue::Unsigned(u64::from(rtype))
        })
        .expect("record type exists")
}

fn range_bytes(dataset: &CaptureDataset, range: ByteRange) -> &[u8] {
    let start = usize::try_from(range.start()).expect("range start fits usize");
    let end = usize::try_from(range.end()).expect("range end fits usize");
    &dataset.bytes()[start..end]
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
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(
        dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize,
        "{} fields exceed the advertised ceiling",
        dataset.fields().len()
    );
    assert!(
        dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize,
        "{} child references exceed the advertised ceiling",
        dataset.field_children().len()
    );
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

fn assert_dns_ranges_within(dataset: &CaptureDataset, start: u64, length: u32) {
    let layer = dataset
        .layers()
        .iter()
        .find(|layer| dataset.string(layer.protocol) == Some("dns"))
        .expect("DNS layer exists");
    assert_relative_range(layer.byte_range, start, length);
    let root = layer.root_field.expect("DNS root exists").0 as usize;
    for field in &dataset.fields()[root..] {
        assert!(field.byte_range.start() >= layer.byte_range.start());
        assert!(field.byte_range.end() <= layer.byte_range.end());
    }
    assert_all_ranges_within_packet(dataset);
}

#[test]
fn decodes_a_udp_query_with_exact_header_and_question_evidence() {
    let message = simple_query();
    let dataset = decode(&udp_packet(&message, CLIENT_PORT, DNS_PORT));

    assert_eq!(layer_names(&dataset), ["ethernet", "ipv4", "udp", "dns"]);
    assert!(dataset.diagnostics().is_empty());
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );

    let root = dns_root(&dataset);
    let header = child_named(&dataset, root, "dns_header");
    assert_relative_range(header.byte_range, UDP_DNS_OFFSET, 12);
    for (name, value, offset) in [
        ("transaction_id", 0x1234, 0),
        ("flags", 0x0100, 2),
        ("question_count", 1, 4),
        ("answer_count", 0, 6),
        ("authority_count", 0, 8),
        ("additional_count", 0, 10),
    ] {
        let field = child_named(&dataset, header, name);
        assert_eq!(field.value, FieldValue::Unsigned(value), "{name}");
        assert_relative_range(field.byte_range, UDP_DNS_OFFSET + offset, 2);
    }
    assert_eq!(
        child_named(&dataset, header, "is_response").value,
        FieldValue::Boolean(false)
    );
    assert_eq!(
        child_named(&dataset, header, "response_code").value,
        FieldValue::Unsigned(0)
    );

    let question = child_named(&dataset, root, "dns_question");
    let name = child_named(&dataset, question, "name");
    assert_eq!(string_value(&dataset, name), "www.Example.com.");
    assert_relative_range(name.byte_range, UDP_DNS_OFFSET + 12, 17);
    let qtype = child_named(&dataset, question, "type");
    assert_eq!(qtype.value, FieldValue::Unsigned(u64::from(TYPE_A)));
    assert_relative_range(qtype.byte_range, UDP_DNS_OFFSET + 29, 2);
    let qclass = child_named(&dataset, question, "class");
    assert_eq!(qclass.value, FieldValue::Unsigned(u64::from(CLASS_IN)));
    assert_relative_range(qclass.byte_range, UDP_DNS_OFFSET + 31, 2);
}

#[test]
fn decodes_multiple_questions_answers_and_a_nonzero_response_code() {
    let mut message = dns_header(0x8183, 2, 2, 0, 0);
    let base_name = wire_name(&[b"example", b"com"]);
    append_question(&mut message, &base_name, TYPE_A, CLASS_IN);
    let second_name_offset = message.len();
    append_question(
        &mut message,
        &prefixed_pointer(b"www", 12),
        TYPE_AAAA,
        CLASS_IN,
    );
    append_record(&mut message, &pointer(12), TYPE_A, &[192, 0, 2, 7]);
    append_record(
        &mut message,
        &pointer(second_name_offset),
        TYPE_AAAA,
        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
    );
    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert!(dataset.diagnostics().is_empty());
    let root = dns_root(&dataset);
    let header = child_named(&dataset, root, "dns_header");
    assert_eq!(
        child_named(&dataset, header, "is_response").value,
        FieldValue::Boolean(true)
    );
    assert_eq!(
        child_named(&dataset, header, "response_code").value,
        FieldValue::Unsigned(3)
    );
    assert_eq!(fields_named(&dataset, "dns_question").count(), 2);
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 2);
    let question_names: Vec<_> = fields_named(&dataset, "dns_question")
        .map(|question| string_value(&dataset, child_named(&dataset, question, "name")))
        .collect();
    assert_eq!(question_names, ["example.com.", "www.example.com."]);
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn decodes_compression_suffixes_multihop_names_and_compressed_rdata() {
    let mut message = dns_header(0x8180, 2, 1, 0, 0);
    let base_offset = message.len();
    append_question(&mut message, &wire_name(&[b"com"]), TYPE_A, CLASS_IN);
    let suffix_offset = message.len();
    let suffix = prefixed_pointer(b"example", base_offset);
    append_question(&mut message, &suffix, TYPE_CNAME, CLASS_IN);
    let answer_owner = prefixed_pointer(b"www", suffix_offset);
    let rdata = prefixed_pointer(b"alias", suffix_offset);
    append_record(&mut message, &answer_owner, TYPE_CNAME, &rdata);
    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert!(dataset.diagnostics().is_empty());
    let names: Vec<_> = fields_named(&dataset, "dns_question")
        .map(|question| string_value(&dataset, child_named(&dataset, question, "name")))
        .collect();
    assert_eq!(names, ["com.", "example.com."]);
    let answer = record_with_type(&dataset, "dns_answer", TYPE_CNAME);
    assert_eq!(
        string_value(&dataset, child_named(&dataset, answer, "name")),
        "www.example.com."
    );
    assert_eq!(
        string_value(&dataset, child_named(&dataset, answer, "canonical_name")),
        "alias.example.com."
    );
    assert_relative_range(
        child_named(&dataset, answer, "canonical_name").byte_range,
        UDP_DNS_OFFSET + u64::try_from(message.len() - rdata.len()).expect("RDATA offset fits u64"),
        u32::try_from(rdata.len()).expect("RDATA length fits u32"),
    );
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn accepts_prior_internal_label_boundaries_and_rejects_non_name_targets() {
    let mut valid = dns_header(0x0100, 2, 0, 0, 0);
    append_question(
        &mut valid,
        &wire_name(&[b"www", b"example", b"com"]),
        TYPE_A,
        CLASS_IN,
    );
    append_question(
        &mut valid,
        &prefixed_pointer(b"api", 16),
        TYPE_AAAA,
        CLASS_IN,
    );
    let valid = decode(&udp_packet(&valid, CLIENT_PORT, DNS_PORT));
    assert!(valid.diagnostics().is_empty());
    let names: Vec<_> = fields_named(&valid, "dns_question")
        .map(|question| string_value(&valid, child_named(&valid, question, "name")))
        .collect();
    assert_eq!(names, ["www.example.com.", "api.example.com."]);
    assert_all_ranges_within_packet(&valid);

    // The first name starts at offset 12. Its first label payload begins at
    // offset 13 and its QTYPE begins at offset 29; neither is a validated name
    // component boundary even though both are strictly earlier than question 2.
    for (case, target) in [("label payload", 13), ("QTYPE", 29)] {
        let mut message = dns_header(0x0100, 2, 0, 0, 0);
        append_question(
            &mut message,
            &wire_name(&[b"www", b"example", b"com"]),
            TYPE_A,
            CLASS_IN,
        );
        let pointer_offset = message.len();
        append_question(&mut message, &pointer(target), TYPE_A, CLASS_IN);
        let dataset = decode(&udp_packet(&message, CLIENT_PORT, DNS_PORT));

        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::MALFORMED_PROTOCOL),
            "{case}"
        );
        assert_eq!(fields_named(&dataset, "dns_question").count(), 1, "{case}");
        assert_relative_range(
            dataset.diagnostics()[0]
                .byte_range
                .expect("invalid target has evidence"),
            UDP_DNS_OFFSET + u64::try_from(pointer_offset).expect("offset fits u64"),
            2,
        );
        assert_all_ranges_within_packet(&dataset);
    }
}

fn assert_common_record_fields(dataset: &CaptureDataset) {
    let a = child_named(
        dataset,
        record_with_type(dataset, "dns_answer", TYPE_A),
        "address",
    );
    assert_eq!(range_bytes(dataset, a.byte_range), [192, 0, 2, 7]);
    let aaaa = child_named(
        dataset,
        record_with_type(dataset, "dns_answer", TYPE_AAAA),
        "address",
    );
    assert_eq!(range_bytes(dataset, aaaa.byte_range).len(), 16);

    for (rtype, field_name, expected) in [
        (TYPE_NS, "name_server", "ns1.Example.com."),
        (TYPE_CNAME, "canonical_name", "alias.Example.com."),
        (TYPE_PTR, "domain_name", "host.Example.com."),
    ] {
        let record = record_with_type(dataset, "dns_answer", rtype);
        assert_eq!(
            string_value(dataset, child_named(dataset, record, field_name)),
            expected
        );
    }

    let soa = child_named(
        dataset,
        record_with_type(dataset, "dns_answer", TYPE_SOA),
        "rdata",
    );
    for (field_name, expected) in [
        ("primary_name_server", "ns1.Example.com."),
        ("responsible_mailbox", "hostmaster.Example.com."),
    ] {
        assert_eq!(
            string_value(dataset, child_named(dataset, soa, field_name)),
            expected
        );
    }
    for (field_name, value) in [
        ("serial", 1),
        ("refresh", 3600),
        ("retry", 600),
        ("expire", 86_400),
        ("minimum", 300),
    ] {
        assert_eq!(
            child_named(dataset, soa, field_name).value,
            FieldValue::Unsigned(value),
            "{field_name}"
        );
    }

    let mx = child_named(
        dataset,
        record_with_type(dataset, "dns_answer", TYPE_MX),
        "rdata",
    );
    assert_eq!(
        child_named(dataset, mx, "preference").value,
        FieldValue::Unsigned(10)
    );
    assert_eq!(
        string_value(dataset, child_named(dataset, mx, "exchange")),
        "mail.Example.com."
    );

    let text: Vec<_> = fields_named(dataset, "text")
        .map(|field| range_bytes(dataset, field.byte_range))
        .collect();
    assert_eq!(text, [b"foo".as_slice(), b"bar".as_slice()]);
    let unknown = child_named(
        dataset,
        record_with_type(dataset, "dns_answer", 65_000),
        "rdata",
    );
    assert_eq!(unknown.value, FieldValue::Bytes(unknown.byte_range));
    assert_eq!(
        range_bytes(dataset, unknown.byte_range),
        [0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn decodes_common_records_and_preserves_unknown_rdata() {
    let mut message = dns_header(0x8180, 1, 9, 0, 0);
    append_question(
        &mut message,
        &wire_name(&[b"Example", b"com"]),
        255,
        CLASS_IN,
    );
    let owner = pointer(12);
    append_record(&mut message, &owner, TYPE_A, &[192, 0, 2, 7]);
    append_record(
        &mut message,
        &owner,
        TYPE_AAAA,
        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
    );
    append_record(&mut message, &owner, TYPE_NS, &prefixed_pointer(b"ns1", 12));
    append_record(
        &mut message,
        &owner,
        TYPE_CNAME,
        &prefixed_pointer(b"alias", 12),
    );
    let mut soa = prefixed_pointer(b"ns1", 12);
    soa.extend(prefixed_pointer(b"hostmaster", 12));
    for value in [1_u32, 3600, 600, 86_400, 300] {
        soa.extend(value.to_be_bytes());
    }
    append_record(&mut message, &owner, TYPE_SOA, &soa);
    append_record(
        &mut message,
        &owner,
        TYPE_PTR,
        &prefixed_pointer(b"host", 12),
    );
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend(prefixed_pointer(b"mail", 12));
    append_record(&mut message, &owner, TYPE_MX, &mx);
    append_record(&mut message, &owner, TYPE_TXT, b"\x03foo\x03bar");
    append_record(&mut message, &owner, 65_000, &[0xde, 0xad, 0xbe, 0xef]);

    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 9);
    assert_common_record_fields(&dataset);
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn preserves_non_internet_class_rdata_without_applying_internet_type_semantics() {
    let mut message = dns_header(0x8180, 0, 2, 0, 0);
    append_record_with_class_and_length(&mut message, &[0], TYPE_A, CLASS_CHAOS, 3, &[1, 2, 3]);
    append_record_with_class_and_length(&mut message, &[0], TYPE_CNAME, CLASS_CHAOS, 1, &[0xff]);

    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 2);
    assert_eq!(fields_named(&dataset, "address").count(), 0);
    assert_eq!(fields_named(&dataset, "canonical_name").count(), 0);
    for record_type in [TYPE_A, TYPE_CNAME] {
        let record = record_with_type(&dataset, "dns_answer", record_type);
        assert_eq!(
            child_named(&dataset, record, "class").value,
            FieldValue::Unsigned(u64::from(CLASS_CHAOS))
        );
        let rdata = child_named(&dataset, record, "rdata");
        assert_eq!(rdata.value, FieldValue::Bytes(rdata.byte_range));
    }
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn decodes_authority_and_additional_sections_with_distinct_roots() {
    let mut message = dns_header(0x8180, 0, 0, 1, 1);
    append_record(
        &mut message,
        &wire_name(&[b"authority", b"example"]),
        TYPE_A,
        &[192, 0, 2, 20],
    );
    append_record(
        &mut message,
        &wire_name(&[b"additional", b"example"]),
        TYPE_AAAA,
        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20],
    );
    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 0);
    let authority = one_field(&dataset, "dns_authority");
    assert_eq!(
        string_value(&dataset, child_named(&dataset, authority, "name")),
        "authority.example."
    );
    assert_eq!(
        child_named(&dataset, authority, "address").value,
        FieldValue::Bytes(child_named(&dataset, authority, "address").byte_range)
    );
    let additional = one_field(&dataset, "dns_additional");
    assert_eq!(
        string_value(&dataset, child_named(&dataset, additional, "name")),
        "additional.example."
    );
    assert_eq!(
        child_named(&dataset, additional, "address").value,
        FieldValue::Bytes(child_named(&dataset, additional, "address").byte_range)
    );
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn accepts_the_label_boundary_and_escapes_non_display_name_bytes() {
    let maximum_label = [b'a'; 63];
    let mut maximum = dns_header(0x0100, 1, 0, 0, 0);
    append_question(
        &mut maximum,
        &wire_name(&[&maximum_label]),
        TYPE_A,
        CLASS_IN,
    );
    let maximum = decode(&udp_packet(&maximum, CLIENT_PORT, DNS_PORT));
    assert!(maximum.diagnostics().is_empty());
    let maximum_name = child_named(&maximum, one_field(&maximum, "dns_question"), "name");
    assert_eq!(
        string_value(&maximum, maximum_name),
        format!("{}.", "a".repeat(63))
    );

    let mut escaped = dns_header(0x0100, 1, 0, 0, 0);
    append_question(&mut escaped, &wire_name(&[&[b'A', 0xff]]), TYPE_A, CLASS_IN);
    let escaped = decode(&udp_packet(&escaped, CLIENT_PORT, DNS_PORT));
    assert!(escaped.diagnostics().is_empty());
    let escaped_name = child_named(&escaped, one_field(&escaped, "dns_question"), "name");
    assert_eq!(string_value(&escaped, escaped_name), "A\\255.");
    assert_all_ranges_within_packet(&maximum);
    assert_all_ranges_within_packet(&escaped);
}

#[test]
fn accepts_an_exact_255_byte_name_and_escapes_ambiguous_octets() {
    let label_63 = [0_u8; 63];
    let label_61 = [0_u8; 61];
    let exact_name = wire_name(&[&label_63, &label_63, &label_63, &label_61]);
    assert_eq!(exact_name.len(), 255);
    let mut exact = dns_header(0x0100, 1, 0, 0, 0);
    append_question(&mut exact, &exact_name, TYPE_A, CLASS_IN);
    let exact = decode(&udp_packet(&exact, CLIENT_PORT, DNS_PORT));
    assert!(exact.diagnostics().is_empty());
    let rendered = string_value(
        &exact,
        child_named(&exact, one_field(&exact, "dns_question"), "name"),
    );
    assert_eq!(rendered.len(), 1_004);
    assert!(rendered.starts_with("\\000\\000"));
    assert!(rendered.ends_with("\\000."));

    let mut escaped = dns_header(0x0100, 1, 0, 0, 0);
    append_question(
        &mut escaped,
        &wire_name(&[&[b'.', b'\\', 0, b'A']]),
        TYPE_A,
        CLASS_IN,
    );
    let escaped = decode(&udp_packet(&escaped, CLIENT_PORT, DNS_PORT));
    assert!(escaped.diagnostics().is_empty());
    let rendered = string_value(
        &escaped,
        child_named(&escaped, one_field(&escaped, "dns_question"), "name"),
    );
    assert_eq!(rendered, "\\046\\092\\000A.");
    assert_all_ranges_within_packet(&exact);
    assert_all_ranges_within_packet(&escaped);
}

#[test]
fn rejects_self_cycles_forward_out_of_bounds_and_reserved_name_encodings() {
    let cases: [(&str, Vec<u8>, usize, usize); 6] = [
        ("self", pointer(12).to_vec(), 12, 2),
        ("cycle", [pointer(14), pointer(12)].concat(), 12, 2),
        ("forward", [pointer(14).as_slice(), &[0]].concat(), 12, 2),
        ("out of bounds", [0xff, 0xff].to_vec(), 12, 2),
        ("reserved 01", [0x40].to_vec(), 12, 1),
        ("reserved 10", [0x80].to_vec(), 12, 1),
    ];
    for (case, name, evidence_offset, evidence_length) in cases {
        let mut message = dns_header(0x0100, 1, 0, 0, 0);
        append_question(&mut message, &name, TYPE_A, CLASS_IN);
        let dataset = decode(&udp_packet(&message, CLIENT_PORT, DNS_PORT));
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::MALFORMED_PROTOCOL),
            "{case}"
        );
        assert_eq!(fields_named(&dataset, "dns_question").count(), 0, "{case}");
        assert_relative_range(
            dataset.diagnostics()[0]
                .byte_range
                .expect("name fault has evidence"),
            UDP_DNS_OFFSET + u64::try_from(evidence_offset).expect("offset fits u64"),
            u32::try_from(evidence_length).expect("length fits u32"),
        );
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn rejects_a_pending_literal_boundary_loop_and_a_truncated_pointer() {
    let mut looped = dns_header(0x0100, 1, 0, 0, 0);
    let pointer_offset = looped.len() + 2;
    append_question(
        &mut looped,
        &[1, b'a', pointer(12)[0], pointer(12)[1]],
        TYPE_A,
        CLASS_IN,
    );
    let looped = decode(&udp_packet(&looped, CLIENT_PORT, DNS_PORT));
    assert_eq!(
        diagnostic_code(&looped),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(fields_named(&looped, "dns_question").count(), 0);
    assert_relative_range(
        looped.diagnostics()[0]
            .byte_range
            .expect("pending-boundary loop has evidence"),
        UDP_DNS_OFFSET + u64::try_from(pointer_offset).expect("offset fits u64"),
        2,
    );

    let mut truncated = dns_header(0x0100, 1, 0, 0, 0);
    truncated.push(0xc0);
    let truncated = decode(&udp_packet(&truncated, CLIENT_PORT, DNS_PORT));
    assert_eq!(
        diagnostic_code(&truncated),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(fields_named(&truncated, "dns_question").count(), 0);
    assert_relative_range(
        truncated.diagnostics()[0]
            .byte_range
            .expect("partial pointer has evidence"),
        UDP_DNS_OFFSET + 12,
        1,
    );
    assert_all_ranges_within_packet(&looped);
    assert_all_ranges_within_packet(&truncated);
}

#[test]
fn rejects_an_expanded_name_beyond_255_wire_bytes() {
    let label = [b'x'; 63];
    let mut oversized_name = Vec::new();
    for _ in 0..4 {
        oversized_name.push(63);
        oversized_name.extend(label);
    }
    oversized_name.push(0);
    let mut message = dns_header(0x0100, 1, 0, 0, 0);
    append_question(&mut message, &oversized_name, TYPE_A, CLASS_IN);
    let dataset = decode(&udp_packet(&message, CLIENT_PORT, DNS_PORT));

    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(fields_named(&dataset, "dns_question").count(), 0);
    assert_relative_range(
        dataset.diagnostics()[0]
            .byte_range
            .expect("long name has evidence"),
        UDP_DNS_OFFSET + 12 + 3 * 64,
        1,
    );
    assert_all_ranges_within_packet(&dataset);
}

fn pointer_chain_message(overflow_in_rdata: bool) -> Vec<u8> {
    let answer_type = if overflow_in_rdata {
        TYPE_CNAME
    } else {
        TYPE_A
    };
    let mut message = dns_header(0x8180, 16, 1, 0, 0);
    let mut previous_offset = message.len();
    append_question(&mut message, &wire_name(&[b"a"]), answer_type, CLASS_IN);
    for _ in 1..16 {
        let current_offset = message.len();
        append_question(
            &mut message,
            &pointer(previous_offset),
            answer_type,
            CLASS_IN,
        );
        previous_offset = current_offset;
    }
    let answer_offset = message.len();
    let rdata = if overflow_in_rdata {
        pointer(answer_offset).to_vec()
    } else {
        vec![192, 0, 2, 1]
    };
    append_record(&mut message, &pointer(previous_offset), answer_type, &rdata);
    message
}

#[test]
fn accepts_sixteen_pointer_hops_and_rejects_the_seventeenth() {
    let maximum = pointer_chain_message(false);
    let maximum = decode(&udp_packet(&maximum, DNS_PORT, CLIENT_PORT));
    assert!(maximum.diagnostics().is_empty());
    assert_eq!(fields_named(&maximum, "dns_question").count(), 16);
    assert_eq!(fields_named(&maximum, "dns_answer").count(), 1);

    let overflow = pointer_chain_message(true);
    let overflow = decode(&udp_packet(&overflow, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&overflow),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );
    assert!(overflow.diagnostics()[0].byte_range.is_some());
    assert_all_ranges_within_packet(&maximum);
    assert_all_ranges_within_packet(&overflow);
}

#[test]
fn distinguishes_header_question_record_and_rdata_truncation() {
    let header = dns_header(0x0100, 0, 0, 0, 0);
    for cutoff in 0..12 {
        let dataset = decode(&udp_packet(&header[..cutoff], CLIENT_PORT, DNS_PORT));
        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::TRUNCATED_PROTOCOL),
            "header cutoff {cutoff}"
        );
        assert_dns_ranges_within(
            &dataset,
            UDP_DNS_OFFSET,
            u32::try_from(cutoff).expect("cutoff fits u32"),
        );
    }

    let query = simple_query();
    let question = decode(&udp_packet(
        &query[..query.len() - 1],
        CLIENT_PORT,
        DNS_PORT,
    ));
    assert_eq!(
        diagnostic_code(&question),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(fields_named(&question, "dns_question").count(), 0);

    let mut record = dns_header(0x8180, 0, 1, 0, 0);
    record.extend([0, 0, 1, 0, 1, 0, 0, 1]);
    let record = decode(&udp_packet(&record, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&record),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(fields_named(&record, "dns_answer").count(), 0);

    let mut rdata = dns_header(0x8180, 0, 1, 0, 0);
    append_record_with_length(&mut rdata, &[0], TYPE_A, 4, &[192, 0, 2]);
    let rdata = decode(&udp_packet(&rdata, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&rdata),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_relative_range(
        rdata.diagnostics()[0]
            .byte_range
            .expect("RDLENGTH overrun has evidence"),
        UDP_DNS_OFFSET + 21,
        2,
    );
    assert_all_ranges_within_packet(&question);
    assert_all_ranges_within_packet(&record);
    assert_all_ranges_within_packet(&rdata);
}

#[test]
fn malformed_known_rdata_and_trailing_bytes_have_exact_evidence() {
    let mut wrong_a = dns_header(0x8180, 0, 1, 0, 0);
    append_record(&mut wrong_a, &[0], TYPE_A, &[192, 0, 2]);
    let wrong_a = decode(&udp_packet(&wrong_a, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&wrong_a),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        wrong_a.diagnostics()[0]
            .byte_range
            .expect("known RDATA mismatch has evidence"),
        UDP_DNS_OFFSET + 21,
        2,
    );

    let mut trailing = dns_header(0x0100, 0, 0, 0, 0);
    trailing.extend([0xde, 0xad]);
    let trailing = decode(&udp_packet(&trailing, CLIENT_PORT, DNS_PORT));
    assert_eq!(
        diagnostic_code(&trailing),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        trailing.diagnostics()[0]
            .byte_range
            .expect("trailing data has evidence"),
        UDP_DNS_OFFSET + 12,
        2,
    );
    assert_all_ranges_within_packet(&wrong_a);
    assert_all_ranges_within_packet(&trailing);
}

#[test]
fn rejects_malformed_common_rdata_without_emitting_the_current_record() {
    let mut short_soa = vec![0, 0];
    short_soa.extend([0; 16]);
    let cases = [
        ("AAAA length", TYPE_AAAA, vec![0; 15], "address"),
        (
            "name trailing byte",
            TYPE_CNAME,
            vec![0, 0xff],
            "canonical_name",
        ),
        ("SOA integers", TYPE_SOA, short_soa, "rdata"),
        ("MX preference", TYPE_MX, vec![0], "rdata"),
        ("TXT string length", TYPE_TXT, vec![2, b'a'], "text"),
    ];

    for (case, record_type, rdata, semantic_field) in cases {
        let mut message = dns_header(0x8180, 0, 1, 0, 0);
        append_record(&mut message, &[0], record_type, &rdata);
        let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

        assert_eq!(
            diagnostic_code(&dataset),
            Some(DiagnosticCode::MALFORMED_PROTOCOL),
            "{case}"
        );
        assert_eq!(fields_named(&dataset, "dns_answer").count(), 0, "{case}");
        assert_eq!(fields_named(&dataset, semantic_field).count(), 0, "{case}");
        assert!(dataset.diagnostics()[0].byte_range.is_some(), "{case}");
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn rejects_empty_txt_rdata_atomically() {
    let mut message = dns_header(0x8180, 0, 1, 0, 0);
    append_record(&mut message, &[0], TYPE_TXT, &[]);
    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 0);
    assert_eq!(fields_named(&dataset, "text").count(), 0);
    assert_relative_range(
        dataset.diagnostics()[0]
            .byte_range
            .expect("empty TXT has RDLENGTH evidence"),
        UDP_DNS_OFFSET + 21,
        2,
    );
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

fn maximum_name_occurrence_message() -> Vec<u8> {
    let mut message = dns_header(0x8180, 16, 16, 0, 0);
    let base_offset = message.len();
    append_question(&mut message, &wire_name(&[b"limit"]), TYPE_SOA, CLASS_IN);
    for _ in 1..16 {
        append_question(&mut message, &pointer(base_offset), TYPE_SOA, CLASS_IN);
    }
    for serial in 0_u32..16 {
        let mut soa = pointer(base_offset).to_vec();
        soa.extend(pointer(base_offset));
        for value in [serial, 3_600, 600, 86_400, 300] {
            soa.extend(value.to_be_bytes());
        }
        append_record(&mut message, &pointer(base_offset), TYPE_SOA, &soa);
    }
    message
}

#[test]
fn accepts_exactly_sixty_four_name_occurrences() {
    assert_eq!(MAX_DNS_NAMES_PER_PACKET, 64);
    let message = maximum_name_occurrence_message();
    let dataset = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert!(dataset.diagnostics().is_empty());
    assert_eq!(fields_named(&dataset, "dns_question").count(), 16);
    assert_eq!(fields_named(&dataset, "dns_answer").count(), 16);
    assert_eq!(fields_named(&dataset, "name").count(), 32);
    assert_eq!(fields_named(&dataset, "primary_name_server").count(), 16);
    assert_eq!(fields_named(&dataset, "responsible_mailbox").count(), 16);
    let emitted_name_occurrences = fields_named(&dataset, "name").count()
        + fields_named(&dataset, "primary_name_server").count()
        + fields_named(&dataset, "responsible_mailbox").count();
    assert_eq!(
        emitted_name_occurrences,
        usize::try_from(MAX_DNS_NAMES_PER_PACKET).expect("name ceiling fits usize")
    );
    assert_dns_ranges_within(
        &dataset,
        UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

fn maximum_aggregate_message() -> Vec<u8> {
    let mut message = dns_header(0x8180, 16, 16, 0, 0);
    let base_offset = message.len();
    append_question(&mut message, &wire_name(&[b"x"]), TYPE_TXT, CLASS_IN);
    for _ in 1..16 {
        append_question(&mut message, &pointer(base_offset), TYPE_TXT, CLASS_IN);
    }
    for _ in 0..16 {
        append_record(&mut message, &pointer(base_offset), TYPE_TXT, b"\x01a");
    }
    message
}

#[test]
fn enforces_sixteen_question_aggregate_record_and_txt_string_caps() {
    let maximum = maximum_aggregate_message();
    let maximum = decode(&udp_packet(&maximum, DNS_PORT, CLIENT_PORT));
    assert!(maximum.diagnostics().is_empty());
    assert_eq!(fields_named(&maximum, "dns_question").count(), 16);
    assert_eq!(fields_named(&maximum, "dns_answer").count(), 16);
    assert_eq!(fields_named(&maximum, "text").count(), 16);
    assert_all_ranges_within_packet(&maximum);

    let question_overflow = dns_header(0x0100, 17, 0, 0, 0);
    let question_overflow = decode(&udp_packet(&question_overflow, CLIENT_PORT, DNS_PORT));
    assert_eq!(
        diagnostic_code(&question_overflow),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );

    let record_overflow = dns_header(0x8180, 0, 16, 1, 0);
    let record_overflow = decode(&udp_packet(&record_overflow, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&record_overflow),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );

    let mut txt_overflow = dns_header(0x8180, 0, 1, 0, 0);
    let mut strings = Vec::with_capacity(34);
    for _ in 0..17 {
        strings.extend([1, b'a']);
    }
    append_record(&mut txt_overflow, &[0], TYPE_TXT, &strings);
    let txt_overflow = decode(&udp_packet(&txt_overflow, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&txt_overflow),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );
    assert!(fields_named(&txt_overflow, "text").count() <= 16);
    assert_all_ranges_within_packet(&question_overflow);
    assert_all_ranges_within_packet(&record_overflow);
    assert_all_ranges_within_packet(&txt_overflow);
}

#[test]
fn enforces_aggregate_count_arithmetic_and_the_global_txt_cap_across_records() {
    let maximum_counts = dns_header(0x8180, 0, u16::MAX, u16::MAX, u16::MAX);
    let maximum_counts = decode(&udp_packet(&maximum_counts, DNS_PORT, CLIENT_PORT));
    assert_eq!(
        diagnostic_code(&maximum_counts),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );
    assert_eq!(fields_named(&maximum_counts, "dns_answer").count(), 0);
    assert_relative_range(
        maximum_counts.diagnostics()[0]
            .byte_range
            .expect("oversized count has evidence"),
        UDP_DNS_OFFSET + 6,
        2,
    );

    let mut message = dns_header(0x8180, 0, 2, 0, 0);
    let mut first = Vec::new();
    for _ in 0..8 {
        first.extend([1, b'a']);
    }
    append_record(&mut message, &[0], TYPE_TXT, &first);
    let mut second = Vec::new();
    for _ in 0..9 {
        second.extend([1, b'b']);
    }
    append_record(&mut message, &[0], TYPE_TXT, &second);
    let txt_overflow = decode(&udp_packet(&message, DNS_PORT, CLIENT_PORT));

    assert_eq!(
        diagnostic_code(&txt_overflow),
        Some(DiagnosticCode::RESOURCE_LIMIT)
    );
    assert_eq!(fields_named(&txt_overflow, "dns_answer").count(), 1);
    assert_eq!(fields_named(&txt_overflow, "text").count(), 8);
    assert_all_ranges_within_packet(&maximum_counts);
    assert_all_ranges_within_packet(&txt_overflow);
}

#[test]
fn udp_dns_never_reads_bytes_beyond_the_declared_datagram() {
    let message = simple_query();
    let mut datagram = udp_with_declared_payload(&message[..12], CLIENT_PORT, DNS_PORT, 12);
    datagram.extend(&message[12..]);
    let dataset = decode(&ethernet(&ipv4(&datagram, 17)));

    assert_eq!(layer_names(&dataset), ["ethernet", "ipv4", "udp", "dns"]);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_eq!(fields_named(&dataset, "dns_question").count(), 0);
    assert_dns_ranges_within(&dataset, UDP_DNS_OFFSET, 12);
}

#[test]
fn accepts_exactly_one_tcp_frame_and_ignores_ambiguous_stream_payloads() {
    let message = simple_query();
    let frame = tcp_frame(&message);
    let exact = decode(&tcp_packet(&frame, CLIENT_PORT, DNS_PORT));
    assert_eq!(layer_names(&exact), ["ethernet", "ipv4", "tcp", "dns"]);
    assert!(exact.diagnostics().is_empty());
    assert_dns_ranges_within(
        &exact,
        TCP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );

    let mut split = Vec::new();
    split.extend(
        u16::try_from(message.len())
            .expect("message length fits u16")
            .to_be_bytes(),
    );
    split.extend(&message[..message.len() / 2]);
    let mut mismatch = Vec::new();
    mismatch.extend(
        u16::try_from(message.len() - 1)
            .expect("message length fits u16")
            .to_be_bytes(),
    );
    mismatch.extend(&message);
    let mut coalesced = frame.clone();
    coalesced.extend(&frame);
    for (case, payload) in [
        ("short prefix", vec![0]),
        ("split", split),
        ("mismatch", mismatch),
        ("coalesced", coalesced),
    ] {
        let dataset = decode(&tcp_packet(&payload, CLIENT_PORT, DNS_PORT));
        assert_eq!(layer_names(&dataset), ["ethernet", "ipv4", "tcp"], "{case}");
        assert!(dataset.diagnostics().is_empty(), "{case}");
        assert_eq!(fields_named(&dataset, "dns").count(), 0, "{case}");
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn dispatches_ipv6_udp_and_exact_tcp_dns_despite_checksum_findings() {
    let message = simple_query();

    let udp = decode(&ipv6_udp_packet(&message, CLIENT_PORT, DNS_PORT));
    assert_eq!(layer_names(&udp), ["ethernet", "ipv6", "udp", "dns"]);
    assert!(udp.diagnostics().is_empty());
    assert_eq!(
        one_field(&udp, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_dns_ranges_within(
        &udp,
        IPV6_UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );

    let frame = tcp_frame(&message);
    let tcp = decode(&ipv6_tcp_packet(&frame, CLIENT_PORT, DNS_PORT));
    assert_eq!(layer_names(&tcp), ["ethernet", "ipv6", "tcp", "dns"]);
    assert!(tcp.diagnostics().is_empty());
    assert_eq!(
        one_field(&tcp, "checksum_valid").value,
        FieldValue::Boolean(true)
    );
    assert_dns_ranges_within(
        &tcp,
        IPV6_TCP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );

    let mut damaged_datagram =
        udp_with_declared_payload(&message, CLIENT_PORT, DNS_PORT, message.len());
    set_udp_checksum_v6(&mut damaged_datagram);
    damaged_datagram[7] ^= 1;
    let damaged = decode(&ethernet_with_type(0x86dd, &ipv6(&damaged_datagram, 17)));
    assert_eq!(layer_names(&damaged), ["ethernet", "ipv6", "udp", "dns"]);
    assert_eq!(
        diagnostic_code(&damaged),
        Some(DiagnosticCode::INVALID_PROTOCOL_CHECKSUM)
    );
    assert_eq!(fields_named(&damaged, "dns_question").count(), 1);
    assert_eq!(
        one_field(&damaged, "checksum_valid").value,
        FieldValue::Boolean(false)
    );
    assert_dns_ranges_within(
        &damaged,
        IPV6_UDP_DNS_OFFSET,
        u32::try_from(message.len()).expect("message length fits u32"),
    );
}

#[test]
fn non_dns_ports_are_not_heuristically_decoded() {
    let message = simple_query();
    let udp = decode(&udp_packet(&message, CLIENT_PORT, 5353));
    assert_eq!(layer_names(&udp), ["ethernet", "ipv4", "udp"]);
    assert!(udp.diagnostics().is_empty());

    let tcp = decode(&tcp_packet(&tcp_frame(&message), CLIENT_PORT, 5353));
    assert_eq!(layer_names(&tcp), ["ethernet", "ipv4", "tcp"]);
    assert!(tcp.diagnostics().is_empty());
    assert_all_ranges_within_packet(&udp);
    assert_all_ranges_within_packet(&tcp);
}

#[test]
fn one_prioritized_dns_diagnostic_wins_and_uses_exact_bounded_evidence() {
    let mut malformed = dns_header(0x0100, 1, 0, 0, 0);
    append_question(&mut malformed, &pointer(12), TYPE_A, CLASS_IN);
    let frame = tcp_frame(&malformed);
    let mut segment = tcp(&frame, CLIENT_PORT, DNS_PORT);
    segment[16] ^= 1;
    let dataset = decode(&ethernet(&ipv4(&segment, 6)));

    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        diagnostic_code(&dataset),
        Some(DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_relative_range(
        dataset.diagnostics()[0]
            .byte_range
            .expect("pointer fault has evidence"),
        TCP_DNS_OFFSET + 12,
        2,
    );
    assert_dns_ranges_within(
        &dataset,
        TCP_DNS_OFFSET,
        u32::try_from(malformed.len()).expect("message length fits u32"),
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bounded_dns_payloads_never_escape_the_packet(payload in prop::collection::vec(any::<u8>(), 0..512)) {
        let dataset = decode(&udp_packet(&payload, CLIENT_PORT, DNS_PORT));
        prop_assert_eq!(layer_names(&dataset).last().copied(), Some("dns"));
        prop_assert!(dataset.diagnostics().len() <= 1);
        assert_dns_ranges_within(
            &dataset,
            UDP_DNS_OFFSET,
            u32::try_from(payload.len()).expect("payload length fits u32"),
        );
    }
}
