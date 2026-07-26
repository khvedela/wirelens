//! Synthetic-only protocol decoder tests.
//!
//! Frames are constructed inline from protocol constants and contain no
//! captured third-party traffic.

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldValue, ImportLimits,
    ImportStep,
};
use proptest::prelude::*;
use protocol_decoders::{
    LINK_LAYER_MAX_FIELD_CHILDREN_PER_PACKET, LINK_LAYER_MAX_FIELDS_PER_PACKET,
    LINK_LAYER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder,
};

const PACKET_OFFSET: u64 = 40;

fn legacy_capture(link_type: u32, packet: &[u8]) -> Vec<u8> {
    let packet_length = u32::try_from(packet.len()).expect("synthetic packet length fits u32");
    let mut bytes = Vec::with_capacity(40 + packet.len());
    bytes.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend(2_u16.to_le_bytes());
    bytes.extend(4_u16.to_le_bytes());
    bytes.extend(0_i32.to_le_bytes());
    bytes.extend(0_u32.to_le_bytes());
    bytes.extend(65_535_u32.to_le_bytes());
    bytes.extend(link_type.to_le_bytes());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(2_u32.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet);
    bytes
}

fn decode_with_link(packet: &[u8], link_type: u32) -> CaptureDataset {
    let capture = legacy_capture(link_type, packet);
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
    decode_with_link(packet, 1)
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

fn decode_pcapng(packet: &[u8]) -> CaptureDataset {
    let mut importer = CaptureImporter::new_with_decoder(
        pcapng_capture(packet).into_boxed_slice(),
        ImportLimits::default(),
        Box::new(LinkLayerDecoder::new()),
    )
    .expect("synthetic PCAPNG is valid");
    loop {
        match importer
            .step(64, 1024 * 1024)
            .expect("bounded synthetic PCAPNG import succeeds")
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
    importer.finish().expect("decoded PCAPNG dataset validates")
}

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + payload.len());
    packet.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    packet.extend(ether_type.to_be_bytes());
    packet.extend(payload);
    packet
}

fn arp(operation: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(28);
    payload.extend(1_u16.to_be_bytes());
    payload.extend(0x0800_u16.to_be_bytes());
    payload.extend([6, 4]);
    payload.extend(operation.to_be_bytes());
    payload.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    payload.extend([192, 0, 2, 1]);
    payload.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    payload.extend([192, 0, 2, 2]);
    payload
}

fn vlan(inner_type: u16, payload: &[u8], pcp: u16, dei: bool, vid: u16) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(4 + payload.len());
    let tci = ((pcp & 0x7) << 13) | (u16::from(dei) << 12) | (vid & 0x0fff);
    tagged.extend(tci.to_be_bytes());
    tagged.extend(inner_type.to_be_bytes());
    tagged.extend(payload);
    ethernet(0x8100, &tagged)
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
    dataset.fields().iter().filter(move |field| {
        dataset
            .string(field.name)
            .is_some_and(|name| name == expected)
    })
}

fn one_field<'a>(dataset: &'a CaptureDataset, expected: &str) -> &'a packet_core::DecodedField {
    let mut fields = fields_named(dataset, expected);
    let field = fields.next().expect("field exists");
    assert!(fields.next().is_none(), "field {expected} is unique");
    field
}

fn assert_range(range: ByteRange, relative_start: u64, length: u32) {
    assert_eq!(range.start(), PACKET_OFFSET + relative_start);
    assert_eq!(range.length(), length);
}

fn assert_exact_field_ranges(dataset: &CaptureDataset, expected: &[(&str, u64, u32)]) {
    assert_eq!(dataset.fields().len(), expected.len());
    for &(name, relative_start, length) in expected {
        let field = one_field(dataset, name);
        assert_range(field.byte_range, relative_start, length);
        if let FieldValue::Bytes(value_range) = field.value {
            assert_range(value_range, relative_start, length);
        }
    }
}

fn assert_exact_field_ranges_in_order(dataset: &CaptureDataset, expected: &[(&str, u64, u32)]) {
    assert_eq!(dataset.fields().len(), expected.len());
    for (field, &(name, relative_start, length)) in dataset.fields().iter().zip(expected) {
        assert_eq!(dataset.string(field.name), Some(name));
        assert_range(field.byte_range, relative_start, length);
        if let FieldValue::Bytes(value_range) = field.value {
            assert_range(value_range, relative_start, length);
        }
    }
}

fn assert_all_ranges_within_packet(dataset: &CaptureDataset) {
    let packet = dataset.packets()[0];
    assert!(dataset.layers().len() <= LINK_LAYER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= LINK_LAYER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= LINK_LAYER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
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

#[test]
fn advertised_per_packet_arena_ceilings_cover_the_largest_current_decode() {
    let mut unsupported_addressing = arp(1);
    unsupported_addressing[0..2].copy_from_slice(&2_u16.to_be_bytes());
    let dataset = decode(&vlan(0x0806, &unsupported_addressing, 7, true, 4095));

    assert_eq!(
        dataset.layers().len(),
        LINK_LAYER_MAX_LAYERS_PER_PACKET as usize
    );
    assert_eq!(
        dataset.fields().len(),
        LINK_LAYER_MAX_FIELDS_PER_PACKET as usize
    );
    assert_eq!(
        dataset.field_children().len(),
        LINK_LAYER_MAX_FIELD_CHILDREN_PER_PACKET as usize
    );
    assert_eq!(names(&dataset), ["ethernet", "vlan", "arp", "unsupported"]);
    assert!(dataset.diagnostics().is_empty());
    for (layer, (relative_start, length)) in
        dataset
            .layers()
            .iter()
            .zip([(0, 14), (12, 6), (18, 8), (18, 28)])
    {
        assert_range(layer.byte_range, relative_start, length);
    }
    assert_exact_field_ranges_in_order(
        &dataset,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("vlan", 12, 6),
            ("tag_protocol_identifier", 12, 2),
            ("tag_control_information", 14, 2),
            ("priority_code_point", 14, 2),
            ("drop_eligible", 14, 2),
            ("vlan_identifier", 14, 2),
            ("inner_ether_type", 16, 2),
            ("arp", 18, 8),
            ("hardware_type", 18, 2),
            ("protocol_type", 20, 2),
            ("hardware_address_length", 22, 1),
            ("protocol_address_length", 23, 1),
            ("operation", 24, 2),
            ("is_request", 24, 2),
            ("is_reply", 24, 2),
            ("unsupported_arp_addressing", 18, 28),
            ("hardware_type", 18, 2),
            ("protocol_type", 20, 2),
            ("hardware_address_length", 22, 1),
            ("protocol_address_length", 23, 1),
            ("data", 26, 20),
        ],
    );
    assert_all_ranges_within_packet(&dataset);
}

#[test]
fn decodes_ethernet_and_arp_request_with_exact_ranges() {
    let dataset = decode(&ethernet(0x0806, &arp(1)));
    assert_eq!(names(&dataset), ["ethernet", "arp"]);
    assert!(dataset.diagnostics().is_empty());
    assert_range(dataset.layers()[0].byte_range, 0, 14);
    assert_range(dataset.layers()[1].byte_range, 14, 28);
    assert_exact_field_ranges(
        &dataset,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("arp", 14, 28),
            ("hardware_type", 14, 2),
            ("protocol_type", 16, 2),
            ("hardware_address_length", 18, 1),
            ("protocol_address_length", 19, 1),
            ("operation", 20, 2),
            ("is_request", 20, 2),
            ("is_reply", 20, 2),
            ("sender_hardware_address", 22, 6),
            ("sender_protocol_address", 28, 4),
            ("target_hardware_address", 32, 6),
            ("target_protocol_address", 38, 4),
        ],
    );

    let destination = one_field(&dataset, "destination");
    assert_eq!(destination.value, FieldValue::Bytes(destination.byte_range));
    assert_range(destination.byte_range, 0, 6);
    assert_range(one_field(&dataset, "source").byte_range, 6, 6);
    let ether_type = one_field(&dataset, "ether_type");
    assert_eq!(ether_type.value, FieldValue::Unsigned(0x0806));
    assert_range(ether_type.byte_range, 12, 2);

    let operation = one_field(&dataset, "operation");
    assert_eq!(operation.value, FieldValue::Unsigned(1));
    assert_range(operation.byte_range, 20, 2);
    assert_eq!(
        one_field(&dataset, "is_request").value,
        FieldValue::Boolean(true)
    );
    assert_eq!(
        one_field(&dataset, "is_reply").value,
        FieldValue::Boolean(false)
    );
    assert_range(
        one_field(&dataset, "sender_hardware_address").byte_range,
        22,
        6,
    );
    assert_range(
        one_field(&dataset, "sender_protocol_address").byte_range,
        28,
        4,
    );
    assert_range(
        one_field(&dataset, "target_hardware_address").byte_range,
        32,
        6,
    );
    assert_range(
        one_field(&dataset, "target_protocol_address").byte_range,
        38,
        4,
    );

    for layer in dataset.layers() {
        let root = layer.root_field.expect("decoded layer has root");
        let children = &dataset.field_children()[dataset.fields()[root.0 as usize].children.start()
            as usize
            ..dataset.fields()[root.0 as usize].children.end() as usize];
        assert!(children.iter().all(|child| child.0 > root.0));
    }
}

#[test]
fn decodes_one_vlan_tag_and_arp_reply() {
    let dataset = decode(&vlan(0x0806, &arp(2), 5, true, 100));
    assert_eq!(names(&dataset), ["ethernet", "vlan", "arp"]);
    assert!(dataset.diagnostics().is_empty());

    assert_range(dataset.layers()[0].byte_range, 0, 14);
    assert_range(dataset.layers()[1].byte_range, 12, 6);
    assert_range(dataset.layers()[2].byte_range, 18, 28);
    assert_exact_field_ranges(
        &dataset,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("vlan", 12, 6),
            ("tag_protocol_identifier", 12, 2),
            ("tag_control_information", 14, 2),
            ("priority_code_point", 14, 2),
            ("drop_eligible", 14, 2),
            ("vlan_identifier", 14, 2),
            ("inner_ether_type", 16, 2),
            ("arp", 18, 28),
            ("hardware_type", 18, 2),
            ("protocol_type", 20, 2),
            ("hardware_address_length", 22, 1),
            ("protocol_address_length", 23, 1),
            ("operation", 24, 2),
            ("is_request", 24, 2),
            ("is_reply", 24, 2),
            ("sender_hardware_address", 26, 6),
            ("sender_protocol_address", 32, 4),
            ("target_hardware_address", 36, 6),
            ("target_protocol_address", 42, 4),
        ],
    );
    let tpid = one_field(&dataset, "tag_protocol_identifier");
    assert_eq!(tpid.value, FieldValue::Unsigned(0x8100));
    assert_range(tpid.byte_range, 12, 2);
    let pcp = one_field(&dataset, "priority_code_point");
    assert_eq!(pcp.value, FieldValue::Unsigned(5));
    assert_range(pcp.byte_range, 14, 2);
    assert_eq!(
        one_field(&dataset, "drop_eligible").value,
        FieldValue::Boolean(true)
    );
    assert_eq!(
        one_field(&dataset, "vlan_identifier").value,
        FieldValue::Unsigned(100)
    );
    assert_eq!(
        one_field(&dataset, "inner_ether_type").value,
        FieldValue::Unsigned(0x0806)
    );

    let operation = one_field(&dataset, "operation");
    assert_eq!(operation.value, FieldValue::Unsigned(2));
    assert_range(operation.byte_range, 24, 2);
    assert_eq!(
        one_field(&dataset, "is_request").value,
        FieldValue::Boolean(false)
    );
    assert_eq!(
        one_field(&dataset, "is_reply").value,
        FieldValue::Boolean(true)
    );
}

#[test]
fn decodes_vlan_arp_and_truncation_through_pcapng_framing() {
    let reply = decode_pcapng(&vlan(0x0806, &arp(2), 5, true, 100));
    assert_eq!(names(&reply), ["ethernet", "vlan", "arp"]);
    assert!(reply.diagnostics().is_empty());
    let packet_start = reply.packets()[0].data.start();
    assert_eq!(packet_start, 76);
    assert_eq!(
        one_field(&reply, "vlan_identifier").value,
        FieldValue::Unsigned(100)
    );
    assert_eq!(
        one_field(&reply, "vlan_identifier").byte_range,
        ByteRange::new(packet_start + 14, 2).expect("range is representable")
    );
    assert_eq!(
        one_field(&reply, "operation").byte_range,
        ByteRange::new(packet_start + 24, 2).expect("range is representable")
    );

    let full_arp = ethernet(0x0806, &arp(1));
    let truncated = decode_pcapng(&full_arp[..full_arp.len() - 1]);
    assert_eq!(names(&truncated), ["ethernet", "arp"]);
    assert!(
        truncated
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::TRUNCATED_PROTOCOL)
    );
    assert_all_ranges_within_packet(&truncated);
}

#[test]
fn unsupported_encapsulations_are_structured_without_diagnostics() {
    let ieee_802_3 = decode(&ethernet(100, &[1, 2, 3]));
    assert_eq!(names(&ieee_802_3), ["ethernet", "unsupported"]);
    assert!(ieee_802_3.diagnostics().is_empty());
    assert_range(ieee_802_3.layers()[0].byte_range, 0, 14);
    assert_range(ieee_802_3.layers()[1].byte_range, 12, 5);
    assert_exact_field_ranges_in_order(
        &ieee_802_3,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("ieee_802_3", 12, 5),
            ("length", 12, 2),
            ("data", 14, 3),
        ],
    );
    assert_all_ranges_within_packet(&ieee_802_3);

    let provider_vlan = decode(&ethernet(0x88a8, &[1, 2, 3, 4]));
    assert_eq!(names(&provider_vlan), ["ethernet", "unsupported"]);
    assert!(provider_vlan.diagnostics().is_empty());
    assert_range(provider_vlan.layers()[0].byte_range, 0, 14);
    assert_range(provider_vlan.layers()[1].byte_range, 12, 6);
    assert_exact_field_ranges_in_order(
        &provider_vlan,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("provider_vlan", 12, 6),
            ("encapsulation", 12, 2),
            ("data", 14, 4),
        ],
    );
    assert_all_ranges_within_packet(&provider_vlan);

    let stacked_vlan = decode(&vlan(0x8100, &[1, 2, 3], 0, false, 7));
    assert_eq!(names(&stacked_vlan), ["ethernet", "vlan", "unsupported"]);
    assert!(stacked_vlan.diagnostics().is_empty());
    for (layer, (relative_start, length)) in
        stacked_vlan
            .layers()
            .iter()
            .zip([(0, 14), (12, 6), (16, 5)])
    {
        assert_range(layer.byte_range, relative_start, length);
    }
    assert_exact_field_ranges_in_order(
        &stacked_vlan,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("vlan", 12, 6),
            ("tag_protocol_identifier", 12, 2),
            ("tag_control_information", 14, 2),
            ("priority_code_point", 14, 2),
            ("drop_eligible", 14, 2),
            ("vlan_identifier", 14, 2),
            ("inner_ether_type", 16, 2),
            ("stacked_vlan", 16, 5),
            ("encapsulation", 16, 2),
            ("data", 18, 3),
        ],
    );
    assert_all_ranges_within_packet(&stacked_vlan);

    let dataset = decode_with_link(&[1, 2, 3, 4], 147);
    assert!(names(&dataset).is_empty());
    assert!(dataset.fields().is_empty());
    assert!(dataset.diagnostics().is_empty());
}

#[test]
fn known_future_and_unknown_ether_types_stop_cleanly_at_the_type_field() {
    for ether_type in [0x0800_u16, 0x86dd, 0x88b5, 0xffff] {
        let dataset = decode(&ethernet(ether_type, &[0x42; 32]));
        assert_eq!(names(&dataset), ["ethernet"]);
        assert!(dataset.diagnostics().is_empty());
        assert_eq!(
            one_field(&dataset, "ether_type").value,
            FieldValue::Unsigned(u64::from(ether_type))
        );
    }
}

#[test]
fn every_ethernet_and_vlan_header_cutoff_is_diagnosed_without_invalid_ranges() {
    let full_ethernet = ethernet(0x0806, &arp(1));
    for length in 0..14 {
        let dataset = decode(&full_ethernet[..length]);
        assert_eq!(names(&dataset), ["ethernet"]);
        assert!(
            dataset
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_all_ranges_within_packet(&dataset);
    }

    let full_vlan = vlan(0x0806, &arp(1), 3, false, 4094);
    for length in 14..18 {
        let dataset = decode(&full_vlan[..length]);
        assert_eq!(names(&dataset), ["ethernet", "vlan"]);
        assert!(
            dataset
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_all_ranges_within_packet(&dataset);
    }
}

#[test]
fn every_arp_boundary_is_diagnosed_and_complete_fields_remain_exact() {
    let full_packet = ethernet(0x0806, &arp(1));
    for arp_length in 0..28 {
        let dataset = decode(&full_packet[..14 + arp_length]);
        assert_eq!(names(&dataset), ["ethernet", "arp"]);
        assert!(
            dataset
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::TRUNCATED_PROTOCOL)
        );
        assert_all_ranges_within_packet(&dataset);
        if arp_length >= 2 {
            assert_range(one_field(&dataset, "hardware_type").byte_range, 14, 2);
        }
        if arp_length >= 8 {
            assert_range(one_field(&dataset, "operation").byte_range, 20, 2);
        }
    }
}

#[test]
fn malformed_and_unsupported_arp_variants_are_bounded_and_visible() {
    let gap = decode(&ethernet(1501, &[0; 8]));
    assert!(
        gap.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MALFORMED_PROTOCOL)
    );
    assert_eq!(names(&gap), ["ethernet", "unsupported"]);

    let mut contradictory = arp(1);
    contradictory[4] = 5;
    contradictory.truncate(26);
    let contradictory = decode(&ethernet(0x0806, &contradictory));
    assert_eq!(names(&contradictory), ["ethernet", "arp", "unsupported"]);
    let malformed = contradictory
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DiagnosticCode::MALFORMED_PROTOCOL)
        .expect("contradictory address lengths are diagnosed");
    assert_range(
        malformed.byte_range.expect("malformed evidence is exact"),
        14,
        8,
    );
    assert_eq!(
        one_field(&contradictory, "unsupported_arp_addressing").value,
        FieldValue::None
    );

    let mut hostile_lengths = arp(1);
    hostile_lengths[4] = 255;
    hostile_lengths[5] = 255;
    let hostile_lengths = decode(&ethernet(0x0806, &hostile_lengths));
    assert_eq!(names(&hostile_lengths), ["ethernet", "arp"]);
    let malformed = hostile_lengths
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DiagnosticCode::MALFORMED_PROTOCOL)
        .expect("hostile contradictory lengths are diagnosed");
    assert_range(
        malformed.byte_range.expect("malformed evidence is exact"),
        14,
        8,
    );
    assert_all_ranges_within_packet(&hostile_lengths);

    let unsupported_operation = decode(&ethernet(0x0806, &arp(3)));
    assert_eq!(
        names(&unsupported_operation),
        ["ethernet", "arp", "unsupported"]
    );
    assert!(unsupported_operation.diagnostics().is_empty());
    for (layer, (relative_start, length)) in
        unsupported_operation
            .layers()
            .iter()
            .zip([(0, 14), (14, 28), (20, 2)])
    {
        assert_range(layer.byte_range, relative_start, length);
    }
    assert_exact_field_ranges_in_order(
        &unsupported_operation,
        &[
            ("ethernet", 0, 14),
            ("destination", 0, 6),
            ("source", 6, 6),
            ("ether_type", 12, 2),
            ("arp", 14, 28),
            ("hardware_type", 14, 2),
            ("protocol_type", 16, 2),
            ("hardware_address_length", 18, 1),
            ("protocol_address_length", 19, 1),
            ("operation", 20, 2),
            ("sender_hardware_address", 22, 6),
            ("sender_protocol_address", 28, 4),
            ("target_hardware_address", 32, 6),
            ("target_protocol_address", 38, 4),
            ("unsupported_arp_operation", 20, 2),
            ("operation", 20, 2),
        ],
    );
    assert_all_ranges_within_packet(&unsupported_operation);
}

proptest! {
    #[test]
    fn arbitrary_packet_lengths_never_escape_checked_ranges(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        link_type in prop_oneof![8 => Just(1_u32), 2 => any::<u32>()],
    ) {
        let dataset = decode_with_link(&bytes, link_type);
        assert_all_ranges_within_packet(&dataset);
    }

    #[test]
    fn every_ether_type_is_preserved_exactly(
        ether_type in any::<u16>(),
        tail in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let packet = ethernet(ether_type, &tail);
        let dataset = decode(&packet);
        let field = one_field(&dataset, "ether_type");
        prop_assert_eq!(field.value, FieldValue::Unsigned(u64::from(ether_type)));
        prop_assert_eq!(field.byte_range.start(), PACKET_OFFSET + 12);
        prop_assert_eq!(field.byte_range.length(), 2);
        assert_all_ranges_within_packet(&dataset);
    }
}
