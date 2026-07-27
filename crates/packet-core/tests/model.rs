use core::mem::size_of;

use packet_core::{
    ByteOrder, ByteRange, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata,
    CaptureTimestamp, DecodedField, Diagnostic, DiagnosticCode, DiagnosticScope, FieldId,
    FieldValue, IndexRange, InterfaceId, InterfaceMetadata, LayerFact, LinkType, ModelError,
    PacketId, PacketRecord, Recovery, SectionId, SectionMetadata, Severity, StringId,
    TimestampError, TimestampResolution,
};

fn range(start: u64, length: u32) -> ByteRange {
    ByteRange::new(start, length).expect("test range must be valid")
}

fn single_packet_parts(timestamp: Option<CaptureTimestamp>) -> CaptureDatasetParts {
    let timestamp_resolution = timestamp.map_or(
        TimestampResolution::Decimal(6),
        CaptureTimestamp::resolution,
    );
    CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: 100,
            packet_count: 1,
            started_at: timestamp,
            ended_at: timestamp,
        },
        bytes: vec![0; 100].into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 100),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 1).expect("valid interface span"),
        }]
        .into_boxed_slice(),
        interfaces: vec![InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: range(0, 24),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: 65_535,
            timestamp_resolution,
            name: None,
        }]
        .into_boxed_slice(),
        packets: vec![PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp,
            captured_length: 20,
            original_length: 20,
            data: range(40, 20),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        }]
        .into_boxed_slice(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    }
}

#[test]
fn retained_index_bytes_excludes_capture_and_counts_exact_arenas() {
    let mut parts = single_packet_parts(None);
    parts.interfaces[0].name = Some(StringId(0));
    parts.strings = vec![Box::from("interface-zero")].into_boxed_slice();
    let capture_bytes = parts.bytes.len();
    let dataset = CaptureDataset::from_parts(parts).expect("valid named-interface dataset");

    let expected = size_of::<SectionMetadata>()
        + size_of::<InterfaceMetadata>()
        + size_of::<PacketRecord>()
        + size_of::<Box<str>>()
        + "interface-zero".len();
    assert_eq!(
        dataset.retained_index_bytes(),
        Some(u64::try_from(expected).expect("test allocation fits u64"))
    );
    assert_eq!(dataset.bytes().len(), capture_bytes);
    assert_eq!(dataset.interned_string_count(), 1);
    assert_eq!(dataset.interned_string_bytes(), Some(14));
    assert_eq!(
        dataset.retained_packet_index_bytes(),
        Some(u64::try_from(size_of::<PacketRecord>()).expect("packet arena fits u64"))
    );
    assert_ne!(dataset.retained_index_bytes(), Some(capture_bytes as u64));
}

#[test]
fn byte_ranges_are_half_open_checked_and_nestable() {
    let packet = range(100, 64);
    assert_eq!(packet.end(), 164);
    assert_eq!(packet.child(14, 20), ByteRange::new(114, 20));
    assert!(packet.child(60, 8).is_none());
    assert!(ByteRange::new(u64::MAX, 1).is_none());
}

#[test]
fn timestamps_retain_decimal_and_binary_resolution() {
    let micros = CaptureTimestamp::new(1_700_000_000, 999_999, TimestampResolution::Decimal(6));
    let binary = CaptureTimestamp::new(1_700_000_000, 1_023, TimestampResolution::Binary(10));
    assert!(micros.is_ok());
    assert!(binary.is_ok());
    assert_eq!(
        CaptureTimestamp::new(0, 1_000_000, TimestampResolution::Decimal(6)),
        Err(TimestampError::FractionOutOfRange)
    );
    let high_resolution = CaptureTimestamp::new(
        0,
        u64::MAX,
        TimestampResolution::Decimal(TimestampResolution::MAX_EXPONENT),
    )
    .expect("a 64-bit counter remains exact below a 10^-127 denominator");
    assert_eq!(high_resolution.fraction(), u64::MAX);
    assert_eq!(
        high_resolution.resolution(),
        TimestampResolution::Decimal(127)
    );
    assert_eq!(
        CaptureTimestamp::new(0, 0, TimestampResolution::Binary(128)),
        Err(TimestampError::UnsupportedResolution)
    );
    assert_eq!(TimestampResolution::Decimal(20).ticks_per_second(), None);
}

#[test]
fn high_resolution_timestamp_extrema_are_compared_exactly() {
    let decimal = CaptureTimestamp::new(0, 1, TimestampResolution::Decimal(20))
        .expect("valid high decimal resolution");
    let binary = CaptureTimestamp::new(0, 1, TimestampResolution::Binary(64))
        .expect("valid high binary resolution");
    // 10^-20 is earlier than 2^-64; neither denominator fits in u64.
    assert!(decimal.cmp_instant(binary).is_lt());
    let dataset = CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::PcapNg,
            byte_length: 100,
            packet_count: 2,
            started_at: Some(decimal),
            ended_at: Some(binary),
        },
        bytes: vec![0; 100].into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 100),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 2).expect("valid interface span"),
        }]
        .into_boxed_slice(),
        interfaces: vec![
            InterfaceMetadata {
                id: InterfaceId(0),
                section_id: SectionId(0),
                byte_range: range(0, 20),
                section_index: 0,
                link_type: LinkType(1),
                snap_length: 65_535,
                timestamp_resolution: decimal.resolution(),
                name: None,
            },
            InterfaceMetadata {
                id: InterfaceId(1),
                section_id: SectionId(0),
                byte_range: range(20, 20),
                section_index: 1,
                link_type: LinkType(1),
                snap_length: 65_535,
                timestamp_resolution: binary.resolution(),
                name: None,
            },
        ]
        .into_boxed_slice(),
        packets: vec![
            PacketRecord {
                id: PacketId(0),
                section_id: SectionId(0),
                interface_id: InterfaceId(1),
                timestamp: Some(binary),
                captured_length: 10,
                original_length: 10,
                data: range(40, 10),
                layers: IndexRange::default(),
                diagnostics: IndexRange::default(),
            },
            PacketRecord {
                id: PacketId(1),
                section_id: SectionId(0),
                interface_id: InterfaceId(0),
                timestamp: Some(decimal),
                captured_length: 10,
                original_length: 10,
                data: range(50, 10),
                layers: IndexRange::default(),
                diagnostics: IndexRange::default(),
            },
        ]
        .into_boxed_slice(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    })
    .expect("exact comparison accepts the true extrema");

    assert_eq!(dataset.metadata().started_at, Some(decimal));
    assert_eq!(dataset.metadata().ended_at, Some(binary));
}

#[test]
fn validation_rejects_false_timestamp_extrema_and_interface_evidence() {
    let timestamp =
        CaptureTimestamp::new(10, 1, TimestampResolution::Decimal(6)).expect("valid timestamp");
    let mut parts = single_packet_parts(Some(timestamp));
    parts.metadata.ended_at = None;
    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::TimestampBounds)
    );

    let mut parts = single_packet_parts(None);
    parts.interfaces[0].byte_range = range(90, 20);
    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::ByteRange)
    );

    let mut parts = single_packet_parts(None);
    parts.interfaces[0].timestamp_resolution = TimestampResolution::Decimal(128);
    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::TimestampResolution)
    );
}

#[test]
fn packet_arena_spans_have_exclusive_scope_correct_ownership() {
    let mut parts = single_packet_parts(None);
    parts.metadata.packet_count = 2;
    parts.layers = vec![LayerFact {
        protocol: StringId(0),
        byte_range: range(40, 10),
        root_field: None,
    }]
    .into_boxed_slice();
    parts.strings = vec![Box::from("ethernet")].into_boxed_slice();
    parts.packets[0].layers = IndexRange::new(0, 1).expect("valid layer span");
    let mut second = parts.packets[0];
    second.id = PacketId(1);
    second.layers = IndexRange::new(0, 1).expect("overlapping layer span");
    parts.packets = vec![parts.packets[0], second].into_boxed_slice();
    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::ArenaOwnership)
    );

    let mut parts = single_packet_parts(None);
    parts.packets[0].diagnostics = IndexRange::new(0, 1).expect("valid diagnostic span");
    parts.diagnostics = vec![Diagnostic {
        code: DiagnosticCode::TRUNCATED_RECORD,
        severity: Severity::Warning,
        scope: DiagnosticScope::Capture,
        byte_range: Some(range(40, 10)),
        message: StringId(0),
        recovery: Recovery::Continued,
    }]
    .into_boxed_slice();
    parts.strings = vec![Box::from("capture warning")].into_boxed_slice();
    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::ArenaOwnership)
    );
}

#[test]
fn dataset_models_multi_interface_capture_and_packet_identity() {
    let packets = vec![PacketRecord {
        id: PacketId(0),
        section_id: SectionId(0),
        interface_id: InterfaceId(1),
        timestamp: CaptureTimestamp::new(10, 511, TimestampResolution::Binary(10)).ok(),
        captured_length: 60,
        original_length: 64,
        data: range(40, 60),
        layers: IndexRange::default(),
        diagnostics: IndexRange::new(0, 1).expect("valid diagnostic span"),
    }];
    let dataset = CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::PcapNg,
            byte_length: 100,
            packet_count: 1,
            started_at: packets[0].timestamp,
            ended_at: packets[0].timestamp,
        },
        bytes: vec![0; 100].into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 100),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 2).expect("valid interface span"),
        }]
        .into_boxed_slice(),
        interfaces: vec![
            InterfaceMetadata {
                id: InterfaceId(0),
                section_id: SectionId(0),
                byte_range: range(0, 20),
                section_index: 0,
                link_type: LinkType(1),
                snap_length: 65_535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                name: None,
            },
            InterfaceMetadata {
                id: InterfaceId(1),
                section_id: SectionId(0),
                byte_range: range(20, 20),
                section_index: 1,
                link_type: LinkType(101),
                snap_length: 4_096,
                timestamp_resolution: TimestampResolution::Binary(10),
                name: Some(StringId(0)),
            },
        ]
        .into_boxed_slice(),
        packets: packets.into_boxed_slice(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: vec![Diagnostic {
            code: DiagnosticCode::TRUNCATED_RECORD,
            severity: Severity::Warning,
            scope: DiagnosticScope::Packet(PacketId(0)),
            byte_range: Some(range(40, 60)),
            message: StringId(1),
            recovery: Recovery::Continued,
        }]
        .into_boxed_slice(),
        strings: vec![Box::from("raw-ip"), Box::from("record was truncated")].into_boxed_slice(),
    })
    .expect("valid multi-interface dataset");

    assert_eq!(dataset.packet(PacketId(0)), dataset.packets().first());
    assert!(dataset.packet(PacketId(1)).is_none());
    assert_eq!(dataset.string(StringId(0)), Some("raw-ip"));
    assert_eq!(
        dataset.interfaces()[1].timestamp_resolution,
        TimestampResolution::Binary(10)
    );
    assert_eq!(dataset.diagnostics()[0].recovery, Recovery::Continued);
    assert_eq!(dataset.validate(), Ok(()));
}

#[test]
fn validation_rejects_cross_section_interface_references() {
    let mut parts = CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::PcapNg,
            byte_length: 60,
            packet_count: 1,
            started_at: None,
            ended_at: None,
        },
        bytes: vec![0; 60].into_boxed_slice(),
        sections: vec![
            SectionMetadata {
                id: SectionId(0),
                byte_range: range(0, 30),
                byte_order: ByteOrder::LittleEndian,
                interfaces: IndexRange::new(0, 1).expect("valid interface span"),
            },
            SectionMetadata {
                id: SectionId(1),
                byte_range: range(30, 30),
                byte_order: ByteOrder::BigEndian,
                interfaces: IndexRange::new(1, 0).expect("valid empty interface span"),
            },
        ]
        .into_boxed_slice(),
        interfaces: vec![InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: range(0, 20),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: 65_535,
            timestamp_resolution: TimestampResolution::Decimal(6),
            name: None,
        }]
        .into_boxed_slice(),
        packets: vec![PacketRecord {
            id: PacketId(0),
            section_id: SectionId(1),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: 10,
            original_length: 10,
            data: range(40, 10),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        }]
        .into_boxed_slice(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    };

    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(packet_core::ModelError::PacketInterface)
    );
    parts = CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: 0,
            packet_count: 0,
            started_at: None,
            ended_at: None,
        },
        bytes: Box::default(),
        sections: Box::default(),
        interfaces: Box::default(),
        packets: Box::default(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    };
    assert!(CaptureDataset::from_parts(parts).is_ok());
}

#[test]
fn decoded_fields_form_a_forward_hierarchy_with_byte_evidence() {
    let fields = [
        DecodedField {
            name: StringId(0),
            value: FieldValue::None,
            byte_range: range(40, 20),
            children: IndexRange::new(0, 2).expect("valid child span"),
        },
        DecodedField {
            name: StringId(1),
            value: FieldValue::Unsigned(4),
            byte_range: range(40, 4),
            children: IndexRange::new(2, 1).expect("valid grandchild span"),
        },
        DecodedField {
            name: StringId(2),
            value: FieldValue::Bytes(range(50, 4)),
            byte_range: range(50, 4),
            children: IndexRange::default(),
        },
        DecodedField {
            name: StringId(3),
            value: FieldValue::Boolean(true),
            byte_range: range(41, 1),
            children: IndexRange::default(),
        },
    ];
    let child_ids = [FieldId(1), FieldId(2), FieldId(3)];

    assert_eq!(fields[0].children.start(), 0);
    assert_eq!(fields[0].children.length(), 2);
    assert_eq!(child_ids[fields[0].children.start() as usize], FieldId(1));
    assert_eq!(child_ids[fields[1].children.start() as usize], FieldId(3));
    assert!(fields[1].byte_range.is_within(fields[0].byte_range.end()));

    let mut parts = single_packet_parts(None);
    parts.packets[0].layers = IndexRange::new(0, 1).expect("valid layer span");
    parts.layers = vec![LayerFact {
        protocol: StringId(4),
        byte_range: range(40, 20),
        root_field: Some(FieldId(0)),
    }]
    .into_boxed_slice();
    parts.fields = fields.into();
    parts.field_children = child_ids.into();
    parts.strings = ["root", "version", "address", "flag", "ipv4"]
        .map(Box::from)
        .into();
    CaptureDataset::from_parts(parts).expect("valid field tree has one layer-owned root");
}

#[test]
fn raw_byte_values_must_remain_inside_their_field_evidence() {
    let mut parts = single_packet_parts(None);
    parts.packets[0].layers = IndexRange::new(0, 1).expect("valid layer span");
    parts.layers = vec![LayerFact {
        protocol: StringId(1),
        byte_range: range(40, 20),
        root_field: Some(FieldId(0)),
    }]
    .into_boxed_slice();
    parts.fields = vec![DecodedField {
        name: StringId(0),
        value: FieldValue::Bytes(range(48, 4)),
        byte_range: range(40, 4),
        children: IndexRange::default(),
    }]
    .into_boxed_slice();
    parts.strings = ["field", "test"].map(Box::from).into();

    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::ByteRange)
    );
}

#[test]
fn packet_diagnostic_evidence_must_remain_inside_its_packet() {
    let mut parts = single_packet_parts(None);
    parts.packets[0].diagnostics = IndexRange::new(0, 1).expect("diagnostic span");
    parts.diagnostics = vec![Diagnostic {
        code: DiagnosticCode::TRUNCATED_PROTOCOL,
        severity: Severity::Warning,
        scope: DiagnosticScope::Packet(PacketId(0)),
        byte_range: Some(range(39, 1)),
        message: StringId(0),
        recovery: Recovery::Continued,
    }]
    .into_boxed_slice();
    parts.strings = vec![Box::from("truncated protocol")].into_boxed_slice();

    assert_eq!(
        CaptureDataset::from_parts(parts),
        Err(ModelError::ArenaOwnership)
    );
}

#[test]
fn million_packet_index_has_a_bounded_metadata_estimate() {
    // Raw capture bytes are the dominant allocation. Packet metadata stays a
    // fixed-width arena and does not allocate one object graph per packet.
    let metadata_bytes = size_of::<PacketRecord>() * 1_000_000;
    assert!(metadata_bytes <= 96 * 1_000_000);
}

#[test]
fn dataset_debug_output_never_contains_capture_payload() {
    let dataset = CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: 6,
            packet_count: 0,
            started_at: None,
            ended_at: None,
        },
        bytes: b"secret".to_vec().into_boxed_slice(),
        sections: Box::default(),
        interfaces: Box::default(),
        packets: Box::default(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    })
    .expect("empty dataset is valid");

    let debug = format!("{dataset:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("[115, 101, 99"));
    assert!(debug.contains("packet_count"));
}
