use packet_core::{
    ByteOrder, ByteRange, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata,
    DecodedField, Diagnostic, DiagnosticCode, DiagnosticScope, FieldId, FieldValue, IndexRange,
    InterfaceId, InterfaceMetadata, LayerFact, LinkType, PacketId, PacketRecord,
    PacketRelativeRange, Recovery, SectionId, SectionMetadata, Severity, StringId,
    TimestampResolution,
};
use wasm_adapter::{
    API_VERSION, BoundaryErrorCode, BoundaryState, MAX_PACKET_DETAIL_BYTES,
    MAX_PACKET_EVIDENCE_BYTES, MIN_PACKET_DETAIL_BYTES, PACKET_DETAIL_SCHEMA_VERSION,
};

const ABSENT: u32 = u32::MAX;

fn range(start: u64, length: u32) -> ByteRange {
    ByteRange::new(start, length).expect("test range is valid")
}

#[allow(clippy::too_many_lines)] // Keeping the adversarial field/value fixture auditable is useful.
fn detail_dataset() -> CaptureDataset {
    let bytes = (0_u8..128).collect::<Vec<_>>().into_boxed_slice();
    CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: 128,
            packet_count: 1,
            started_at: None,
            ended_at: None,
        },
        bytes,
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 128),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 1).expect("interface span"),
        }]
        .into_boxed_slice(),
        interfaces: vec![InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: range(0, 24),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: 65_535,
            timestamp_resolution: TimestampResolution::Decimal(6),
            name: None,
        }]
        .into_boxed_slice(),
        packets: vec![PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: 40,
            original_length: 48,
            data: range(40, 40),
            layers: IndexRange::new(0, 2).expect("layer span"),
            diagnostics: IndexRange::new(0, 1).expect("diagnostic span"),
        }]
        .into_boxed_slice(),
        layers: vec![
            LayerFact {
                protocol: StringId(0),
                byte_range: range(40, 16),
                root_field: Some(FieldId(0)),
            },
            LayerFact {
                protocol: StringId(1),
                byte_range: range(56, 24),
                root_field: Some(FieldId(6)),
            },
        ]
        .into_boxed_slice(),
        fields: vec![
            DecodedField {
                name: StringId(2),
                value: FieldValue::None,
                byte_range: range(40, 16),
                children: IndexRange::new(0, 5).expect("first root children"),
            },
            DecodedField {
                name: StringId(3),
                value: FieldValue::Unsigned(u64::MAX),
                byte_range: range(40, 2),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(4),
                value: FieldValue::Signed(-2),
                byte_range: range(42, 2),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(5),
                value: FieldValue::Boolean(true),
                byte_range: range(44, 1),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(6),
                value: FieldValue::String(StringId(7)),
                byte_range: range(45, 3),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(8),
                value: FieldValue::Bytes(range(48, 4)),
                byte_range: range(47, 6),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(9),
                value: FieldValue::None,
                byte_range: range(56, 24),
                children: IndexRange::new(5, 2).expect("second root children"),
            },
            DecodedField {
                name: StringId(10),
                value: FieldValue::None,
                byte_range: range(60, 8),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(11),
                value: FieldValue::None,
                byte_range: range(80, 0),
                children: IndexRange::default(),
            },
        ]
        .into_boxed_slice(),
        field_children: vec![
            FieldId(1),
            FieldId(2),
            FieldId(3),
            FieldId(4),
            FieldId(5),
            FieldId(7),
            FieldId(8),
        ]
        .into_boxed_slice(),
        diagnostics: vec![Diagnostic {
            code: DiagnosticCode::TRUNCATED_PROTOCOL,
            severity: Severity::Warning,
            scope: DiagnosticScope::Packet(PacketId(0)),
            byte_range: Some(range(80, 0)),
            message: StringId(12),
            recovery: Recovery::Continued,
        }]
        .into_boxed_slice(),
        strings: [
            "ethernet",
            "test",
            "first_root",
            "unsigned",
            "signed",
            "boolean",
            "string",
            "value.example",
            "bytes",
            "second_root",
            "overlap",
            "truncated_marker",
            "protocol truncated safely",
        ]
        .map(Box::from)
        .into(),
    })
    .expect("packet-detail fixture is canonical")
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 bytes"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 bytes"))
}

fn descriptor(bytes: &[u8], column_index: usize) -> (usize, usize, usize) {
    let descriptor = 80 + column_index * 24;
    assert_eq!(
        read_u16(bytes, descriptor),
        u16::try_from(column_index + 1).expect("detail column ID fits u16")
    );
    let width = read_u32(bytes, descriptor + 4) as usize;
    let offset = read_u32(bytes, descriptor + 8) as usize;
    let count = read_u32(bytes, descriptor + 12) as usize;
    assert_eq!(read_u32(bytes, descriptor + 16) as usize, width * count);
    assert_eq!(read_u32(bytes, descriptor + 20), 0);
    (offset, width, count)
}

fn column_u8(bytes: &[u8], column_index: usize, row: usize) -> u8 {
    let (offset, width, count) = descriptor(bytes, column_index);
    assert_eq!(width, 1);
    assert!(row < count);
    bytes[offset + row]
}

fn column_u32(bytes: &[u8], column_index: usize, row: usize) -> u32 {
    let (offset, width, count) = descriptor(bytes, column_index);
    assert_eq!(width, 4);
    assert!(row < count);
    read_u32(bytes, offset + row * width)
}

fn column_u64(bytes: &[u8], column_index: usize, row: usize) -> u64 {
    let (offset, width, count) = descriptor(bytes, column_index);
    assert_eq!(width, 8);
    assert!(row < count);
    read_u64(bytes, offset + row * width)
}

#[test]
fn detail_encoding_is_packet_relative_typed_and_dictionary_bounded() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(detail_dataset())
        .expect("dataset registers");
    let detail = state
        .read_packet_detail(
            dataset,
            PacketId(0),
            u32::try_from(MAX_PACKET_DETAIL_BYTES).expect("detail cap fits u32"),
        )
        .expect("detail encodes");
    let bytes = detail.bytes();

    assert_eq!(&bytes[0..8], b"WLPKDT01");
    assert_eq!(read_u16(bytes, 8), PACKET_DETAIL_SCHEMA_VERSION);
    assert_eq!(read_u16(bytes, 10), 80);
    assert_eq!(read_u32(bytes, 12), API_VERSION);
    assert_eq!(read_u16(bytes, 16), 24);
    assert_eq!(read_u16(bytes, 18), 20);
    assert_eq!(read_u32(bytes, 20), 3);
    assert_eq!(read_u32(bytes, 24), 0);
    assert_eq!(read_u32(bytes, 28), 40);
    assert_eq!(read_u32(bytes, 32), 48);
    assert_eq!(read_u32(bytes, 36), 2);
    assert_eq!(read_u32(bytes, 40), 9);
    assert_eq!(read_u32(bytes, 44), 12);
    assert_eq!(read_u32(bytes, 48), 80);
    assert_eq!(read_u32(bytes, 52), 560);
    assert_eq!(read_u32(bytes, 56) as usize, bytes.len());
    assert!(read_u32(bytes, 60) > 0);
    assert_eq!(read_u64(bytes, 64), 40);
    assert_eq!(read_u32(bytes, 72), 40);
    assert_eq!(read_u32(bytes, 76), 0);
    assert!(bytes.len() <= MAX_PACKET_DETAIL_BYTES);

    assert_eq!(column_u32(bytes, 0, 0), 0);
    assert_eq!(column_u32(bytes, 1, 1), 16);
    assert_eq!(column_u32(bytes, 2, 1), 24);
    assert_eq!(column_u32(bytes, 3, 1), 6);
    assert_eq!(column_u32(bytes, 4, 8), 8);
    assert_eq!(column_u32(bytes, 5, 0), ABSENT);
    assert_eq!(column_u32(bytes, 5, 8), 6);
    assert_eq!(column_u32(bytes, 6, 8), 1);
    assert_eq!(column_u32(bytes, 7, 8), 1);
    assert_eq!(column_u32(bytes, 9, 8), 40);
    assert_eq!(column_u32(bytes, 10, 8), 0);

    assert_eq!(column_u8(bytes, 18, 0), 0);
    assert_eq!(column_u8(bytes, 18, 1), 1);
    assert_eq!(column_u64(bytes, 17, 1), u64::MAX);
    assert_eq!(column_u8(bytes, 18, 2), 2);
    assert_eq!(column_u64(bytes, 17, 2), u64::MAX - 1);
    assert_eq!(column_u8(bytes, 18, 3), 3);
    assert_eq!(column_u64(bytes, 17, 3), 1);
    assert_eq!(column_u8(bytes, 18, 4), 4);
    assert_eq!(column_u32(bytes, 11, 4), 7);
    assert_eq!(column_u8(bytes, 18, 5), 5);
    assert_eq!(column_u32(bytes, 12, 5), 8);
    assert_eq!(column_u32(bytes, 13, 5), 4);

    for row in 0..12 {
        assert_eq!(
            column_u32(bytes, 14, row),
            u32::try_from(row).expect("dictionary row fits u32")
        );
    }
    let (blob_offset, blob_width, blob_count) = descriptor(bytes, 19);
    assert_eq!(blob_width, 1);
    assert_eq!(blob_count, read_u32(bytes, 60) as usize);
    let blob = std::str::from_utf8(&bytes[blob_offset..blob_offset + blob_count])
        .expect("dictionary blob is UTF-8");
    assert!(blob.contains("value.example"));
    assert!(!blob.contains("protocol truncated safely"));
}

#[test]
fn detail_requests_reject_invalid_budgets_packets_and_handle_kinds() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(detail_dataset())
        .expect("dataset registers");
    assert_eq!(
        state
            .read_packet_detail(
                dataset,
                PacketId(0),
                u32::try_from(MIN_PACKET_DETAIL_BYTES - 1)
                    .expect("undersized detail envelope fits u32"),
            )
            .expect_err("undersized envelope is rejected")
            .code(),
        BoundaryErrorCode::INVALID_ARGUMENT
    );
    assert_eq!(
        state
            .read_packet_detail(
                dataset,
                PacketId(0),
                u32::try_from(MIN_PACKET_DETAIL_BYTES).expect("minimum detail bytes fit u32"),
            )
            .expect_err("complete detail does not fit the envelope alone")
            .code(),
        BoundaryErrorCode::BATCH_BYTE_LIMIT
    );
    assert_eq!(
        state
            .read_packet_detail(
                dataset,
                PacketId(1),
                u32::try_from(MAX_PACKET_DETAIL_BYTES).expect("detail cap fits u32"),
            )
            .expect_err("unknown packet is rejected")
            .code(),
        BoundaryErrorCode::INVALID_ARGUMENT
    );
    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("cursor opens");
    assert_eq!(
        state
            .read_packet_detail(
                cursor,
                PacketId(0),
                u32::try_from(MAX_PACKET_DETAIL_BYTES).expect("detail cap fits u32"),
            )
            .expect_err("cursor cannot stand in for a dataset")
            .code(),
        BoundaryErrorCode::WRONG_HANDLE_KIND
    );
}

#[test]
fn evidence_pages_are_relative_bounded_and_never_cross_the_packet() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(detail_dataset())
        .expect("dataset registers");

    let page = state
        .read_packet_evidence(dataset, PacketId(0), 8, 4)
        .expect("relative evidence page succeeds");
    assert_eq!(page.offset(), 48);
    assert_eq!(page.bytes(), &[48, 49, 50, 51]);

    let tail = state
        .read_packet_evidence(dataset, PacketId(0), 38, MAX_PACKET_EVIDENCE_BYTES)
        .expect("tail page is clamped to captured bytes");
    assert_eq!(tail.bytes(), &[78, 79]);
    let end = state
        .read_packet_evidence(dataset, PacketId(0), 40, 1)
        .expect("captured end is a valid empty boundary");
    assert!(end.bytes().is_empty());
    assert_eq!(end.offset(), 80);

    for (start, budget) in [(41, 1), (0, 0), (0, MAX_PACKET_EVIDENCE_BYTES + 1)] {
        assert!(
            state
                .read_packet_evidence(dataset, PacketId(0), start, budget)
                .is_err()
        );
    }
    assert_eq!(
        state
            .read_packet_evidence(dataset, PacketId(1), 0, 1)
            .expect_err("unknown packet is rejected")
            .code(),
        BoundaryErrorCode::INVALID_ARGUMENT
    );
}

#[test]
fn correlation_returns_all_matches_primary_first_and_rejects_missing_bytes() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(detail_dataset())
        .expect("dataset registers");
    let selection = PacketRelativeRange::new(20, 1).expect("selection range");
    let matches = state
        .correlate_packet_range(dataset, PacketId(0), selection)
        .expect("selection correlates");
    assert_eq!(
        matches
            .matches()
            .iter()
            .map(|field| field.field_id)
            .collect::<Vec<_>>(),
        [FieldId(7), FieldId(6)]
    );

    let marker = state
        .correlate_packet_range(
            dataset,
            PacketId(0),
            PacketRelativeRange::new(40, 0).expect("end marker range"),
        )
        .expect("zero-length boundary correlates");
    assert_eq!(
        marker.primary().map(|field| field.field_id),
        Some(FieldId(8))
    );
    assert_eq!(
        state
            .correlate_packet_range(
                dataset,
                PacketId(0),
                PacketRelativeRange::new(40, 1).expect("representable missing-byte range"),
            )
            .expect_err("missing wire bytes are rejected")
            .code(),
        BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE
    );
}
