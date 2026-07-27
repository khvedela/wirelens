use packet_core::{
    ByteOrder, ByteRange, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata,
    CorrelationError, DecodedField, FieldId, FieldValue, IndexRange, InterfaceId,
    InterfaceMetadata, LayerFact, LinkType, PacketId, PacketRecord, PacketRelativeRange, SectionId,
    SectionMetadata, StringId, TimestampResolution,
};
use proptest::prelude::*;

fn range(start: u64, length: u32) -> ByteRange {
    ByteRange::new(start, length).expect("test capture range is valid")
}

fn relative(start: u32, length: u32) -> PacketRelativeRange {
    PacketRelativeRange::new(start, length).expect("test packet range is valid")
}

fn correlation_dataset() -> CaptureDataset {
    CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: 64,
            packet_count: 1,
            started_at: None,
            ended_at: None,
        },
        bytes: vec![0; 64].into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 64),
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
            snap_length: 64,
            timestamp_resolution: TimestampResolution::Decimal(6),
            name: None,
        }]
        .into_boxed_slice(),
        packets: vec![PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: 12,
            original_length: 20,
            data: range(40, 12),
            layers: IndexRange::new(0, 1).expect("layer span"),
            diagnostics: IndexRange::default(),
        }]
        .into_boxed_slice(),
        layers: vec![LayerFact {
            protocol: StringId(5),
            byte_range: range(40, 12),
            root_field: Some(FieldId(0)),
        }]
        .into_boxed_slice(),
        fields: vec![
            DecodedField {
                name: StringId(0),
                value: FieldValue::None,
                byte_range: range(40, 12),
                children: IndexRange::new(0, 2).expect("root children"),
            },
            DecodedField {
                name: StringId(1),
                value: FieldValue::None,
                byte_range: range(43, 5),
                children: IndexRange::new(2, 2).expect("nested children"),
            },
            DecodedField {
                name: StringId(2),
                value: FieldValue::Unsigned(7),
                byte_range: range(44, 2),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(3),
                value: FieldValue::Boolean(true),
                byte_range: range(45, 3),
                children: IndexRange::default(),
            },
            DecodedField {
                name: StringId(4),
                value: FieldValue::None,
                byte_range: range(52, 0),
                children: IndexRange::default(),
            },
        ]
        .into_boxed_slice(),
        field_children: vec![FieldId(1), FieldId(4), FieldId(2), FieldId(3)].into_boxed_slice(),
        diagnostics: Box::default(),
        strings: ["root", "header", "exact", "overlap", "truncated", "test"]
            .map(Box::from)
            .into(),
    })
    .expect("correlation fixture is canonical")
}

#[test]
fn packet_paths_are_preorder_relative_and_bounded() {
    let dataset = correlation_dataset();
    let paths = dataset
        .packet_field_paths(PacketId(0), 5)
        .expect("exact field ceiling admits the packet");
    assert_eq!(
        paths.iter().map(|path| path.field_id).collect::<Vec<_>>(),
        [FieldId(0), FieldId(1), FieldId(2), FieldId(3), FieldId(4)]
    );
    assert_eq!(paths[2].parent_field_id, Some(FieldId(1)));
    assert_eq!(paths[2].depth, 2);
    assert_eq!(paths[2].byte_range, relative(4, 2));
    assert_eq!(paths[4].byte_range, relative(12, 0));
    assert_eq!(
        dataset.packet_field_paths(PacketId(0), 4),
        Err(CorrelationError::FieldLimitExceeded)
    );
    assert_eq!(
        dataset.packet_field_paths(PacketId(0), 0),
        Err(CorrelationError::FieldLimitExceeded)
    );
    assert_eq!(
        dataset.packet_field_paths(PacketId(1), 5),
        Err(CorrelationError::PacketNotFound)
    );
}

#[test]
fn correlation_orders_exact_containing_and_overlapping_fields_deterministically() {
    let dataset = correlation_dataset();
    let selection = dataset
        .correlate_packet_fields(PacketId(0), relative(4, 2), 5)
        .expect("valid selection");
    assert_eq!(
        selection.primary().map(|item| item.field_id),
        Some(FieldId(2))
    );
    assert_eq!(
        selection
            .matches()
            .iter()
            .map(|item| item.field_id)
            .collect::<Vec<_>>(),
        [FieldId(2), FieldId(1), FieldId(0), FieldId(3)]
    );

    let one_byte = dataset
        .correlate_packet_fields(PacketId(0), relative(5, 1), 5)
        .expect("valid one-byte selection");
    assert_eq!(
        one_byte
            .matches()
            .iter()
            .map(|item| item.field_id)
            .collect::<Vec<_>>(),
        [FieldId(2), FieldId(3), FieldId(1), FieldId(0)]
    );
}

#[test]
fn zero_length_and_truncated_packet_boundaries_never_select_missing_bytes() {
    let dataset = correlation_dataset();
    let insertion = dataset
        .correlate_packet_fields(PacketId(0), relative(12, 0), 5)
        .expect("captured end boundary is valid");
    assert_eq!(
        insertion
            .matches()
            .iter()
            .map(|item| item.field_id)
            .collect::<Vec<_>>(),
        [FieldId(4)]
    );
    assert_eq!(
        dataset.correlate_packet_fields(PacketId(0), relative(12, 1), 5),
        Err(CorrelationError::SelectionOutOfBounds)
    );
    assert!(PacketRelativeRange::new(u32::MAX, 1).is_none());
}

proptest! {
    #[test]
    fn arbitrary_relative_ranges_never_escape_captured_bytes(start in any::<u32>(), length in any::<u32>()) {
        let dataset = correlation_dataset();
        let Some(selection) = PacketRelativeRange::new(start, length) else {
            prop_assert!(start.checked_add(length).is_none());
            return Ok(());
        };
        let result = dataset.correlate_packet_fields(PacketId(0), selection, 5);
        if selection.end() > 12 {
            prop_assert_eq!(result, Err(CorrelationError::SelectionOutOfBounds));
        } else {
            let result = result.expect("in-bounds selection must resolve");
            for field in result.matches() {
                prop_assert!(field.byte_range.end() <= 12);
            }
        }
    }
}
