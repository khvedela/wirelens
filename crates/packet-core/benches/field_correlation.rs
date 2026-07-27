//! Directional worst-case packet-field correlation benchmark.
//!
//! The synthetic packet uses the browser boundary's 1,024-field ceiling. It
//! contains no capture-derived or proprietary bytes and prints local timing
//! evidence without claiming a universal machine-independent result.

use std::{hint::black_box, time::Instant};

use packet_core::{
    ByteOrder, ByteRange, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata,
    DecodedField, FieldId, FieldValue, IndexRange, InterfaceId, InterfaceMetadata, LayerFact,
    LinkType, PacketId, PacketRecord, PacketRelativeRange, SectionId, SectionMetadata, StringId,
    TimestampResolution,
};

const FIELD_COUNT: u32 = 1_024;
const ITERATIONS: u32 = 10_000;

fn main() {
    let dataset = dense_field_dataset();
    let selection = PacketRelativeRange::new(FIELD_COUNT / 2, 1).expect("benchmark selection");
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        let result = dataset
            .correlate_packet_fields(PacketId(0), black_box(selection), FIELD_COUNT)
            .expect("bounded benchmark query succeeds");
        black_box(result);
    }
    let elapsed = started.elapsed();
    let average_micros = elapsed.as_secs_f64() * 1_000_000.0 / f64::from(ITERATIONS);
    eprintln!(
        "field_correlation: {FIELD_COUNT} fields, {ITERATIONS} selections, {elapsed:?}, {average_micros:.2} us/query"
    );
}

fn range(start: u64, length: u32) -> ByteRange {
    ByteRange::new(start, length).expect("benchmark range is valid")
}

fn dense_field_dataset() -> CaptureDataset {
    const PACKET_START: u64 = 24;
    let packet_range = range(PACKET_START, FIELD_COUNT);
    let mut fields = Vec::with_capacity(
        usize::try_from(FIELD_COUNT).expect("benchmark field count fits the host pointer width"),
    );
    fields.push(DecodedField {
        name: StringId(0),
        value: FieldValue::None,
        byte_range: packet_range,
        children: IndexRange::new(0, FIELD_COUNT - 1).expect("child arena span"),
    });
    for index in 1..FIELD_COUNT {
        fields.push(DecodedField {
            name: StringId(0),
            value: FieldValue::Unsigned(u64::from(index)),
            byte_range: range(PACKET_START + u64::from(index - 1), 1),
            children: IndexRange::default(),
        });
    }
    let children = (1..FIELD_COUNT).map(FieldId).collect::<Vec<_>>();
    let capture_length = PACKET_START + u64::from(FIELD_COUNT);

    CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::Pcap,
            byte_length: capture_length,
            packet_count: 1,
            started_at: None,
            ended_at: None,
        },
        bytes: vec![
            0;
            usize::try_from(capture_length)
                .expect("benchmark capture length fits the host pointer width")
        ]
        .into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(
                0,
                u32::try_from(capture_length).expect("benchmark capture length fits u32"),
            ),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 1).expect("interface span"),
        }]
        .into_boxed_slice(),
        interfaces: vec![InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: range(
                0,
                u32::try_from(PACKET_START).expect("benchmark packet start fits u32"),
            ),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: FIELD_COUNT,
            timestamp_resolution: TimestampResolution::Decimal(6),
            name: None,
        }]
        .into_boxed_slice(),
        packets: vec![PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: FIELD_COUNT,
            original_length: FIELD_COUNT,
            data: packet_range,
            layers: IndexRange::new(0, 1).expect("layer span"),
            diagnostics: IndexRange::default(),
        }]
        .into_boxed_slice(),
        layers: vec![LayerFact {
            protocol: StringId(1),
            byte_range: packet_range,
            root_field: Some(FieldId(0)),
        }]
        .into_boxed_slice(),
        fields: fields.into_boxed_slice(),
        field_children: children.into_boxed_slice(),
        diagnostics: Box::default(),
        strings: ["field", "benchmark"].map(Box::from).into(),
    })
    .expect("benchmark dataset is canonical")
}
