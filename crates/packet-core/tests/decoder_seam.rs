use std::sync::{Arc, Mutex};

use packet_core::{
    ByteRange, CaptureDataset, CaptureImporter, DiagnosticCode, FieldId, FieldValue, ImportError,
    ImportLimitKind, ImportLimits, ImportStep, LinkType, ModelError, PacketDecodeInput,
    PacketDecodeSink, PacketDecoder, PacketId, Recovery, Severity,
};

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend(value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend(value.to_le_bytes());
}

fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len() + 12).expect("synthetic block length fits");
    assert_eq!(length % 4, 0);
    let mut output = Vec::new();
    push_u32(&mut output, block_type);
    push_u32(&mut output, length);
    output.extend(body);
    push_u32(&mut output, length);
    output
}

fn legacy_capture(payload: &[u8], original_length: u32) -> Vec<u8> {
    let captured_length = u32::try_from(payload.len()).expect("synthetic payload length fits");
    let mut output = Vec::new();
    output.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    push_u16(&mut output, 2);
    push_u16(&mut output, 4);
    push_u32(&mut output, 0);
    push_u32(&mut output, 0);
    push_u32(&mut output, 65_535);
    push_u32(&mut output, 1);
    push_u32(&mut output, 1);
    push_u32(&mut output, 2);
    push_u32(&mut output, captured_length);
    push_u32(&mut output, original_length);
    output.extend(payload);
    output
}

fn append_legacy_packet(output: &mut Vec<u8>, payload: &[u8]) {
    let length = u32::try_from(payload.len()).expect("synthetic payload length fits");
    push_u32(output, 2);
    push_u32(output, 3);
    push_u32(output, length);
    push_u32(output, length);
    output.extend(payload);
}

fn section_header() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend([0x4d, 0x3c, 0x2b, 0x1a]);
    push_u16(&mut body, 1);
    push_u16(&mut body, 0);
    body.extend((-1_i64).to_le_bytes());
    block(0x0a0d_0d0a, &body)
}

fn interface_description() -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 1);
    push_u16(&mut body, 0);
    push_u32(&mut body, 65_535);
    block(1, &body)
}

fn enhanced_packet(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("synthetic payload length fits");
    let mut body = Vec::new();
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    push_u32(&mut body, 1);
    push_u32(&mut body, length);
    push_u32(&mut body, length);
    body.extend(payload);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(6, &body)
}

fn simple_packet(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("synthetic payload length fits");
    let mut body = Vec::new();
    push_u32(&mut body, length);
    body.extend(payload);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(3, &body)
}

fn finish(mut importer: CaptureImporter) -> CaptureDataset {
    loop {
        match importer
            .step(32, u64::from(u32::MAX))
            .expect("synthetic decode import succeeds")
        {
            ImportStep::Progress(_) => {}
            ImportStep::NeedsBudget { minimum_bytes, .. } => {
                importer
                    .step(1, minimum_bytes)
                    .expect("reported budget makes progress");
            }
            ImportStep::Ready(_) => break,
        }
    }
    importer.finish().expect("decoded dataset validates")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenPacket {
    packet_id: PacketId,
    link_type: LinkType,
    data_range: ByteRange,
    bytes: Vec<u8>,
}

struct FactDecoder {
    seen: Arc<Mutex<Vec<SeenPacket>>>,
}

impl PacketDecoder for FactDecoder {
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError> {
        self.seen.lock().expect("seen lock").push(SeenPacket {
            packet_id: input.packet_id(),
            link_type: input.link_type(),
            data_range: input.data_range(),
            bytes: input.bytes().to_vec(),
        });
        let protocol = sink.intern("test-frame")?;
        let root_name = sink.intern("frame")?;
        let byte_name = sink.intern("first-byte")?;
        let message = sink.intern("synthetic decoder evidence")?;
        let root = sink.add_field(
            root_name,
            FieldValue::Bytes(input.data_range()),
            input.data_range(),
        )?;
        let first_byte = input
            .data_range()
            .child(0, 1)
            .ok_or(ImportError::Arithmetic)?;
        let child = sink.add_field(
            byte_name,
            FieldValue::Unsigned(u64::from(input.bytes()[0])),
            first_byte,
        )?;
        sink.set_field_children(root, &[child])?;
        sink.add_layer(protocol, input.data_range(), Some(root))?;
        sink.add_diagnostic(
            DiagnosticCode::UNSUPPORTED_PROTOCOL,
            Severity::Info,
            Recovery::Continued,
            Some(first_byte),
            message,
        )
    }
}

#[test]
fn decoder_receives_live_legacy_packet_bytes_and_publishes_exact_spans() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let importer = CaptureImporter::new_with_decoder(
        legacy_capture(&[0xaa, 0xbb, 0xcc], 3).into_boxed_slice(),
        ImportLimits::default(),
        Box::new(FactDecoder {
            seen: Arc::clone(&seen),
        }),
    )
    .expect("valid legacy capture");
    let dataset = finish(importer);

    assert_eq!(
        *seen.lock().expect("seen lock"),
        [SeenPacket {
            packet_id: PacketId(0),
            link_type: LinkType(1),
            data_range: ByteRange::new(40, 3).expect("range"),
            bytes: vec![0xaa, 0xbb, 0xcc],
        }]
    );
    assert_eq!(dataset.packets()[0].layers.length(), 1);
    assert_eq!(dataset.packets()[0].diagnostics.length(), 1);
    assert_eq!(dataset.layers()[0].byte_range, dataset.packets()[0].data);
    assert_eq!(dataset.layers()[0].root_field, Some(FieldId(0)));
    assert_eq!(dataset.fields()[0].children.length(), 1);
    assert_eq!(dataset.field_children(), &[FieldId(1)]);
    assert_eq!(
        dataset.diagnostics()[0].scope,
        packet_core::DiagnosticScope::Packet(PacketId(0))
    );
}

#[test]
fn decoder_runs_for_enhanced_and_simple_pcapng_packets_without_padding_bytes() {
    let mut bytes = section_header();
    bytes.extend(interface_description());
    bytes.extend(enhanced_packet(&[1, 2, 3]));
    bytes.extend(simple_packet(&[4, 5, 6, 7, 8]));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let importer = CaptureImporter::new_with_decoder(
        bytes.into_boxed_slice(),
        ImportLimits::default(),
        Box::new(FactDecoder {
            seen: Arc::clone(&seen),
        }),
    )
    .expect("valid pcapng capture");
    let dataset = finish(importer);

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].bytes, [1, 2, 3]);
    assert_eq!(seen[1].bytes, [4, 5, 6, 7, 8]);
    assert_eq!(seen[0].data_range, dataset.packets()[0].data);
    assert_eq!(seen[1].data_range, dataset.packets()[1].data);
    assert_eq!(
        dataset.packets()[0].layers,
        packet_core::IndexRange::new(0, 1).expect("span")
    );
    assert_eq!(
        dataset.packets()[1].layers,
        packet_core::IndexRange::new(1, 1).expect("span")
    );
    assert_eq!(dataset.packets()[0].diagnostics.length(), 1);
    assert_eq!(dataset.packets()[1].diagnostics.length(), 1);
    assert_eq!(dataset.field_children(), &[FieldId(1), FieldId(3)]);
}

struct FailOnceDecoder {
    failed: bool,
}

impl PacketDecoder for FailOnceDecoder {
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError> {
        if !self.failed {
            self.failed = true;
            let protocol = sink.intern("rolled-back-protocol")?;
            let field_name = sink.intern("rolled-back-field")?;
            let message = sink.intern("rolled-back-message")?;
            let parent = sink.add_field(field_name, FieldValue::None, input.data_range())?;
            let child = sink.add_field(field_name, FieldValue::None, input.data_range())?;
            sink.set_field_children(parent, &[child])?;
            sink.add_layer(protocol, input.data_range(), Some(parent))?;
            sink.add_diagnostic(
                DiagnosticCode::MALFORMED_PROTOCOL,
                Severity::Error,
                Recovery::Continued,
                Some(input.data_range()),
                message,
            )?;
            return Err(ImportError::Arithmetic);
        }
        let protocol = sink.intern("kept-protocol")?;
        sink.add_layer(protocol, input.data_range(), None)
    }
}

#[test]
fn decoder_error_rolls_back_outputs_but_keeps_container_diagnostics_for_retry() {
    let mut importer = CaptureImporter::new_with_decoder(
        legacy_capture(&[0xff], 0).into_boxed_slice(),
        ImportLimits::default(),
        Box::new(FailOnceDecoder { failed: false }),
    )
    .expect("valid inconsistent legacy record");

    assert_eq!(importer.step(32, 1_000), Err(ImportError::Arithmetic));
    let dataset = finish(importer);
    assert_eq!(dataset.layers().len(), 1);
    assert!(dataset.fields().is_empty());
    assert!(dataset.field_children().is_empty());
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INCONSISTENT_LENGTH
    );
    assert_eq!(dataset.packets()[0].diagnostics.length(), 1);
    assert_eq!(dataset.interned_string_count(), 2);
    assert_eq!(
        dataset.string(dataset.layers()[0].protocol),
        Some("kept-protocol")
    );
}

enum InvalidDecoder {
    OutsideRange,
    BytesOutsideField,
    OrphanField,
    TooManyLayers,
    TooManyFields,
    TooManyChildren,
}

impl PacketDecoder for InvalidDecoder {
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError> {
        let name = sink.intern("bounded")?;
        match self {
            Self::OutsideRange => sink.add_layer(
                name,
                ByteRange::new(input.data_range().end(), 1).ok_or(ImportError::Arithmetic)?,
                None,
            ),
            Self::BytesOutsideField => {
                let field_range = input
                    .data_range()
                    .child(0, 1)
                    .ok_or(ImportError::Arithmetic)?;
                let value_range = input
                    .data_range()
                    .child(1, 1)
                    .ok_or(ImportError::Arithmetic)?;
                sink.add_field(name, FieldValue::Bytes(value_range), field_range)?;
                Ok(())
            }
            Self::OrphanField => {
                sink.add_field(name, FieldValue::None, input.data_range())?;
                Ok(())
            }
            Self::TooManyLayers => {
                sink.add_layer(name, input.data_range(), None)?;
                sink.add_layer(name, input.data_range(), None)
            }
            Self::TooManyFields => {
                sink.add_field(name, FieldValue::None, input.data_range())?;
                sink.add_field(name, FieldValue::None, input.data_range())?;
                Ok(())
            }
            Self::TooManyChildren => {
                let parent = sink.add_field(name, FieldValue::None, input.data_range())?;
                let child_one = sink.add_field(name, FieldValue::None, input.data_range())?;
                let child_two = sink.add_field(name, FieldValue::None, input.data_range())?;
                sink.set_field_children(parent, &[child_one, child_two])
            }
        }
    }
}

fn one_packet_error(decoder: InvalidDecoder, limits: ImportLimits) -> ImportError {
    let mut importer = CaptureImporter::new_with_decoder(
        legacy_capture(&[1, 2, 3], 3).into_boxed_slice(),
        limits,
        Box::new(decoder),
    )
    .expect("valid bounded legacy capture");
    importer
        .step(32, 1_000)
        .expect_err("invalid decoder output is rejected")
}

#[test]
fn sink_rejects_malformed_ranges_and_incomplete_field_hierarchies() {
    assert_eq!(
        one_packet_error(InvalidDecoder::OutsideRange, ImportLimits::default()),
        ImportError::Model(ModelError::ByteRange)
    );
    assert_eq!(
        one_packet_error(InvalidDecoder::BytesOutsideField, ImportLimits::default()),
        ImportError::Model(ModelError::ByteRange)
    );
    assert_eq!(
        one_packet_error(InvalidDecoder::OrphanField, ImportLimits::default()),
        ImportError::Model(ModelError::FieldHierarchy)
    );
}

#[test]
fn sink_enforces_per_packet_layer_field_and_child_limits() {
    let layer_limits = ImportLimits {
        max_layers: 1,
        max_layers_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        one_packet_error(InvalidDecoder::TooManyLayers, layer_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::LayersPerPacket,
            limit: 1,
            ..
        }
    ));

    let field_limits = ImportLimits {
        max_fields: 1,
        max_fields_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        one_packet_error(InvalidDecoder::TooManyFields, field_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::FieldsPerPacket,
            limit: 1,
            ..
        }
    ));

    let child_limits = ImportLimits {
        max_field_children: 1,
        max_field_children_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        one_packet_error(InvalidDecoder::TooManyChildren, child_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::FieldChildrenPerPacket,
            limit: 1,
            ..
        }
    ));
}

enum OneFactPerPacket {
    Layer,
    Field,
    Child,
}

impl PacketDecoder for OneFactPerPacket {
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError> {
        let name = sink.intern("one-per-packet")?;
        match self {
            Self::Layer => sink.add_layer(name, input.data_range(), None),
            Self::Field => {
                let field = sink.add_field(name, FieldValue::None, input.data_range())?;
                sink.add_layer(name, input.data_range(), Some(field))
            }
            Self::Child => {
                let parent = sink.add_field(name, FieldValue::None, input.data_range())?;
                let child = sink.add_field(name, FieldValue::None, input.data_range())?;
                sink.set_field_children(parent, &[child])?;
                sink.add_layer(name, input.data_range(), Some(parent))
            }
        }
    }
}

fn two_packet_error(decoder: OneFactPerPacket, limits: ImportLimits) -> ImportError {
    let mut bytes = legacy_capture(&[1], 1);
    append_legacy_packet(&mut bytes, &[2]);
    let mut importer =
        CaptureImporter::new_with_decoder(bytes.into_boxed_slice(), limits, Box::new(decoder))
            .expect("valid two-packet legacy capture");
    importer
        .step(32, 1_000)
        .expect_err("capture-wide decode ceiling rejects the second packet")
}

#[test]
fn sink_enforces_capture_wide_limits_across_packets() {
    let layer_limits = ImportLimits {
        max_layers: 1,
        max_layers_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        two_packet_error(OneFactPerPacket::Layer, layer_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::Layers,
            limit: 1,
            ..
        }
    ));

    let field_limits = ImportLimits {
        max_fields: 1,
        max_fields_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        two_packet_error(OneFactPerPacket::Field, field_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::Fields,
            limit: 1,
            ..
        }
    ));

    let child_limits = ImportLimits {
        max_field_children: 1,
        max_field_children_per_packet: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        two_packet_error(OneFactPerPacket::Child, child_limits),
        ImportError::ResourceLimit {
            kind: ImportLimitKind::FieldChildren,
            limit: 1,
            ..
        }
    ));
}

#[test]
fn decode_arena_limit_relationships_must_be_nonzero_and_admit_one_packet() {
    for limits in [
        ImportLimits {
            max_layers_per_packet: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            max_fields: 1,
            max_fields_per_packet: 2,
            ..ImportLimits::default()
        },
        ImportLimits {
            max_field_children: 1,
            max_field_children_per_packet: 2,
            ..ImportLimits::default()
        },
    ] {
        assert!(matches!(
            CaptureImporter::new(legacy_capture(&[1], 1).into_boxed_slice(), limits),
            Err(ImportError::InvalidLimits)
        ));
    }
}
