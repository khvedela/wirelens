use packet_core::{
    ByteOrder, CaptureDataset, CaptureFormat, CaptureImporter, DiagnosticCode, ImportError,
    ImportLimitKind, ImportLimits, ImportStep, Recovery, TimestampResolution,
    decoder_scratch_bytes_upper_bound,
};

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn push_u16(output: &mut Vec<u8>, value: u16, endian: Endian) {
    output.extend(match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}

fn push_u32(output: &mut Vec<u8>, value: u32, endian: Endian) {
    output.extend(match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}

fn push_i64(output: &mut Vec<u8>, value: i64, endian: Endian) {
    output.extend(match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}

fn u32_length(length: usize) -> u32 {
    u32::try_from(length).expect("synthetic fixture length fits in u32")
}

fn u16_length(length: usize) -> u16 {
    u16::try_from(length).expect("synthetic fixture length fits in u16")
}

fn legacy_capture(
    endian: Endian,
    nanosecond: bool,
    modified: bool,
    timestamp_fraction: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    let magic = match (endian, nanosecond, modified) {
        (Endian::Little, false, false) => [0xd4, 0xc3, 0xb2, 0xa1],
        (Endian::Big, false, false) => [0xa1, 0xb2, 0xc3, 0xd4],
        (Endian::Little, true, false) => [0x4d, 0x3c, 0xb2, 0xa1],
        (Endian::Big, true, false) => [0xa1, 0xb2, 0x3c, 0x4d],
        (Endian::Little, false, true) => [0x34, 0xcd, 0xb2, 0xa1],
        (_, true, true) | (Endian::Big, false, true) => panic!("unsupported synthetic magic"),
    };
    output.extend(magic);
    push_u16(&mut output, 2, endian);
    push_u16(&mut output, 4, endian);
    push_u32(&mut output, 0, endian);
    push_u32(&mut output, 0, endian);
    push_u32(&mut output, 65_535, endian);
    push_u32(&mut output, 1, endian);
    push_u32(&mut output, 7, endian);
    push_u32(&mut output, timestamp_fraction, endian);
    push_u32(&mut output, u32_length(payload.len()), endian);
    push_u32(&mut output, u32_length(payload.len()), endian);
    if modified {
        output.extend([0; 8]);
    }
    output.extend(payload);
    output
}

fn option(endian: Endian, code: u16, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    push_u16(&mut output, code, endian);
    push_u16(&mut output, u16_length(value.len()), endian);
    output.extend(value);
    while output.len() % 4 != 0 {
        output.push(0);
    }
    output
}

fn block(endian: Endian, block_type: u32, body: &[u8]) -> Vec<u8> {
    let length = 12_u32
        .checked_add(u32_length(body.len()))
        .expect("synthetic block length fits");
    assert_eq!(length % 4, 0);
    let mut output = Vec::with_capacity(length as usize);
    push_u32(&mut output, block_type, endian);
    push_u32(&mut output, length, endian);
    output.extend(body);
    push_u32(&mut output, length, endian);
    output
}

fn shb(endian: Endian, minor: u16) -> Vec<u8> {
    shb_with_section_length(endian, minor, -1)
}

fn shb_with_section_length(endian: Endian, minor: u16, section_length: i64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(match endian {
        Endian::Little => [0x4d, 0x3c, 0x2b, 0x1a],
        Endian::Big => [0x1a, 0x2b, 0x3c, 0x4d],
    });
    push_u16(&mut body, 1, endian);
    push_u16(&mut body, minor, endian);
    push_i64(&mut body, section_length, endian);
    block(endian, 0x0a0d_0d0a, &body)
}

fn option_bearing_block(endian: Endian, block_type: u32, fixed_body_bytes: usize) -> Vec<u8> {
    let mut body = vec![0; fixed_body_bytes];
    for _ in 0..3 {
        body.extend(option(endian, 1, &[]));
    }
    block(endian, block_type, &body)
}

fn option_dense_idb(endian: Endian, item_count: u32) -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 1, endian);
    push_u16(&mut body, 0, endian);
    push_u32(&mut body, 65_535, endian);
    for _ in 0..item_count {
        body.extend(option(endian, 1, &[]));
    }
    block(endian, 1, &body)
}

fn idb(
    endian: Endian,
    snap_length: u32,
    resolution: Option<u8>,
    timestamp_offset: Option<i64>,
    name: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 1, endian);
    push_u16(&mut body, 0, endian);
    push_u32(&mut body, snap_length, endian);
    if let Some(raw) = resolution {
        body.extend(option(endian, 9, &[raw]));
    }
    if let Some(offset) = timestamp_offset {
        let bytes = match endian {
            Endian::Little => offset.to_le_bytes(),
            Endian::Big => offset.to_be_bytes(),
        };
        body.extend(option(endian, 14, &bytes));
    }
    if let Some(name) = name {
        body.extend(option(endian, 2, name.as_bytes()));
    }
    if resolution.is_some() || timestamp_offset.is_some() || name.is_some() {
        body.extend(option(endian, 0, &[]));
    }
    block(endian, 1, &body)
}

fn epb(
    endian: Endian,
    interface_id: u32,
    ticks: u64,
    original_length: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, interface_id, endian);
    push_u32(&mut body, (ticks >> 32) as u32, endian);
    push_u32(
        &mut body,
        u32::try_from(ticks & u64::from(u32::MAX)).expect("masked timestamp low word"),
        endian,
    );
    push_u32(&mut body, u32_length(payload.len()), endian);
    push_u32(&mut body, original_length, endian);
    body.extend(payload);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(endian, 6, &body)
}

fn spb(endian: Endian, original_length: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, original_length, endian);
    body.extend(payload);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(endian, 3, &body)
}

fn finish(mut importer: CaptureImporter) -> CaptureDataset {
    loop {
        match importer
            .step(64, u64::from(u32::MAX))
            .expect("synthetic import step")
        {
            ImportStep::Progress(_) => {}
            ImportStep::NeedsBudget { minimum_bytes, .. } => {
                importer
                    .step(1, minimum_bytes)
                    .expect("required budget must make progress");
            }
            ImportStep::Ready(_) => break,
        }
    }
    importer.finish().expect("synthetic import finalization")
}

#[test]
fn legacy_import_is_bounded_and_recovers_the_original_allocation() {
    let bytes = legacy_capture(Endian::Little, false, false, 123_456, &[1, 2, 3, 4]);
    let original_pointer = bytes.as_ptr();
    let mut importer = CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
        .expect("valid legacy capture");

    assert_eq!(
        importer.step(1, 1).expect("budget response"),
        ImportStep::NeedsBudget {
            progress: importer.progress(),
            minimum_bytes: 24,
        }
    );
    assert!(matches!(
        importer.step(1, 24).expect("header step"),
        ImportStep::Progress(_)
    ));
    assert_eq!(importer.progress().consumed_bytes, 24);
    let record_length = 20;
    assert!(matches!(
        importer.step(1, record_length - 1).expect("record budget"),
        ImportStep::NeedsBudget {
            minimum_bytes: 20,
            ..
        }
    ));
    let dataset = finish(importer);

    assert_eq!(dataset.bytes().as_ptr(), original_pointer);
    assert_eq!(dataset.metadata().format, CaptureFormat::Pcap);
    assert_eq!(dataset.metadata().packet_count, 1);
    assert_eq!(dataset.sections()[0].byte_order, ByteOrder::LittleEndian);
    let timestamp = dataset.packets()[0].timestamp.expect("valid microseconds");
    assert_eq!(timestamp.seconds(), 7);
    assert_eq!(timestamp.fraction(), 123_456);
    assert_eq!(timestamp.resolution(), TimestampResolution::Decimal(6));
    assert_eq!(dataset.bytes()[40..44], [1, 2, 3, 4]);
}

#[test]
fn legacy_big_endian_nanoseconds_and_modified_records_are_supported() {
    let big = finish(
        CaptureImporter::new(
            legacy_capture(Endian::Big, true, false, 999_999_999, &[9, 8]).into_boxed_slice(),
            ImportLimits::default(),
        )
        .expect("valid big-endian nanosecond capture"),
    );
    assert_eq!(big.sections()[0].byte_order, ByteOrder::BigEndian);
    assert_eq!(
        big.packets()[0]
            .timestamp
            .expect("nanosecond timestamp")
            .resolution(),
        TimestampResolution::Decimal(9)
    );

    let modified = finish(
        CaptureImporter::new(
            legacy_capture(Endian::Little, false, true, 1, &[5, 6, 7]).into_boxed_slice(),
            ImportLimits::default(),
        )
        .expect("valid modified capture"),
    );
    assert_eq!(modified.packets()[0].data.start(), 48);
    assert_eq!(modified.packets()[0].captured_length, 3);
}

#[test]
fn legacy_header_and_record_limits_are_checked_before_growth() {
    let mut invalid_version = legacy_capture(Endian::Little, false, false, 0, &[]);
    invalid_version[4] = 3;
    assert!(matches!(
        CaptureImporter::new(invalid_version.into_boxed_slice(), ImportLimits::default()),
        Err(ImportError::InvalidHeader)
    ));

    let limits = ImportLimits {
        max_block_bytes: 64,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(
        legacy_capture(Endian::Little, false, false, 0, &[0; 100]).into_boxed_slice(),
        limits,
    )
    .expect("header itself is within the limit");
    assert!(matches!(importer.step(1, 24), Ok(ImportStep::Progress(_))));
    assert_eq!(
        importer.step(1, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: 64,
            offset: 24,
        })
    );
}

#[test]
fn incomplete_initial_headers_have_a_truthful_truncated_category() {
    assert!(matches!(
        CaptureImporter::new(
            vec![0xd4, 0xc3, 0xb2, 0xa1].into_boxed_slice(),
            ImportLimits::default(),
        ),
        Err(ImportError::TruncatedInput { offset: 0 })
    ));

    let mut pcapng = shb(Endian::Little, 0);
    pcapng.truncate(pcapng.len() - 4);
    assert!(matches!(
        CaptureImporter::new(pcapng.into_boxed_slice(), ImportLimits::default()),
        Err(ImportError::TruncatedInput { offset: 0 })
    ));
}

#[test]
fn truncated_legacy_record_finishes_with_bounded_diagnostic() {
    let mut bytes = legacy_capture(Endian::Little, false, false, 0, &[1, 2, 3, 4]);
    bytes.truncate(bytes.len() - 2);
    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("valid header with truncated record"),
    );
    assert!(dataset.packets().is_empty());
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::TRUNCATED_RECORD
    );
    assert_eq!(dataset.diagnostics()[0].recovery, Recovery::RecordSkipped);
}

#[test]
fn mixed_endian_sections_reset_interfaces_and_decode_raw_time_options() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(idb(Endian::Little, 0, None, None, Some("unlimited")));
    bytes.extend(idb(
        Endian::Little,
        65_535,
        Some(20),
        Some(5),
        Some("precise"),
    ));
    bytes.extend(spb(Endian::Little, 3, &[1, 2, 3]));
    bytes.extend(epb(Endian::Little, 1, u64::MAX, 2, &[4, 5, 6]));
    let second_section_start = bytes.len() as u64;
    bytes.extend(shb(Endian::Big, 2));
    bytes.extend(idb(
        Endian::Big,
        65_535,
        Some(0x80 | 0x0a),
        Some(-2),
        Some("big"),
    ));
    bytes.extend(epb(Endian::Big, 0, 1_024, 1, &[9]));

    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("mixed-endian pcapng"),
    );
    assert_eq!(dataset.metadata().format, CaptureFormat::PcapNg);
    assert_eq!(dataset.sections().len(), 2);
    assert_eq!(dataset.sections()[0].byte_order, ByteOrder::LittleEndian);
    assert_eq!(dataset.sections()[0].byte_range.end(), second_section_start);
    assert_eq!(dataset.sections()[1].byte_order, ByteOrder::BigEndian);
    assert_eq!(dataset.interfaces().len(), 3);
    assert_eq!(dataset.packets().len(), 3);

    let simple = dataset.packets()[0];
    assert_eq!(simple.interface_id.0, 0);
    assert_eq!(simple.captured_length, 3);
    assert!(simple.timestamp.is_none());

    let precise = dataset.packets()[1];
    assert_eq!(precise.interface_id.0, 1);
    let precise_timestamp = precise.timestamp.expect("exact 10^-20 timestamp");
    assert_eq!(precise_timestamp.seconds(), 5);
    assert_eq!(precise_timestamp.fraction(), u64::MAX);
    assert_eq!(
        precise_timestamp.resolution(),
        TimestampResolution::Decimal(20)
    );
    assert_eq!(precise.original_length, 2);
    assert_eq!(precise.captured_length, 3);
    assert_eq!(precise.diagnostics.length(), 1);

    let big = dataset.packets()[2];
    assert_eq!(big.section_id.0, 1);
    assert_eq!(big.interface_id.0, 2);
    let big_timestamp = big.timestamp.expect("signed big-endian offset");
    assert_eq!(big_timestamp.seconds(), -1);
    assert_eq!(big_timestamp.fraction(), 0);
    assert_eq!(big_timestamp.resolution(), TimestampResolution::Binary(10));
}

#[test]
fn malformed_footer_is_detected_even_when_upstream_frames_the_block() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(idb(Endian::Little, 65_535, None, None, None));
    let mut simple = spb(Endian::Little, 1, &[1]);
    let last = simple.len();
    simple[last - 4..].copy_from_slice(&12_u32.to_le_bytes());
    bytes.extend(simple);

    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("valid header before malformed footer"),
    );
    assert!(dataset.packets().is_empty());
    assert!(
        dataset
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::INVALID_CAPTURE_HEADER)
    );
}

#[test]
fn packets_without_a_valid_section_interface_are_skipped_with_diagnostics() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(spb(Endian::Little, 1, &[1]));
    bytes.extend(epb(Endian::Little, 7, 0, 1, &[2]));

    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("well-framed capture"),
    );
    assert!(dataset.packets().is_empty());
    assert_eq!(dataset.diagnostics().len(), 2);
    assert!(dataset.diagnostics().iter().all(|diagnostic| {
        diagnostic.code == DiagnosticCode::INCONSISTENT_LENGTH
            && diagnostic.recovery == Recovery::RecordSkipped
    }));
}

#[test]
fn binary_127_is_exact_and_signed_timestamp_overflow_is_diagnosed() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(idb(
        Endian::Little,
        65_535,
        Some(0xff),
        Some(i64::MIN),
        None,
    ));
    bytes.extend(idb(Endian::Little, 65_535, Some(0), Some(i64::MAX), None));
    bytes.extend(epb(Endian::Little, 0, u64::MAX, 1, &[1]));
    bytes.extend(epb(Endian::Little, 1, 1, 1, &[2]));

    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("well-framed timestamp capture"),
    );
    let exact = dataset.packets()[0]
        .timestamp
        .expect("2^-127 counter remains below one second");
    assert_eq!(exact.seconds(), i64::MIN);
    assert_eq!(exact.fraction(), u64::MAX);
    assert_eq!(exact.resolution(), TimestampResolution::Binary(127));

    assert!(dataset.packets()[1].timestamp.is_none());
    let diagnostic_start = dataset.packets()[1].diagnostics.start() as usize;
    assert_eq!(
        dataset.diagnostics()[diagnostic_start].code,
        DiagnosticCode::INVALID_TIMESTAMP
    );
}

#[test]
fn oversized_pcapng_block_is_rejected_before_parser_growth() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(block(Endian::Little, 0xdead_beef, &[0; 52]));
    let limits = ImportLimits {
        max_block_bytes: 32,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(bytes.into_boxed_slice(), limits)
        .expect("first section is within the block limit");
    assert!(matches!(importer.step(1, 28), Ok(ImportStep::Progress(_))));
    assert_eq!(
        importer.step(1, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: 32,
            offset: 28,
        })
    );
}

#[test]
fn decoded_item_bombs_are_rejected_before_dependency_allocations() {
    let limits = ImportLimits {
        max_decoded_items_per_block: 2,
        ..ImportLimits::default()
    };

    let mut first_section_body = Vec::new();
    first_section_body.extend([0x4d, 0x3c, 0x2b, 0x1a]);
    push_u16(&mut first_section_body, 1, Endian::Little);
    push_u16(&mut first_section_body, 0, Endian::Little);
    push_i64(&mut first_section_body, -1, Endian::Little);
    for _ in 0..3 {
        first_section_body.extend(option(Endian::Little, 1, &[]));
    }
    let first_section = block(Endian::Little, 0x0a0d_0d0a, &first_section_body);
    assert!(matches!(
        CaptureImporter::new(first_section.into_boxed_slice(), limits),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::DecodedItemsPerBlock,
            limit: 2,
            offset: 0,
        })
    ));

    let mut name_records = Vec::new();
    push_u16(&mut name_records, 1, Endian::Little);
    push_u16(&mut name_records, 0, Endian::Little);
    push_u16(&mut name_records, 1, Endian::Little);
    push_u16(&mut name_records, 0, Endian::Little);
    push_u16(&mut name_records, 0, Endian::Little);
    push_u16(&mut name_records, 0, Endian::Little);

    let bomb_blocks = [
        option_bearing_block(Endian::Little, 1, 8),
        option_bearing_block(Endian::Little, 6, 20),
        block(Endian::Little, 4, &name_records),
        option_bearing_block(Endian::Little, 5, 12),
        option_bearing_block(Endian::Little, 0x0000_000a, 8),
        option_bearing_block(Endian::Little, 0x8000_0001, 4),
    ];
    for bomb in bomb_blocks {
        let mut bytes = shb(Endian::Little, 0);
        bytes.extend(bomb);
        let mut importer =
            CaptureImporter::new(bytes.into_boxed_slice(), limits).expect("bounded first section");
        assert_eq!(
            importer.step(2, 1_024),
            Err(ImportError::ResourceLimit {
                kind: ImportLimitKind::DecodedItemsPerBlock,
                limit: 2,
                offset: 28,
            })
        );
        assert_eq!(importer.progress().consumed_bytes, 28);
    }
}

#[test]
fn decoded_item_step_budget_checkpoints_before_consuming_the_next_block() {
    let dense_block = option_dense_idb(Endian::Little, 3);
    let first_block_end = 28_u64 + dense_block.len() as u64;
    let mut bytes = shb(Endian::Little, 0);
    bytes.extend(&dense_block);
    bytes.extend(&dense_block);
    bytes.extend(&dense_block);
    let total_bytes = bytes.len() as u64;
    let limits = ImportLimits {
        max_decoded_items_per_block: 3,
        max_decoded_items_per_step: 5,
        ..ImportLimits::default()
    };
    let mut importer =
        CaptureImporter::new(bytes.into_boxed_slice(), limits).expect("bounded dense options");

    let first = importer
        .step(32, total_bytes)
        .expect("first bounded work step succeeds");
    let ImportStep::Progress(first) = first else {
        panic!("the next complete block must remain unconsumed at the work checkpoint")
    };
    assert_eq!(first.records_processed, 2);
    assert_eq!(first.consumed_bytes, first_block_end);

    let second = importer
        .step(32, total_bytes)
        .expect("second bounded work step succeeds");
    let ImportStep::Progress(second) = second else {
        panic!("each three-item block requires a new five-item work step")
    };
    assert_eq!(second.records_processed, first.records_processed + 1);
    assert_eq!(
        second.consumed_bytes,
        first.consumed_bytes + dense_block.len() as u64
    );
    assert!(second.consumed_bytes > first.consumed_bytes);

    let dataset = finish(importer);
    assert_eq!(dataset.interfaces().len(), 3);
}

#[test]
fn a_full_item_block_makes_progress_without_decoding_the_hostile_tail() {
    const ITEMS_PER_BLOCK: u32 = 4_096;
    const BLOCK_COUNT: u32 = 513;

    let dense_block = option_dense_idb(Endian::Little, ITEMS_PER_BLOCK);
    let mut bytes = shb(Endian::Little, 0);
    for _ in 0..BLOCK_COUNT {
        bytes.extend(&dense_block);
    }
    assert!(u64::from(ITEMS_PER_BLOCK) * u64::from(BLOCK_COUNT) > 2_000_000);
    let byte_budget = bytes.len() as u64;
    let mut importer = CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
        .expect("each hostile block remains within the per-block item cap");

    let first = importer
        .step(u32::MAX, byte_budget)
        .expect("the first full-budget block makes bounded progress");
    let ImportStep::Progress(first) = first else {
        panic!("exhausting the cumulative item budget must create a checkpoint")
    };
    assert_eq!(first.records_processed, 2);
    assert_eq!(first.consumed_bytes, 28 + dense_block.len() as u64);

    let second = importer
        .step(u32::MAX, byte_budget)
        .expect("a fresh step must consume the next individually admitted block");
    let ImportStep::Progress(second) = second else {
        panic!("a full-budget block must not livelock or consume the hostile tail")
    };
    assert_eq!(second.records_processed, first.records_processed + 1);
    assert_eq!(
        second.consumed_bytes,
        first.consumed_bytes + dense_block.len() as u64
    );
    assert!(second.consumed_bytes > first.consumed_bytes);
    let _ = importer.cancel();
}

#[test]
fn per_step_item_budget_must_admit_every_allowed_block() {
    let limits = ImportLimits {
        max_decoded_items_per_block: 4,
        max_decoded_items_per_step: 3,
        ..ImportLimits::default()
    };
    assert!(matches!(
        CaptureImporter::new(shb(Endian::Little, 0).into_boxed_slice(), limits),
        Err(ImportError::InvalidLimits)
    ));
}

#[test]
fn decoder_scratch_ceiling_covers_small_and_default_vector_capacities() {
    let minimum = decoder_scratch_bytes_upper_bound(1).expect("minimum scratch is representable");
    let default =
        decoder_scratch_bytes_upper_bound(4_096).expect("default decoder scratch is representable");
    assert!(minimum > 0);
    assert!(default >= minimum);
    assert!(
        decoder_scratch_bytes_upper_bound(u32::MAX)
            .expect("u32-sized item counts remain representable")
            > default
    );
}

#[test]
fn partial_legacy_headers_and_pcapng_header_damage_have_exact_categories() {
    for partial_header_bytes in [1_usize, 8, 15] {
        let mut bytes = legacy_capture(Endian::Little, false, false, 0, &[1]);
        bytes.truncate(24 + partial_header_bytes);
        let dataset = finish(
            CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
                .expect("complete global header"),
        );
        assert!(dataset.packets().is_empty());
        assert_eq!(dataset.diagnostics().len(), 1);
        let diagnostic = &dataset.diagnostics()[0];
        assert_eq!(diagnostic.code, DiagnosticCode::TRUNCATED_RECORD);
        let evidence = diagnostic
            .byte_range
            .expect("partial bytes are bounded evidence");
        assert_eq!(evidence.start(), 24);
        assert_eq!(
            evidence.length(),
            u32::try_from(partial_header_bytes).expect("partial fixture length fits u32")
        );
    }

    let mut malformed_bom = shb(Endian::Little, 0);
    malformed_bom[8..12].copy_from_slice(&[0xff; 4]);
    let mut bytes = shb(Endian::Little, 0);
    bytes.extend(malformed_bom);
    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("safe first section"),
    );
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );
    assert_eq!(
        dataset.diagnostics()[0]
            .byte_range
            .expect("malformed header evidence")
            .start(),
        28
    );

    let mut bytes = shb(Endian::Little, 0);
    let mut malformed_length = vec![0; 12];
    malformed_length[..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
    malformed_length[4..8].copy_from_slice(&14_u32.to_le_bytes());
    bytes.extend(malformed_length);
    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("safe first section"),
    );
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );
}

#[test]
fn oversized_declared_block_wins_over_truncation() {
    let limits = ImportLimits {
        max_block_bytes: 64,
        ..ImportLimits::default()
    };
    let mut bytes = shb(Endian::Little, 0);
    bytes.extend(0xdead_beef_u32.to_le_bytes());
    bytes.extend(68_u32.to_le_bytes());
    bytes.extend([0; 4]);
    let mut importer =
        CaptureImporter::new(bytes.into_boxed_slice(), limits).expect("complete first section");
    assert!(matches!(importer.step(1, 28), Ok(ImportStep::Progress(_))));
    assert_eq!(
        importer.step(1, 1_024),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: 64,
            offset: 28,
        })
    );
}

#[test]
fn declared_section_lengths_match_the_next_section_or_eof() {
    let interface = idb(Endian::Little, 65_535, None, None, None);
    let mut exact = shb_with_section_length(
        Endian::Little,
        0,
        i64::try_from(interface.len()).expect("fixture length"),
    );
    exact.extend(&interface);
    let dataset = finish(
        CaptureImporter::new(exact.into_boxed_slice(), ImportLimits::default())
            .expect("aligned exact section length"),
    );
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(dataset.sections()[0].byte_range.length(), 48);

    let mut exact_next_section = shb_with_section_length(
        Endian::Little,
        0,
        i64::try_from(interface.len()).expect("fixture length"),
    );
    exact_next_section.extend(&interface);
    exact_next_section.extend(shb_with_section_length(Endian::Big, 2, 0));
    let dataset = finish(
        CaptureImporter::new(
            exact_next_section.into_boxed_slice(),
            ImportLimits::default(),
        )
        .expect("exact next-section boundary"),
    );
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(dataset.sections().len(), 2);
    assert_eq!(dataset.sections()[1].byte_range.length(), 28);

    let mut early_eof = shb_with_section_length(Endian::Little, 0, 24);
    early_eof.extend(&interface);
    let dataset = finish(
        CaptureImporter::new(early_eof.into_boxed_slice(), ImportLimits::default())
            .expect("framing is complete before the boundary contradiction"),
    );
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );

    let mut crossed_boundary = shb_with_section_length(Endian::Little, 0, 16);
    crossed_boundary.extend(&interface);
    let dataset = finish(
        CaptureImporter::new(crossed_boundary.into_boxed_slice(), ImportLimits::default())
            .expect("framing is complete before the boundary contradiction"),
    );
    assert!(dataset.interfaces().is_empty());
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );

    let mut early_next_section = shb_with_section_length(Endian::Little, 0, 24);
    early_next_section.extend(&interface);
    early_next_section.extend(shb(Endian::Big, 0));
    let dataset = finish(
        CaptureImporter::new(
            early_next_section.into_boxed_slice(),
            ImportLimits::default(),
        )
        .expect("first section header is valid"),
    );
    assert_eq!(dataset.sections().len(), 1);
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );

    let invalid_alignment = shb_with_section_length(Endian::Little, 0, 2);
    assert!(matches!(
        CaptureImporter::new(
            invalid_alignment.into_boxed_slice(),
            ImportLimits::default()
        ),
        Err(ImportError::InvalidHeader)
    ));

    let mut invalid_followup_alignment = shb(Endian::Little, 0);
    invalid_followup_alignment.extend(shb_with_section_length(Endian::Big, 2, 2));
    let dataset = finish(
        CaptureImporter::new(
            invalid_followup_alignment.into_boxed_slice(),
            ImportLimits::default(),
        )
        .expect("safe first section"),
    );
    assert_eq!(dataset.sections().len(), 1);
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::INVALID_CAPTURE_HEADER
    );
}

#[test]
fn well_framed_unknown_block_is_a_bounded_unsupported_diagnostic() {
    let mut bytes = Vec::new();
    bytes.extend(shb(Endian::Little, 0));
    bytes.extend(block(Endian::Little, 0xdead_beef, &[]));
    let dataset = finish(
        CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            .expect("well-framed unknown block"),
    );
    assert_eq!(dataset.diagnostics().len(), 1);
    assert_eq!(
        dataset.diagnostics()[0].code,
        DiagnosticCode::UNSUPPORTED_BLOCK
    );
}

#[test]
fn persistent_resource_limits_are_enforced() {
    let mut two_packets = legacy_capture(Endian::Little, false, false, 0, &[1]);
    push_u32(&mut two_packets, 8, Endian::Little);
    push_u32(&mut two_packets, 0, Endian::Little);
    push_u32(&mut two_packets, 1, Endian::Little);
    push_u32(&mut two_packets, 1, Endian::Little);
    two_packets.push(2);
    let packet_limits = ImportLimits {
        max_packets: 1,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(two_packets.into_boxed_slice(), packet_limits)
        .expect("valid two-packet capture");
    assert!(matches!(
        importer.step(3, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::Packets,
            limit: 1,
            ..
        })
    ));

    let mut two_sections = Vec::new();
    two_sections.extend(shb(Endian::Little, 0));
    two_sections.extend(shb(Endian::Big, 2));
    let section_limits = ImportLimits {
        max_sections: 1,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(two_sections.into_boxed_slice(), section_limits)
        .expect("valid first section");
    assert!(matches!(
        importer.step(2, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::Sections,
            limit: 1,
            ..
        })
    ));

    let mut two_interfaces = Vec::new();
    two_interfaces.extend(shb(Endian::Little, 0));
    two_interfaces.extend(idb(Endian::Little, 1, None, None, None));
    two_interfaces.extend(idb(Endian::Little, 1, None, None, None));
    let interface_limits = ImportLimits {
        max_interfaces: 1,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(two_interfaces.into_boxed_slice(), interface_limits)
        .expect("valid first interface");
    assert!(matches!(
        importer.step(3, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::Interfaces,
            limit: 1,
            ..
        })
    ));

    let mut unknown_blocks = Vec::new();
    unknown_blocks.extend(shb(Endian::Little, 0));
    unknown_blocks.extend(block(Endian::Little, 0x1111_1111, &[]));
    unknown_blocks.extend(block(Endian::Little, 0x2222_2222, &[]));
    let diagnostic_limits = ImportLimits {
        max_diagnostics: 1,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(unknown_blocks.into_boxed_slice(), diagnostic_limits)
        .expect("valid capture with unknown blocks");
    assert!(matches!(
        importer.step(3, 1_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::Diagnostics,
            limit: 1,
            ..
        })
    ));

    let long_name = "n".repeat(1_025);
    let mut named_interface = Vec::new();
    named_interface.extend(shb(Endian::Little, 0));
    named_interface.extend(idb(Endian::Little, 1, None, None, Some(&long_name)));
    let string_limits = ImportLimits {
        max_string_bytes: 1_024,
        ..ImportLimits::default()
    };
    let mut importer = CaptureImporter::new(named_interface.into_boxed_slice(), string_limits)
        .expect("valid named interface framing");
    assert!(matches!(
        importer.step(2, 10_000),
        Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::StringBytes,
            limit: 1_024,
            ..
        })
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // One deterministic corpus and invariant runner is easier to audit together.
fn deterministic_malformed_corpus_replay_preserves_import_invariants() {
    let mut seed = Vec::new();
    seed.extend(shb(Endian::Little, 0));
    seed.extend(idb(
        Endian::Little,
        65_535,
        Some(6),
        Some(0),
        Some("mutate"),
    ));
    seed.extend(epb(Endian::Little, 0, 1, 3, &[1, 2, 3]));

    let mut cases = Vec::new();
    for length in 0..seed.len() {
        cases.push(seed[..length].to_vec());
    }
    for index in 0..seed.len() {
        let mut mutated = seed.clone();
        mutated[index] ^= 0xff;
        cases.push(mutated);
    }
    let mut random_state = 0x8b5a_2c97_1d4e_6f03_u64;
    for case_index in 0..256_usize {
        let mut mutated = seed.clone();
        let mutation_count = 1 + case_index % 8;
        for _ in 0..mutation_count {
            random_state ^= random_state << 13;
            random_state ^= random_state >> 7;
            random_state ^= random_state << 17;
            let index = usize::try_from(random_state % mutated.len() as u64)
                .expect("fixture index fits usize");
            let mutation = u8::try_from((random_state >> 32) & 0xff)
                .expect("masked mutation byte fits u8")
                | 1;
            mutated[index] ^= mutation;
        }
        if case_index % 5 == 0 {
            let retained = case_index % mutated.len();
            mutated.truncate(retained);
        }
        cases.push(mutated);
    }

    let mut unterminated_name_records = shb(Endian::Little, 0);
    unterminated_name_records.extend(block(Endian::Little, 4, &[1, 0, 0, 0]));
    cases.push(unterminated_name_records);
    let mut invalid_followup_bom = shb(Endian::Little, 0);
    let mut damaged_section = shb(Endian::Big, 0);
    damaged_section[8..12].copy_from_slice(&[0x55; 4]);
    invalid_followup_bom.extend(damaged_section);
    cases.push(invalid_followup_bom);

    for bytes in cases {
        let result = std::panic::catch_unwind(|| {
            let Ok(mut importer) =
                CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
            else {
                return;
            };
            let mut previous = importer.progress();
            let mut terminal = false;
            let mut byte_budget = 64 * 1024;
            for _ in 0..64 {
                match importer.step(8, byte_budget) {
                    Ok(ImportStep::Progress(progress)) => {
                        assert!(progress.consumed_bytes >= previous.consumed_bytes);
                        assert!(progress.records_processed >= previous.records_processed);
                        assert!(progress.packets_retained >= previous.packets_retained);
                        assert!(progress.consumed_bytes <= progress.total_bytes);
                        assert!(progress.packets_retained <= progress.records_processed);
                        previous = progress;
                        byte_budget = 64 * 1024;
                    }
                    Ok(ImportStep::NeedsBudget {
                        progress,
                        minimum_bytes,
                    }) => {
                        assert_eq!(progress, previous);
                        assert!(minimum_bytes > 0);
                        if minimum_bytes > 16 * 1024 * 1024 {
                            break;
                        }
                        byte_budget = minimum_bytes;
                    }
                    Ok(ImportStep::Ready(progress)) => {
                        assert!(progress.consumed_bytes >= previous.consumed_bytes);
                        assert!(progress.consumed_bytes <= progress.total_bytes);
                        terminal = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if terminal {
                let dataset = importer.finish().expect("ready corpus import validates");
                assert_eq!(
                    dataset.metadata().packet_count,
                    dataset.packets().len() as u64
                );
            } else {
                let _ = importer.cancel();
            }
        });
        assert!(result.is_ok());
    }
}

#[test]
fn cancellation_consumes_partial_state_and_finish_requires_ready() {
    let bytes = legacy_capture(Endian::Little, false, false, 0, &[1]);
    let importer = CaptureImporter::new(bytes.clone().into_boxed_slice(), ImportLimits::default())
        .expect("valid capture");
    assert_eq!(importer.finish(), Err(ImportError::NotReady));

    let mut importer = CaptureImporter::new(bytes.into_boxed_slice(), ImportLimits::default())
        .expect("valid capture");
    importer.step(1, 24).expect("consume header");
    let progress = importer.cancel();
    assert_eq!(progress.consumed_bytes, 24);
    assert_eq!(progress.records_processed, 1);
}
