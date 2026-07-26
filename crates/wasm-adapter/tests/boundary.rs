use packet_core::{
    ByteOrder, ByteRange, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata,
    CaptureTimestamp, DiagnosticCode, DiagnosticScope, IndexRange, InterfaceId, InterfaceMetadata,
    LinkType, PacketId, PacketRecord, Recovery, SectionId, SectionMetadata, Severity,
    TimestampResolution,
};
use wasm_adapter::{
    API_VERSION, BATCH_SCHEMA_VERSION, BoundaryErrorCode, BoundaryHandle, BoundaryState,
    CAPTURE_BYTES_PER_PACKET, CAPTURE_PACKET_BASE_ALLOWANCE, DisposeStatus, HandleKind,
    ImportAdvance, ImportLimits, ImportPhase, ImportProgressSnapshot, MAX_CAPTURE_BLOCK_BYTES,
    MAX_CAPTURE_BYTES, MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK, MAX_CAPTURE_DECODED_ITEMS_PER_STEP,
    MAX_CAPTURE_PACKETS, MAX_CAPTURE_STRING_BYTES, MAX_DATASET_HANDLES, MAX_EVIDENCE_BYTES,
    MAX_IMPORT_HANDLES, MAX_IMPORT_STEP_BYTES, MAX_IMPORT_STEP_RECORDS, MAX_PACKET_BATCH_BYTES,
    MAX_PACKET_BATCH_ROWS, MIN_PACKET_BATCH_BYTES, PacketBatch, PacketBatchColumn,
    packet_limit_for_capture,
};

fn range(start: u64, length: u32) -> ByteRange {
    ByteRange::new(start, length).expect("test byte range is representable")
}

fn empty_dataset() -> CaptureDataset {
    CaptureDataset::from_parts(CaptureDatasetParts {
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
    })
    .expect("empty canonical dataset is valid")
}

fn dataset_with_interned_string_bytes(length: usize) -> CaptureDataset {
    let value = String::from_utf8(vec![b'x'; length]).expect("ASCII test string is valid UTF-8");
    CaptureDataset::from_parts(CaptureDatasetParts {
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
        strings: vec![value.into_boxed_str()].into_boxed_slice(),
    })
    .expect("unused canonical strings remain structurally valid")
}

fn exact_dataset() -> CaptureDataset {
    let resolution = TimestampResolution::Decimal(127);
    let early = CaptureTimestamp::new(i64::MIN + 100, u64::MAX, resolution)
        .expect("high-resolution early timestamp is exact");
    let late = CaptureTimestamp::new(i64::MAX - 100, u64::MAX - 1, resolution)
        .expect("high-resolution late timestamp is exact");
    let packets = vec![
        PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: Some(early),
            captured_length: 3,
            original_length: 7,
            data: range(64, 3),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        },
        PacketRecord {
            id: PacketId(1),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: 4,
            original_length: 4,
            data: range(80, 4),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        },
        PacketRecord {
            id: PacketId(2),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: Some(late),
            captured_length: 5,
            original_length: 9,
            data: range(96, 5),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        },
    ];
    let bytes: Vec<u8> = (0_u16..512).map(|value| value.to_le_bytes()[0]).collect();
    CaptureDataset::from_parts(CaptureDatasetParts {
        metadata: CaptureMetadata {
            format: CaptureFormat::PcapNg,
            byte_length: bytes.len() as u64,
            packet_count: packets.len() as u64,
            started_at: Some(early),
            ended_at: Some(late),
        },
        bytes: bytes.into_boxed_slice(),
        sections: vec![SectionMetadata {
            id: SectionId(0),
            byte_range: range(0, 512),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 1).expect("test interface span is valid"),
        }]
        .into_boxed_slice(),
        interfaces: vec![InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: range(0, 24),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: 65_535,
            timestamp_resolution: resolution,
            name: None,
        }]
        .into_boxed_slice(),
        packets: packets.into_boxed_slice(),
        layers: Box::default(),
        fields: Box::default(),
        field_children: Box::default(),
        diagnostics: Box::default(),
        strings: Box::default(),
    })
    .expect("exact-timestamp dataset is valid")
}

fn synthetic_pcap(payloads: &[&[u8]]) -> Box<[u8]> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    // Generic boundary tests intentionally use LINKTYPE_USER0. Protocol-specific
    // tests build explicit Ethernet captures instead of treating arbitrary test
    // payload bytes as an Ethernet frame.
    bytes.extend_from_slice(&147_u32.to_le_bytes());
    for (index, payload) in payloads.iter().enumerate() {
        let length = u32::try_from(payload.len()).expect("synthetic payload length fits u32");
        bytes.extend_from_slice(
            &u32::try_from(index + 1)
                .expect("synthetic timestamp fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&500_000_u32.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes.into_boxed_slice()
}

fn synthetic_ethernet_pcap(payloads: &[&[u8]]) -> Box<[u8]> {
    let mut bytes = synthetic_pcap(payloads).into_vec();
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes.into_boxed_slice()
}

fn dense_empty_pcap(packet_count: u32) -> Box<[u8]> {
    let mut bytes = Vec::with_capacity(24 + packet_count as usize * 16);
    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&147_u32.to_le_bytes());
    for index in 0..packet_count {
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes.into_boxed_slice()
}

fn advance_until_ready(
    state: &mut BoundaryState,
    import: BoundaryHandle,
) -> ImportProgressSnapshot {
    let mut previous = state
        .import_progress(import)
        .expect("live import exposes progress");
    for _ in 0..32 {
        let outcome = state
            .advance_import(import, 1, MAX_IMPORT_STEP_BYTES)
            .expect("bounded import step succeeds");
        let current = match outcome {
            ImportAdvance::Progress(progress) | ImportAdvance::Ready(progress) => progress,
            ImportAdvance::NeedsBudget { .. } => {
                panic!("hard byte budget fits every accepted block")
            }
        };
        assert!(current.consumed_bytes >= previous.consumed_bytes);
        assert!(current.records_processed >= previous.records_processed);
        assert!(current.packets_retained >= previous.packets_retained);
        assert!(current.diagnostics >= previous.diagnostics);
        assert!(current.consumed_bytes <= current.total_bytes);
        if current.phase == ImportPhase::Ready {
            return current;
        }
        previous = current;
    }
    panic!("small synthetic import did not become ready within its record count")
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("u16 test slice"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("u32 test slice"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("u64 test slice"),
    )
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("i64 test slice"),
    )
}

fn column_offset(batch: &PacketBatch, column: PacketBatchColumn, row: usize) -> usize {
    let descriptor = batch
        .descriptor(column)
        .expect("stable batch column is described");
    let width = usize::try_from(descriptor.byte_length / descriptor.element_count.max(1))
        .expect("column width fits usize");
    descriptor.byte_offset as usize + row * width
}

fn commit_batch(state: &mut BoundaryState, cursor: BoundaryHandle, batch: &PacketBatch) {
    state
        .commit_packet_batch(
            cursor,
            BATCH_SCHEMA_VERSION,
            batch.start_row(),
            batch.next_row(),
        )
        .expect("validated batch range commits exactly once");
}

fn read_committed_batch(
    state: &mut BoundaryState,
    cursor: BoundaryHandle,
    rows: u32,
) -> PacketBatch {
    let batch = state
        .read_packet_batch(cursor, rows)
        .expect("packet batch is encoded");
    commit_batch(state, cursor, &batch);
    batch
}

#[test]
fn import_steps_publish_only_after_ready_and_preserve_exact_progress() {
    let capture = synthetic_pcap(&[&[1, 2, 3], &[4, 5, 6, 7]]);
    let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
    let mut state = BoundaryState::new();
    let import = state
        .begin_import(capture)
        .expect("valid synthetic capture begins importing");
    assert_eq!(import.kind(), Some(HandleKind::Import));
    let initial = state
        .import_progress(import)
        .expect("initial import progress is available");
    assert_eq!(initial.phase, ImportPhase::Importing);
    assert_eq!(initial.consumed_bytes, 0);
    assert_eq!(initial.total_bytes, capture_length);
    assert_eq!(
        state
            .finish_import(import)
            .expect_err("an importing handle cannot publish")
            .code(),
        BoundaryErrorCode::INVALID_STATE
    );

    for (records, bytes) in [
        (0, 1),
        (1, 0),
        (MAX_IMPORT_STEP_RECORDS + 1, 1),
        (1, MAX_IMPORT_STEP_BYTES + 1),
    ] {
        assert_eq!(
            state
                .advance_import(import, records, bytes)
                .expect_err("invalid step budget is rejected before mutation")
                .code(),
            BoundaryErrorCode::INVALID_ARGUMENT
        );
    }
    assert_eq!(state.import_progress(import), Ok(initial));

    let needs = state
        .advance_import(import, 1, 1)
        .expect("small byte budget reports the required complete record");
    let ImportAdvance::NeedsBudget {
        progress,
        minimum_bytes,
    } = needs
    else {
        panic!("global header cannot fit a one-byte step")
    };
    assert_eq!(progress, initial);
    assert!(minimum_bytes > 1);

    let ready = advance_until_ready(&mut state, import);
    assert_eq!(ready.total_bytes, capture_length);
    assert_eq!(ready.packets_retained, 2);
    let published = state
        .finish_import(import)
        .expect("ready canonical dataset publishes atomically");
    assert_eq!(published.progress.phase, ImportPhase::Published);
    assert_eq!(
        published.progress,
        ImportProgressSnapshot {
            phase: ImportPhase::Published,
            ..ready
        }
    );
    assert_eq!(published.dataset.kind(), Some(HandleKind::Dataset));
    assert_eq!(state.dataset_packet_count(published.dataset), Ok(2));
    assert_eq!(
        state
            .import_progress(import)
            .expect_err("publication consumes the import handle")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );
    let repeat = state
        .cancel_import(import)
        .expect("terminal import cleanup is idempotent");
    assert_eq!(repeat.status, DisposeStatus::AlreadyDisposed);
    assert_eq!(repeat.progress, None);

    let snapshot = state.resource_stats().expect("published stats are exact");
    assert_eq!(snapshot.active_imports, 0);
    assert_eq!(snapshot.active_datasets, 1);
    assert_eq!(snapshot.transient_import_input_bytes, 0);
    assert_eq!(snapshot.retained_capture_bytes, capture_length);
}

#[test]
fn import_cancellation_is_deterministic_before_between_and_after_steps() {
    let capture = synthetic_pcap(&[&[1, 2, 3]]);
    let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
    let mut state = BoundaryState::new();

    let before = state
        .begin_import(capture.clone())
        .expect("first import is registered");
    let cancelled = state
        .cancel_import(before)
        .expect("cancellation before parsing succeeds");
    assert_eq!(cancelled.status, DisposeStatus::Disposed);
    let before_progress = cancelled.progress.expect("terminal counters are returned");
    assert_eq!(before_progress.phase, ImportPhase::Cancelled);
    assert_eq!(before_progress.consumed_bytes, 0);
    assert_eq!(before_progress.total_bytes, capture_length);
    for error in [
        state
            .import_progress(before)
            .expect_err("cancelled progress remains a terminal tombstone"),
        state
            .advance_import(before, 1, 1)
            .expect_err("cancelled import cannot advance"),
        state
            .finish_import(before)
            .expect_err("cancelled import cannot publish"),
    ] {
        assert_eq!(error.code(), BoundaryErrorCode::CANCELLED);
    }
    assert_eq!(
        state
            .cancel_import(before)
            .expect("repeated cancellation is idempotent before slot reuse")
            .status,
        DisposeStatus::AlreadyDisposed
    );

    let between = state
        .begin_import(capture.clone())
        .expect("slot is safely reused at a new generation");
    assert_ne!(before, between);
    assert_eq!(
        state
            .cancel_import(before)
            .expect_err("old cancellation tombstone expires when its slot is reused")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );
    let step = state
        .advance_import(between, 1, MAX_IMPORT_STEP_BYTES)
        .expect("one bounded step succeeds");
    let ImportAdvance::Progress(step_progress) = step else {
        panic!("one record leaves the packet record for a later step")
    };
    assert!(step_progress.consumed_bytes > 0);
    let between_cancel = state
        .cancel_import(between)
        .expect("cancellation between steps succeeds");
    assert_eq!(
        between_cancel
            .progress
            .expect("last counters are returned")
            .consumed_bytes,
        step_progress.consumed_bytes
    );

    let ready_import = state
        .begin_import(capture)
        .expect("third generation is registered");
    let ready = advance_until_ready(&mut state, ready_import);
    let ready_cancel = state
        .cancel_import(ready_import)
        .expect("ready import can be cancelled instead of published");
    assert_eq!(ready_cancel.status, DisposeStatus::Disposed);
    let terminal = ready_cancel.progress.expect("ready counters are retained");
    assert_eq!(terminal.phase, ImportPhase::Cancelled);
    assert_eq!(terminal.consumed_bytes, ready.consumed_bytes);
    assert_eq!(
        state
            .resource_stats()
            .expect("all imports released")
            .active_imports,
        0
    );
}

#[test]
fn fatal_import_errors_release_state_and_keep_error_context_payload_free() {
    let mut state = BoundaryState::new();
    let truncated = state
        .begin_import(vec![0xd4, 0xc3, 0xb2].into_boxed_slice())
        .expect_err("partial initial header is distinctly truncated");
    assert_eq!(truncated.code(), BoundaryErrorCode::TRUNCATED_CAPTURE);
    assert_eq!(truncated.input_offset(), Some(0));
    assert_eq!(truncated.resource_limit(), None);
    assert_eq!(truncated.terminal_import_progress(), None);

    let invalid = state
        .begin_import(vec![0_u8; 24].into_boxed_slice())
        .expect_err("unknown capture header is rejected");
    assert_eq!(invalid.code(), BoundaryErrorCode::CAPTURE_FORMAT);
    assert_eq!(invalid.input_offset(), None);
    assert_eq!(
        state
            .resource_stats()
            .expect("failed begin retains nothing")
            .active_imports,
        0
    );

    let incompatible_limits = ImportLimits {
        max_block_bytes: u32::try_from(MAX_IMPORT_STEP_BYTES + 1)
            .expect("step cap plus one fits u32"),
        ..ImportLimits::default()
    };
    assert_eq!(
        state
            .begin_import_with_limits(synthetic_pcap(&[]), incompatible_limits)
            .expect_err("unserviceable block ceiling is rejected")
            .code(),
        BoundaryErrorCode::INVALID_ARGUMENT
    );

    let limits = ImportLimits {
        max_packets: 1,
        ..ImportLimits::default()
    };
    let import = state
        .begin_import_with_limits(synthetic_pcap(&[&[1], &[2]]), limits)
        .expect("valid input begins below the packet ceiling");
    let failure = state
        .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
        .expect_err("second packet reaches the configured resource ceiling");
    assert_eq!(failure.code(), BoundaryErrorCode::RESOURCE_LIMIT);
    assert_eq!(failure.resource_limit(), Some(1));
    assert!(failure.input_offset().is_some_and(|offset| offset > 0));
    assert!(!failure.message().contains('1'));
    let failed_progress = failure
        .terminal_import_progress()
        .expect("fatal step reports its last valid counters");
    assert_eq!(failed_progress.phase, ImportPhase::Failed);
    assert_eq!(failed_progress.total_bytes, 58);
    assert_eq!(failed_progress.packets_retained, 1);
    assert_eq!(
        state
            .resource_stats()
            .expect("fatal step is reclaimed")
            .active_imports,
        0
    );
    assert_eq!(
        state
            .cancel_import(import)
            .expect("failed import handle is terminal")
            .status,
        DisposeStatus::AlreadyDisposed
    );
}

#[test]
fn truncated_capture_finishes_with_bounded_diagnostics_instead_of_panicking() {
    let mut bytes = synthetic_pcap(&[]).into_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let capture_length = u64::try_from(bytes.len()).expect("capture length fits u64");
    let mut state = BoundaryState::new();
    let import = state
        .begin_import(bytes.into_boxed_slice())
        .expect("valid header permits bounded truncated-record recovery");
    let ready = advance_until_ready(&mut state, import);
    assert_eq!(ready.phase, ImportPhase::Ready);
    assert_eq!(ready.diagnostics, 1);
    assert!(ready.consumed_bytes <= capture_length);
    let published = state
        .finish_import(import)
        .expect("safely diagnosed truncated capture remains inspectable");
    assert_eq!(published.progress.diagnostics, 1);
    assert_eq!(state.dataset_packet_count(published.dataset), Ok(0));
    assert_eq!(state.dataset_diagnostic_count(published.dataset), Ok(1));
    let diagnostic = state
        .dataset_diagnostic(published.dataset, 0)
        .expect("diagnostic lookup succeeds")
        .expect("truncation diagnostic exists");
    assert_eq!(diagnostic.diagnostic.code, DiagnosticCode::TRUNCATED_RECORD);
    assert_eq!(diagnostic.diagnostic.severity, Severity::Error);
    assert_eq!(diagnostic.diagnostic.recovery, Recovery::RecordSkipped);
    assert_eq!(diagnostic.diagnostic.scope, DiagnosticScope::Capture);
    let evidence = diagnostic
        .diagnostic
        .byte_range
        .expect("truncation has exact evidence");
    assert_eq!(evidence.start(), 24);
    assert_eq!(evidence.length(), 18);
    assert_eq!(
        diagnostic.message,
        "capture ended before the declared record length"
    );
    assert_eq!(state.dataset_diagnostic(published.dataset, 1), Ok(None));
}

#[test]
fn production_import_path_invokes_the_link_layer_decoder() {
    let mut state = BoundaryState::new();
    let import = state
        .begin_import(synthetic_ethernet_pcap(&[&[0; 10]]))
        .expect("bounded truncated Ethernet fixture begins importing");
    let ready = advance_until_ready(&mut state, import);
    assert_eq!(ready.packets_retained, 1);
    assert_eq!(ready.diagnostics, 1);

    let published = state
        .finish_import(import)
        .expect("packet-scoped decode warning remains publishable");
    let diagnostic = state
        .dataset_diagnostic(published.dataset, 0)
        .expect("diagnostic query succeeds")
        .expect("truncated Ethernet warning exists");
    assert_eq!(
        diagnostic.diagnostic.code,
        DiagnosticCode::TRUNCATED_PROTOCOL
    );
    assert_eq!(
        diagnostic.diagnostic.scope,
        DiagnosticScope::Packet(PacketId(0))
    );
    assert_eq!(diagnostic.diagnostic.recovery, Recovery::Continued);
    assert_eq!(diagnostic.diagnostic.byte_range, Some(range(40, 10)));
}

#[test]
fn pre_copy_admission_is_non_mutating_and_derives_stable_memory_limits() {
    let state = BoundaryState::new();
    let before = state.resource_stats().expect("empty stats are exact");
    let admission = state
        .admit_import_input(u64::from(CAPTURE_BYTES_PER_PACKET))
        .expect("small capture is admitted before allocation");
    assert_eq!(admission.input_bytes(), u64::from(CAPTURE_BYTES_PER_PACKET));
    assert_eq!(
        admission.limits().max_packets,
        CAPTURE_PACKET_BASE_ALLOWANCE + 1
    );
    assert_eq!(admission.limits().max_block_bytes, MAX_CAPTURE_BLOCK_BYTES);
    assert_eq!(
        admission.limits().max_decoded_items_per_block,
        MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK
    );
    assert_eq!(
        admission.limits().max_decoded_items_per_step,
        MAX_CAPTURE_DECODED_ITEMS_PER_STEP
    );
    assert!(admission.auxiliary_bytes_upper_bound() > 0);
    assert_eq!(
        admission.resulting_owned_capture_bytes(),
        u64::from(CAPTURE_BYTES_PER_PACKET)
    );
    assert_eq!(state.resource_stats(), Ok(before));

    let oversized = state
        .admit_import_input(MAX_CAPTURE_BYTES + 1)
        .expect_err("per-capture limit is checked without allocating input");
    assert_eq!(oversized.code(), BoundaryErrorCode::RESOURCE_LIMIT);
    assert_eq!(oversized.resource_limit(), Some(MAX_CAPTURE_BYTES));
    assert_eq!(state.resource_stats(), Ok(before));
}

#[test]
fn packet_admission_is_absolute_and_proportional_and_reclaims_dense_failures() {
    assert_eq!(packet_limit_for_capture(0), CAPTURE_PACKET_BASE_ALLOWANCE);
    assert_eq!(
        packet_limit_for_capture(u64::from(CAPTURE_BYTES_PER_PACKET)),
        CAPTURE_PACKET_BASE_ALLOWANCE + 1
    );
    assert_eq!(packet_limit_for_capture(u64::MAX), MAX_CAPTURE_PACKETS);

    let capture = dense_empty_pcap(1_200);
    let limit = packet_limit_for_capture(capture.len() as u64);
    assert!(limit < 1_200);
    let mut state = BoundaryState::new();
    let import = state
        .begin_import(capture)
        .expect("dense capture begins within its byte limit");
    let failure = state
        .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
        .expect_err("dense packet metadata reaches its proportional ceiling");
    assert_eq!(failure.code(), BoundaryErrorCode::RESOURCE_LIMIT);
    assert_eq!(failure.resource_limit(), Some(u64::from(limit)));
    let clean = state.resource_stats().expect("fatal import is reclaimed");
    assert_eq!(clean.active_imports, 0);
    assert_eq!(clean.transient_import_input_bytes, 0);
    assert_eq!(clean.current_owned_capture_bytes, 0);
    assert!(clean.peak_transient_import_input_bytes > 0);
}

#[test]
fn import_registry_cap_is_enforced_before_constructing_another_importer() {
    let capture = synthetic_pcap(&[]);
    let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
    let mut state = BoundaryState::new();
    let mut imports = Vec::new();
    for _ in 0..MAX_IMPORT_HANDLES {
        imports.push(
            state
                .begin_import(capture.clone())
                .expect("bounded import registry has capacity"),
        );
    }
    assert_eq!(
        state
            .begin_import(capture)
            .expect_err("one importer beyond the cap is rejected")
            .code(),
        BoundaryErrorCode::REGISTRY_LIMIT
    );
    let snapshot = state.resource_stats().expect("registry stats are exact");
    assert_eq!(snapshot.active_imports as usize, MAX_IMPORT_HANDLES);
    assert_eq!(
        snapshot.transient_import_input_bytes,
        capture_length * u64::try_from(MAX_IMPORT_HANDLES).expect("handle cap fits u64")
    );
    assert!(snapshot.transient_auxiliary_bytes_upper_bound > 0);
    assert_eq!(
        snapshot.total_logical_bytes_upper_bound,
        snapshot.transient_import_input_bytes
            + snapshot.transient_parser_buffer_bytes_upper_bound
            + snapshot.transient_packet_index_bytes_upper_bound
            + snapshot.transient_auxiliary_bytes_upper_bound
    );
    for import in imports {
        assert_eq!(
            state
                .cancel_import(import)
                .expect("registered importer is reclaimed")
                .status,
            DisposeStatus::Disposed
        );
    }
    assert_eq!(
        state
            .resource_stats()
            .expect("cleanup is exact")
            .active_imports,
        0
    );
}

#[test]
fn dataset_capacity_failure_leaves_a_ready_import_available_for_retry() {
    let mut state = BoundaryState::new();
    let import = state
        .begin_import(synthetic_pcap(&[]))
        .expect("empty valid capture begins importing");
    let ready = advance_until_ready(&mut state, import);
    let mut datasets = Vec::new();
    for _ in 0..MAX_DATASET_HANDLES {
        datasets.push(
            state
                .register_dataset(empty_dataset())
                .expect("bounded dataset registry has capacity"),
        );
    }

    assert_eq!(
        state
            .finish_import(import)
            .expect_err("full dataset registry blocks publication")
            .code(),
        BoundaryErrorCode::REGISTRY_LIMIT
    );
    assert_eq!(state.import_progress(import), Ok(ready));

    state
        .dispose_dataset(datasets[0])
        .expect("one dataset slot is reclaimed");
    let published = state
        .finish_import(import)
        .expect("ready import publication can be retried");
    assert_eq!(published.progress.phase, ImportPhase::Published);
    assert_eq!(
        state
            .resource_stats()
            .expect("post-publication stats are exact")
            .active_datasets as usize,
        MAX_DATASET_HANDLES
    );
}

#[test]
fn external_dataset_registration_enforces_import_dimension_caps() {
    let mut state = BoundaryState::new();
    let oversized = usize::try_from(MAX_CAPTURE_STRING_BYTES)
        .expect("string limit fits usize")
        .checked_add(1)
        .expect("test size is representable");
    let error = state
        .register_dataset(dataset_with_interned_string_bytes(oversized))
        .expect_err("external datasets cannot bypass the string arena cap");
    assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
    assert_eq!(
        error.resource_limit(),
        Some(u64::from(MAX_CAPTURE_STRING_BYTES))
    );
    assert_eq!(
        state
            .resource_stats()
            .expect("stats remain available")
            .active_datasets,
        0
    );
}

#[test]
fn handles_are_kind_tagged_generational_and_word_exact() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset handle is allocated");
    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("cursor handle is allocated");

    assert_eq!(dataset.kind(), Some(HandleKind::Dataset));
    assert_eq!(cursor.kind(), Some(HandleKind::PacketCursor));
    assert!(dataset.raw() > (1_u64 << 53));
    assert_eq!(BoundaryHandle::from_words(dataset.words()), dataset);
    assert_eq!(
        state
            .dataset_packet_count(cursor)
            .expect_err("wrong handle kind is rejected")
            .code(),
        BoundaryErrorCode::WRONG_HANDLE_KIND
    );
    assert_eq!(
        state
            .dataset_packet_count(BoundaryHandle::from_raw(0))
            .expect_err("zero handle is invalid")
            .code(),
        BoundaryErrorCode::INVALID_HANDLE
    );
}

#[test]
fn dataset_disposal_cascades_and_is_idempotent_without_reviving_stale_handles() {
    let mut state = BoundaryState::new();
    let first = state
        .register_dataset(exact_dataset())
        .expect("first dataset is registered");
    let cursor = state
        .create_packet_cursor(first, 0)
        .expect("dependent cursor is registered");

    let report = state
        .dispose_dataset(first)
        .expect("live dataset disposal succeeds");
    assert_eq!(report.status, DisposeStatus::Disposed);
    assert_eq!(report.cascaded_packet_cursors, 1);
    assert_eq!(
        state
            .dispose_packet_cursor(cursor)
            .expect("cascaded cursor disposal is idempotent"),
        DisposeStatus::AlreadyDisposed
    );
    assert_eq!(
        state
            .read_packet_batch(cursor, 1)
            .expect_err("disposed cursor cannot be read")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );

    let second = state
        .register_dataset(empty_dataset())
        .expect("dataset slot can be reused at a new generation");
    assert_ne!(first, second);
    assert_eq!(
        state
            .dataset_packet_count(first)
            .expect_err("old dataset generation remains stale")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );
    assert_eq!(
        state
            .dispose_dataset(first)
            .expect_err("old dataset disposal becomes stale after slot reuse")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );
    assert_eq!(state.dataset_packet_count(second), Ok(0));
}

#[test]
fn empty_and_bounded_batches_advance_deterministically() {
    let mut state = BoundaryState::new();
    let empty = state
        .register_dataset(empty_dataset())
        .expect("empty dataset is registered");
    let empty_cursor = state
        .create_packet_cursor(empty, 0)
        .expect("end cursor is valid");
    let empty_batch = read_committed_batch(&mut state, empty_cursor, 16);
    assert_eq!(empty_batch.row_count(), 0);
    assert_eq!(empty_batch.start_row(), 0);
    assert_eq!(empty_batch.next_row(), 0);
    assert_eq!(empty_batch.total_rows(), 0);
    assert!(empty_batch.is_done());
    assert!(empty_batch.bytes().len() <= MAX_PACKET_BATCH_BYTES);

    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("cursor is registered");
    let zero = read_committed_batch(&mut state, cursor, 0);
    assert_eq!((zero.start_row(), zero.next_row()), (0, 0));
    assert!(!zero.is_done());
    let first = read_committed_batch(&mut state, cursor, 2);
    assert_eq!(
        (first.row_count(), first.start_row(), first.next_row()),
        (2, 0, 2)
    );
    assert!(!first.is_done());
    let second = read_committed_batch(&mut state, cursor, 2);
    assert_eq!(
        (second.row_count(), second.start_row(), second.next_row()),
        (1, 2, 3)
    );
    assert!(second.is_done());

    assert_eq!(
        state
            .read_packet_batch(cursor, MAX_PACKET_BATCH_ROWS + 1)
            .expect_err("row cap is enforced before allocation")
            .code(),
        BoundaryErrorCode::BATCH_ROW_LIMIT
    );
    assert_eq!(
        state
            .create_packet_cursor(dataset, 4)
            .expect_err("cursor cannot begin past packet count")
            .code(),
        BoundaryErrorCode::CURSOR_OUT_OF_RANGE
    );
}

#[test]
fn byte_limited_batches_fit_whole_rows_without_mutating_on_rejection() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let sizing_cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("sizing cursor is registered");
    let one_row_bytes = read_committed_batch(&mut state, sizing_cursor, 1)
        .bytes()
        .len();
    assert!(one_row_bytes > MIN_PACKET_BATCH_BYTES);
    assert_eq!(
        state
            .dispose_packet_cursor(sizing_cursor)
            .expect("sizing cursor is disposed"),
        DisposeStatus::Disposed
    );

    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("limited cursor is registered");
    for (rows, bytes, expected) in [
        (3, 0, BoundaryErrorCode::INVALID_ARGUMENT),
        (
            3,
            u32::try_from(MAX_PACKET_BATCH_BYTES + 1).expect("hard cap fits u32"),
            BoundaryErrorCode::INVALID_ARGUMENT,
        ),
        (
            MAX_PACKET_BATCH_ROWS + 1,
            u32::try_from(MAX_PACKET_BATCH_BYTES).expect("hard cap fits u32"),
            BoundaryErrorCode::BATCH_ROW_LIMIT,
        ),
        (
            3,
            u32::try_from(MIN_PACKET_BATCH_BYTES).expect("minimum envelope fits u32"),
            BoundaryErrorCode::BATCH_BYTE_LIMIT,
        ),
    ] {
        assert_eq!(
            state
                .read_packet_batch_limited(cursor, rows, bytes)
                .expect_err("invalid limit cannot advance the cursor")
                .code(),
            expected
        );
    }

    let first = state
        .read_packet_batch_limited(
            cursor,
            3,
            u32::try_from(one_row_bytes).expect("one-row batch length fits u32"),
        )
        .expect("exact budget fits the largest whole-row prefix");
    assert_eq!(
        (first.row_count(), first.start_row(), first.next_row()),
        (1, 0, 1)
    );
    assert_eq!(first.bytes().len(), one_row_bytes);
    commit_batch(&mut state, cursor, &first);

    let next = read_committed_batch(&mut state, cursor, 1);
    assert_eq!((next.start_row(), next.next_row()), (1, 2));

    let end_cursor = state
        .create_packet_cursor(dataset, 3)
        .expect("cursor at dataset end is valid");
    let end = state
        .read_packet_batch_limited(
            end_cursor,
            3,
            u32::try_from(MIN_PACKET_BATCH_BYTES).expect("minimum envelope fits u32"),
        )
        .expect("minimum envelope can encode an empty terminal page");
    assert_eq!(end.row_count(), 0);
    assert!(end.is_done());
    assert_eq!(end.bytes().len(), MIN_PACKET_BATCH_BYTES);
    commit_batch(&mut state, end_cursor, &end);
}

#[test]
fn packet_batch_commit_and_discard_are_transactional_and_exact() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("cursor is registered");

    let staged = state
        .read_packet_batch(cursor, 2)
        .expect("first response is staged");
    assert_eq!((staged.start_row(), staged.next_row()), (0, 2));
    assert_eq!(
        state
            .read_packet_batch(cursor, 1)
            .expect_err("a second response cannot bypass the pending transaction")
            .code(),
        BoundaryErrorCode::INVALID_STATE
    );
    assert_eq!(
        state
            .commit_packet_batch(
                cursor,
                BATCH_SCHEMA_VERSION + 1,
                staged.start_row(),
                staged.next_row(),
            )
            .expect_err("the pending schema version must match")
            .code(),
        BoundaryErrorCode::UNSUPPORTED_VERSION
    );
    assert_eq!(
        state
            .discard_packet_batch(
                cursor,
                BATCH_SCHEMA_VERSION,
                staged.start_row(),
                staged.next_row() + 1,
            )
            .expect_err("the pending range must match exactly")
            .code(),
        BoundaryErrorCode::INVALID_ARGUMENT
    );
    state
        .discard_packet_batch(
            cursor,
            BATCH_SCHEMA_VERSION,
            staged.start_row(),
            staged.next_row(),
        )
        .expect("a rejected response is discarded without advancing");

    let retry = state
        .read_packet_batch(cursor, 2)
        .expect("discard makes the same range readable again");
    assert_eq!(
        (retry.start_row(), retry.next_row()),
        (staged.start_row(), staged.next_row())
    );
    commit_batch(&mut state, cursor, &retry);
    assert_eq!(
        state
            .commit_packet_batch(
                cursor,
                BATCH_SCHEMA_VERSION,
                retry.start_row(),
                retry.next_row(),
            )
            .expect_err("a committed response cannot be acknowledged twice")
            .code(),
        BoundaryErrorCode::INVALID_STATE
    );

    let terminal = state
        .read_packet_batch(cursor, 1)
        .expect("commit advances to the remaining row");
    assert_eq!((terminal.start_row(), terminal.next_row()), (2, 3));
    state
        .dispose_packet_cursor(cursor)
        .expect("disposing a cursor also discards its pending transaction");
    assert_eq!(
        state
            .commit_packet_batch(
                cursor,
                BATCH_SCHEMA_VERSION,
                terminal.start_row(),
                terminal.next_row(),
            )
            .expect_err("a disposed cursor remains stale")
            .code(),
        BoundaryErrorCode::STALE_HANDLE
    );
}

#[test]
fn resource_statistics_track_registry_owned_bytes_and_handles() {
    let mut boundary = BoundaryState::new();
    assert_eq!(
        boundary.resource_stats().expect("empty stats are exact"),
        wasm_adapter::ResourceStats {
            active_imports: 0,
            active_datasets: 0,
            active_packet_cursors: 0,
            retained_capture_bytes: 0,
            transient_import_input_bytes: 0,
            retained_packet_index_bytes: 0,
            retained_index_bytes: 0,
            retained_logical_bytes: 0,
            transient_parser_buffer_bytes_upper_bound: 0,
            transient_packet_index_bytes_upper_bound: 0,
            transient_auxiliary_bytes_upper_bound: 0,
            total_logical_bytes_upper_bound: 0,
            current_owned_capture_bytes: 0,
            peak_owned_capture_bytes: 0,
            peak_transient_import_input_bytes: 0,
            retained_batch_bytes: 0,
        }
    );

    let dataset = boundary
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let first_cursor = boundary
        .create_packet_cursor(dataset, 0)
        .expect("first cursor is registered");
    let second_cursor = boundary
        .create_packet_cursor(dataset, 3)
        .expect("second cursor is registered");
    let batch = read_committed_batch(&mut boundary, first_cursor, 1);
    assert!(!batch.bytes().is_empty());

    let snapshot = boundary.resource_stats().expect("live stats are exact");
    assert_eq!(snapshot.active_imports, 0);
    assert_eq!(snapshot.active_datasets, 1);
    assert_eq!(snapshot.active_packet_cursors, 2);
    assert_eq!(snapshot.retained_capture_bytes, 512);
    assert_eq!(
        snapshot.retained_packet_index_bytes,
        u64::try_from(core::mem::size_of::<PacketRecord>() * 3)
            .expect("packet index bytes fit u64")
    );
    assert!(snapshot.retained_index_bytes >= snapshot.retained_packet_index_bytes);
    assert_eq!(
        snapshot.retained_logical_bytes,
        snapshot.retained_capture_bytes + snapshot.retained_index_bytes
    );
    assert_eq!(
        snapshot.total_logical_bytes_upper_bound,
        snapshot.retained_logical_bytes
    );
    assert_eq!(snapshot.transient_import_input_bytes, 0);
    assert_eq!(snapshot.retained_batch_bytes, 0);

    let report = boundary
        .dispose_dataset(dataset)
        .expect("dataset cleanup cascades both cursors");
    assert_eq!(report.cascaded_packet_cursors, 2);
    assert_eq!(
        boundary
            .dispose_packet_cursor(second_cursor)
            .expect("cascaded disposal is idempotent"),
        DisposeStatus::AlreadyDisposed
    );
    let clean = boundary.resource_stats().expect("clean stats are exact");
    assert_eq!(clean.active_datasets, 0);
    assert_eq!(clean.active_packet_cursors, 0);
    assert_eq!(clean.retained_capture_bytes, 0);
}

#[test]
fn packet_batch_header_descriptors_offsets_and_timestamps_are_exact() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let cursor = state
        .create_packet_cursor(dataset, 0)
        .expect("cursor is registered");
    let batch = read_committed_batch(&mut state, cursor, 2);
    let bytes = batch.bytes();

    assert_eq!(&bytes[0..8], b"WLPKTB01");
    assert_eq!(read_u16(bytes, 8), BATCH_SCHEMA_VERSION);
    assert_eq!(read_u32(bytes, 12), API_VERSION);
    assert_eq!(read_u32(bytes, 24), 2);
    assert_eq!(read_u64(bytes, 40), 0);
    assert_eq!(read_u64(bytes, 48), 2);
    assert_eq!(read_u64(bytes, 56), 3);
    assert_eq!(read_u32(bytes, 36) as usize, bytes.len());
    assert!(bytes.len() <= MAX_PACKET_BATCH_BYTES);

    for column in [
        PacketBatchColumn::PacketId,
        PacketBatchColumn::SectionId,
        PacketBatchColumn::InterfaceId,
        PacketBatchColumn::CapturedLength,
        PacketBatchColumn::OriginalLength,
        PacketBatchColumn::EvidenceLength,
        PacketBatchColumn::EvidenceOffset,
        PacketBatchColumn::TimestampSeconds,
        PacketBatchColumn::TimestampFraction,
        PacketBatchColumn::TimestampPresent,
        PacketBatchColumn::TimestampResolutionKind,
        PacketBatchColumn::TimestampResolutionExponent,
    ] {
        let descriptor = batch.descriptor(column).expect("descriptor exists");
        assert_eq!(descriptor.element_count, 2);
        assert_eq!(
            descriptor.byte_offset as usize % descriptor.element_type.element_type_width_for_test(),
            0
        );
        assert!(descriptor.byte_offset as usize + descriptor.byte_length as usize <= bytes.len());
    }

    assert_eq!(
        read_u32(bytes, column_offset(&batch, PacketBatchColumn::PacketId, 0)),
        0
    );
    assert_eq!(
        read_u32(
            bytes,
            column_offset(&batch, PacketBatchColumn::OriginalLength, 0),
        ),
        7
    );
    assert_eq!(
        read_u64(
            bytes,
            column_offset(&batch, PacketBatchColumn::EvidenceOffset, 1),
        ),
        80
    );
    assert_eq!(
        read_i64(
            bytes,
            column_offset(&batch, PacketBatchColumn::TimestampSeconds, 0),
        ),
        i64::MIN + 100
    );
    assert_eq!(
        read_u64(
            bytes,
            column_offset(&batch, PacketBatchColumn::TimestampFraction, 0),
        ),
        u64::MAX
    );
    assert_eq!(
        bytes[column_offset(&batch, PacketBatchColumn::TimestampPresent, 0)],
        1
    );
    assert_eq!(
        bytes[column_offset(&batch, PacketBatchColumn::TimestampResolutionExponent, 0,)],
        127
    );
    assert_eq!(
        bytes[column_offset(&batch, PacketBatchColumn::TimestampPresent, 1)],
        0
    );
    assert_eq!(
        read_u64(
            bytes,
            column_offset(&batch, PacketBatchColumn::TimestampFraction, 1),
        ),
        0
    );
}

#[test]
fn evidence_reads_are_borrowed_bounded_and_checked() {
    let mut state = BoundaryState::new();
    let dataset = state
        .register_dataset(exact_dataset())
        .expect("dataset is registered");
    let evidence = state
        .read_evidence(dataset, 64, 3)
        .expect("packet evidence range is valid");
    assert_eq!(evidence.offset(), 64);
    assert_eq!(evidence.bytes(), &[64, 65, 66]);

    assert_eq!(
        state
            .read_evidence(dataset, 0, MAX_EVIDENCE_BYTES + 1)
            .expect_err("evidence cap is enforced before allocation")
            .code(),
        BoundaryErrorCode::EVIDENCE_BYTE_LIMIT
    );
    assert_eq!(
        state
            .read_evidence(dataset, u64::MAX, 1)
            .expect_err("range addition must be checked")
            .code(),
        BoundaryErrorCode::ARITHMETIC_OVERFLOW
    );
    assert_eq!(
        state
            .read_evidence(dataset, 511, 2)
            .expect_err("range outside capture is rejected")
            .code(),
        BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE
    );
    let empty_tail = state
        .read_evidence(dataset, 512, 0)
        .expect("empty range at capture end is valid");
    assert!(empty_tail.bytes().is_empty());
}

trait ElementWidthForTest {
    fn element_type_width_for_test(self) -> usize;
}

impl ElementWidthForTest for wasm_adapter::BatchElementType {
    fn element_type_width_for_test(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U32 => 4,
            Self::U64 | Self::I64 => 8,
        }
    }
}
