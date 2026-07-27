//! Dataset ownership, cursor lifecycle, and bounded reads.

use core::{fmt, mem};

use packet_core::{
    CaptureDataset, CaptureImporter, DecodedField, Diagnostic, FieldId, ImportError, ImportLimits,
    ImportProgress as CoreImportProgress, ImportStep as CoreImportStep, InterfaceMetadata,
    LayerFact, SectionMetadata, StringId, decoder_scratch_bytes_upper_bound,
};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, DECODER_VOCABULARY_COUNT_UPPER_BOUND, LinkLayerDecoder,
};

use crate::{
    BoundaryError, BoundaryErrorCode, BoundaryHandle, HandleKind, PacketBatch,
    batch::{COLUMN_COUNT, encode_packet_batch, fitting_row_count},
    handle::{DecodedHandle, MAX_GENERATION},
};

/// Stable browser-facing API major version.
pub const API_VERSION: u32 = 1;
/// Maximum packet rows accepted in one batch request.
pub const MAX_PACKET_BATCH_ROWS: u32 = 65_536;
/// Hard maximum bytes in one packet-batch response (8 MiB).
pub const MAX_PACKET_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Smallest valid packet-batch envelope: header plus all descriptors.
pub const MIN_PACKET_BATCH_BYTES: usize = 64 + COLUMN_COUNT * 24;
/// Maximum raw evidence bytes borrowed by one call (1 MiB).
pub const MAX_EVIDENCE_BYTES: u32 = 1024 * 1024;
/// Maximum simultaneously registered datasets.
pub const MAX_DATASET_HANDLES: usize = 1_024;
/// Maximum simultaneously registered packet cursors.
pub const MAX_PACKET_CURSOR_HANDLES: usize = 65_536;
/// Maximum simultaneously registered incremental imports.
pub const MAX_IMPORT_HANDLES: usize = 16;
/// Maximum container records processed by one synchronous import step.
pub const MAX_IMPORT_STEP_RECORDS: u32 = 4_096;
/// Maximum complete record bytes processed by one synchronous import step.
pub const MAX_IMPORT_STEP_BYTES: u64 = 16 * 1024 * 1024;
/// Largest complete capture copied into one Wasm boundary import (256 MiB).
pub const MAX_CAPTURE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum capture bytes retained by imports and datasets together (384 MiB).
pub const MAX_TOTAL_CAPTURE_BYTES: u64 = 384 * 1024 * 1024;
/// Maximum known logical bytes retained or reserved by one boundary (512 MiB).
pub const MAX_TOTAL_LOGICAL_BYTES: u64 = 512 * 1024 * 1024;
/// Largest single capture record or PCAPNG block accepted by the worker (4 MiB).
pub const MAX_CAPTURE_BLOCK_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum PCAPNG options and list records decoded from one block.
pub const MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK: u32 = 4_096;
/// Maximum PCAPNG options and list records decoded by one import step.
pub const MAX_CAPTURE_DECODED_ITEMS_PER_STEP: u32 = 4_096;
/// Absolute packet-arena cap used to bound final canonical validation.
pub const MAX_CAPTURE_PACKETS: u32 = 131_072;
/// Fixed packet allowance for small captures before proportional admission applies.
pub const CAPTURE_PACKET_BASE_ALLOWANCE: u32 = 1_024;
/// Additional packet admission requires this many source bytes per packet.
pub const CAPTURE_BYTES_PER_PACKET: u32 = 256;
/// Maximum structured diagnostics retained for a browser import.
pub const MAX_CAPTURE_DIAGNOSTICS: u32 = 1_024;
/// Maximum bytes retained by the browser import string interner (256 KiB).
pub const MAX_CAPTURE_STRING_BYTES: u32 = 256 * 1024;
/// Maximum capture sections retained by one browser import.
pub const MAX_CAPTURE_SECTIONS: u32 = 1_024;
/// Maximum interfaces retained across one browser import.
pub const MAX_CAPTURE_INTERFACES: u32 = 16_384;
/// Maximum decoded protocol layers retained by one browser import.
pub const MAX_CAPTURE_LAYERS: u32 = 393_216;
/// Maximum decoded fields retained by one browser import.
pub const MAX_CAPTURE_FIELDS: u32 = 1_048_576;
/// Maximum decoded field-child references retained by one browser import.
pub const MAX_CAPTURE_FIELD_CHILDREN: u32 = 1_048_576;
/// Maximum decoded protocol layers emitted for one packet.
pub const MAX_CAPTURE_LAYERS_PER_PACKET: u32 = 32;
/// Maximum decoded fields emitted for one packet.
pub const MAX_CAPTURE_FIELDS_PER_PACKET: u32 = 1_024;
/// Maximum field-child references emitted for one packet.
pub const MAX_CAPTURE_FIELD_CHILDREN_PER_PACKET: u32 = 2_048;
/// Source-byte allowance used to derive a per-import decoded-layer ceiling.
pub const CAPTURE_BYTES_PER_DECODED_LAYER: u32 = 250;
/// Source-byte allowance used to derive a per-import decoded-field ceiling.
pub const CAPTURE_BYTES_PER_DECODED_FIELD: u32 = 63;
/// Source-byte allowance used to derive a per-import field-child ceiling.
pub const CAPTURE_BYTES_PER_FIELD_CHILD: u32 = 84;
/// Baseline decoded-layer allowance for the fixed small-capture packet allowance.
pub const CAPTURE_DECODED_LAYER_BASE_ALLOWANCE: u32 =
    CAPTURE_PACKET_BASE_ALLOWANCE * DECODER_MAX_LAYERS_PER_PACKET;
/// Baseline decoded-field allowance for the fixed small-capture packet allowance.
pub const CAPTURE_DECODED_FIELD_BASE_ALLOWANCE: u32 =
    CAPTURE_PACKET_BASE_ALLOWANCE * DECODER_MAX_FIELDS_PER_PACKET;
/// Baseline field-child allowance for the fixed small-capture packet allowance.
pub const CAPTURE_FIELD_CHILD_BASE_ALLOWANCE: u32 =
    CAPTURE_PACKET_BASE_ALLOWANCE * DECODER_MAX_FIELD_CHILDREN_PER_PACKET;

/// Pre-copy admission result for one complete capture input.
///
/// The worker obtains this value before allocating its Rust-owned input copy.
/// The enclosed limits are derived from the admitted byte length, including
/// the proportional packet-arena ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportAdmission {
    input_bytes: u64,
    resulting_owned_capture_bytes: u64,
    resulting_transient_import_input_bytes: u64,
    parser_buffer_bytes_upper_bound: u64,
    packet_index_bytes_upper_bound: u64,
    auxiliary_bytes_upper_bound: u64,
    resulting_logical_bytes_upper_bound: u64,
    limits: ImportLimits,
}

impl ImportAdmission {
    /// Returns the exact input byte length covered by this admission.
    #[must_use]
    pub const fn input_bytes(self) -> u64 {
        self.input_bytes
    }

    /// Returns retained plus transient capture bytes after registration.
    #[must_use]
    pub const fn resulting_owned_capture_bytes(self) -> u64 {
        self.resulting_owned_capture_bytes
    }

    /// Returns transient input bytes after this import is registered.
    #[must_use]
    pub const fn resulting_transient_import_input_bytes(self) -> u64 {
        self.resulting_transient_import_input_bytes
    }

    /// Returns the conservative auxiliary-arena reservation for this import.
    #[must_use]
    pub const fn auxiliary_bytes_upper_bound(self) -> u64 {
        self.auxiliary_bytes_upper_bound
    }

    /// Returns the post-registration logical-memory upper bound.
    #[must_use]
    pub const fn resulting_logical_bytes_upper_bound(self) -> u64 {
        self.resulting_logical_bytes_upper_bound
    }

    /// Returns the parser limits derived for this input.
    #[must_use]
    pub const fn limits(self) -> ImportLimits {
        self.limits
    }
}

/// One bounded diagnostic resolved to its safe interned message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetDiagnostic<'a> {
    /// Canonical structured diagnostic fields.
    pub diagnostic: Diagnostic,
    /// Non-payload-bearing text resolved from the dataset string arena.
    pub message: &'a str,
}

/// Payload-free snapshot of resources retained by the boundary state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceStats {
    /// Active incremental capture imports.
    pub active_imports: u32,
    /// Published immutable datasets.
    pub active_datasets: u32,
    /// Active packet cursors.
    pub active_packet_cursors: u32,
    /// Capture bytes retained by published datasets.
    pub retained_capture_bytes: u64,
    /// Owned input bytes retained by in-progress importers.
    pub transient_import_input_bytes: u64,
    /// Exact bytes in the published packet-record arenas.
    pub retained_packet_index_bytes: u64,
    /// Exact bytes in all published canonical index and interned-string arenas.
    pub retained_index_bytes: u64,
    /// Capture plus canonical index bytes retained by datasets.
    pub retained_logical_bytes: u64,
    /// Conservative parser-buffer ceiling for currently active imports.
    pub transient_parser_buffer_bytes_upper_bound: u64,
    /// Conservative packet-record allocation ceiling for active imports.
    pub transient_packet_index_bytes_upper_bound: u64,
    /// Conservative non-packet arena and finalization ceiling for active imports.
    pub transient_auxiliary_bytes_upper_bound: u64,
    /// Known retained bytes plus conservative active-import reservations.
    pub total_logical_bytes_upper_bound: u64,
    /// Current capture bytes owned by imports and datasets together.
    pub current_owned_capture_bytes: u64,
    /// High-water mark for capture bytes owned by this boundary instance.
    pub peak_owned_capture_bytes: u64,
    /// High-water mark for in-progress owned input bytes.
    pub peak_transient_import_input_bytes: u64,
    /// Batch bytes retained by the registry; always zero because batches move out.
    pub retained_batch_bytes: u64,
}

/// Stable lifecycle phase attached to every import progress snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImportPhase {
    /// More bounded parser steps may be required.
    Importing,
    /// Parsing reached a terminal condition and can be finalized.
    Ready,
    /// Canonical validation succeeded and a dataset was published.
    Published,
    /// The caller cancelled the import and its owned state was released.
    Cancelled,
    /// A fatal import error released the importer without publishing data.
    Failed,
}

impl ImportPhase {
    /// Returns the stable numeric phase identifier used by bindings.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Importing => 1,
            Self::Ready => 2,
            Self::Published => 3,
            Self::Cancelled => 4,
            Self::Failed => 5,
        }
    }
}

/// Exact, monotonic capture-import progress safe for worker messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportProgressSnapshot {
    /// Current lifecycle phase.
    pub phase: ImportPhase,
    /// Bytes belonging to completely consumed capture records.
    pub consumed_bytes: u64,
    /// Exact owned input length.
    pub total_bytes: u64,
    /// Completely processed container records.
    pub records_processed: u64,
    /// Packet records retained so far.
    pub packets_retained: u64,
    /// Bounded structured diagnostics retained so far.
    pub diagnostics: u32,
}

/// Outcome of one bounded capture-import step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportAdvance {
    /// The supplied step budget was consumed and more input remains.
    Progress(ImportProgressSnapshot),
    /// The next record was left untouched because it exceeds this byte budget.
    NeedsBudget {
        /// Unchanged import progress.
        progress: ImportProgressSnapshot,
        /// Exact minimum budget required for the next complete record.
        minimum_bytes: u64,
    },
    /// Parsing reached a terminal condition and can be finalized.
    Ready(ImportProgressSnapshot),
}

/// Result of atomically validating and publishing a completed import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedDataset {
    /// Newly published immutable dataset handle.
    pub dataset: BoundaryHandle,
    /// Final counters, reported as published only after validation succeeds.
    pub progress: ImportProgressSnapshot,
}

/// Result of cancelling or repeatedly cancelling one import generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportCancelReport {
    /// Whether this call released a live importer.
    pub status: DisposeStatus,
    /// Last counters when this call performed cancellation.
    pub progress: Option<ImportProgressSnapshot>,
}

/// Result of an idempotent disposal request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisposeStatus {
    /// A live resource was disposed by this call.
    Disposed,
    /// The same handle generation had already been disposed.
    AlreadyDisposed,
}

/// Deterministic disposal result, including dependent resources reclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisposeReport {
    /// Whether this call performed the primary disposal.
    pub status: DisposeStatus,
    /// Packet cursors removed because their dataset was disposed.
    pub cascaded_packet_cursors: u32,
}

/// Borrowed, bounded evidence bytes.
///
/// The view cannot outlive the registry borrow, which prevents dataset
/// disposal while a native consumer reads it. A Wasm export must copy or
/// otherwise consume the bytes before returning to JavaScript.
pub struct EvidenceView<'a> {
    offset: u64,
    bytes: &'a [u8],
}

impl EvidenceView<'_> {
    /// Returns the exact source offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the bounded evidence bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl fmt::Debug for EvidenceView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceView")
            .field("offset", &self.offset)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

struct ImportEntry {
    importer: CaptureImporter,
    parser_buffer_bytes_upper_bound: u64,
    packet_index_bytes_upper_bound: u64,
    auxiliary_bytes_upper_bound: u64,
}

impl ImportEntry {
    fn finish(self) -> Result<CaptureDataset, ImportError> {
        self.importer.finish()
    }

    fn cancel(self) -> CoreImportProgress {
        self.importer.cancel()
    }
}

impl core::ops::Deref for ImportEntry {
    type Target = CaptureImporter;

    fn deref(&self) -> &Self::Target {
        &self.importer
    }
}

impl core::ops::DerefMut for ImportEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.importer
    }
}

/// Platform-neutral owner of capture datasets and dependent packet cursors.
///
/// The type is intended to live inside one worker/Wasm instance. It is not
/// synchronized; a worker serializes calls and owns the state exclusively.
pub struct BoundaryState {
    imports: Registry<ImportEntry>,
    datasets: Registry<CaptureDataset>,
    packet_cursors: Registry<PacketCursor>,
    cancelled_imports: [Option<BoundaryHandle>; MAX_IMPORT_HANDLES],
    peak_owned_capture_bytes: u64,
    peak_transient_import_input_bytes: u64,
}

impl BoundaryState {
    /// Creates an empty boundary registry with fixed resource caps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            imports: Registry::new(HandleKind::Import, MAX_IMPORT_HANDLES),
            datasets: Registry::new(HandleKind::Dataset, MAX_DATASET_HANDLES),
            packet_cursors: Registry::new(HandleKind::PacketCursor, MAX_PACKET_CURSOR_HANDLES),
            cancelled_imports: [None; MAX_IMPORT_HANDLES],
            peak_owned_capture_bytes: 0,
            peak_transient_import_input_bytes: 0,
        }
    }

    /// Checks registry and cumulative memory admission before an input copy is allocated.
    ///
    /// The returned limits apply an absolute packet ceiling plus a proportional
    /// allowance of [`CAPTURE_PACKET_BASE_ALLOWANCE`] plus one packet per
    /// [`CAPTURE_BYTES_PER_PACKET`] source bytes. Calling this method does not
    /// mutate the registry; a single-threaded worker can immediately allocate
    /// and pass the result to [`Self::begin_import_with_limits`].
    ///
    /// # Errors
    ///
    /// Returns a resource error when the import registry, per-capture byte
    /// limit, or cumulative retained-plus-transient byte limit is exhausted.
    pub fn admit_import_input(&self, input_bytes: u64) -> Result<ImportAdmission, BoundaryError> {
        self.admit_import_input_with_limits(input_bytes, ImportLimits::default())
    }

    /// Begins a bounded incremental import with default parser limits.
    ///
    /// Ownership of `bytes` transfers into the importer without a
    /// capture-sized clone. Failure releases the supplied allocation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported capture headers, captures above default resource
    /// limits, and a full import registry.
    pub fn begin_import(&mut self, bytes: Box<[u8]>) -> Result<BoundaryHandle, BoundaryError> {
        let input_bytes = u64::try_from(bytes.len()).map_err(|_| arithmetic_error())?;
        let admission = self.admit_import_input(input_bytes)?;
        self.begin_import_with_admission(bytes, admission)
    }

    /// Begins a bounded incremental import with explicit parser limits.
    ///
    /// `max_block_bytes` may not exceed [`MAX_IMPORT_STEP_BYTES`], ensuring
    /// every accepted complete block can be processed by a permitted step.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, unsupported capture headers, resource-limit
    /// violations, and a full import registry.
    pub fn begin_import_with_limits(
        &mut self,
        bytes: Box<[u8]>,
        limits: ImportLimits,
    ) -> Result<BoundaryHandle, BoundaryError> {
        let input_bytes = u64::try_from(bytes.len()).map_err(|_| arithmetic_error())?;
        let admission = self.admit_import_input_with_limits(input_bytes, limits)?;
        self.begin_import_with_admission(bytes, admission)
    }

    fn admit_import_input_with_limits(
        &self,
        input_bytes: u64,
        requested_limits: ImportLimits,
    ) -> Result<ImportAdmission, BoundaryError> {
        self.imports.ensure_insert_capacity()?;
        if input_bytes > MAX_CAPTURE_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::RESOURCE_LIMIT,
                "capture exceeds the per-import byte limit",
            )
            .with_resource_limit(MAX_CAPTURE_BYTES));
        }
        if u64::from(requested_limits.max_block_bytes) > MAX_IMPORT_STEP_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_ARGUMENT,
                "capture block limit exceeds the boundary step cap",
            ));
        }
        let limits = browser_import_limits(input_bytes, requested_limits);
        let stats = self.resource_stats()?;
        let currently_owned = stats.current_owned_capture_bytes;
        let resulting_owned_capture_bytes = currently_owned
            .checked_add(input_bytes)
            .ok_or_else(arithmetic_error)?;
        let resulting_transient_import_input_bytes = stats
            .transient_import_input_bytes
            .checked_add(input_bytes)
            .ok_or_else(arithmetic_error)?;
        if resulting_owned_capture_bytes > MAX_TOTAL_CAPTURE_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::RESOURCE_LIMIT,
                "capture registry exceeds the cumulative byte limit",
            )
            .with_resource_limit(MAX_TOTAL_CAPTURE_BYTES));
        }
        let packet_index_bytes_upper_bound = packet_index_bytes_for_limit(limits.max_packets)?;
        let parser_buffer_bytes_upper_bound =
            parser_buffer_bytes_for_capture(input_bytes, limits.max_block_bytes)?;
        let auxiliary_bytes_upper_bound = import_auxiliary_bytes_upper_bound(limits)?;
        let resulting_logical_bytes_upper_bound = resulting_import_logical_bytes(
            stats.total_logical_bytes_upper_bound,
            input_bytes,
            packet_index_bytes_upper_bound,
            parser_buffer_bytes_upper_bound,
            auxiliary_bytes_upper_bound,
        )?;
        Ok(ImportAdmission {
            input_bytes,
            resulting_owned_capture_bytes,
            resulting_transient_import_input_bytes,
            parser_buffer_bytes_upper_bound,
            packet_index_bytes_upper_bound,
            auxiliary_bytes_upper_bound,
            resulting_logical_bytes_upper_bound,
            limits,
        })
    }

    fn begin_import_with_admission(
        &mut self,
        bytes: Box<[u8]>,
        admission: ImportAdmission,
    ) -> Result<BoundaryHandle, BoundaryError> {
        let input_bytes = u64::try_from(bytes.len()).map_err(|_| arithmetic_error())?;
        if input_bytes != admission.input_bytes {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_ARGUMENT,
                "capture admission does not match the supplied input",
            ));
        }
        // Recheck immediately before mutation. This makes the platform-neutral
        // API safe even when callers do work between preflight and registration.
        let checked = self.admit_import_input_with_limits(input_bytes, admission.limits)?;
        let importer = CaptureImporter::new_with_decoder(
            bytes,
            checked.limits,
            Box::new(LinkLayerDecoder::new()),
        )
        .map_err(map_import_error)?;
        let handle = self.imports.insert(ImportEntry {
            importer,
            parser_buffer_bytes_upper_bound: checked.parser_buffer_bytes_upper_bound,
            packet_index_bytes_upper_bound: checked.packet_index_bytes_upper_bound,
            auxiliary_bytes_upper_bound: checked.auxiliary_bytes_upper_bound,
        })?;
        self.clear_cancelled_import(handle);
        self.peak_owned_capture_bytes = self
            .peak_owned_capture_bytes
            .max(checked.resulting_owned_capture_bytes);
        self.peak_transient_import_input_bytes = self
            .peak_transient_import_input_bytes
            .max(checked.resulting_transient_import_input_bytes);
        Ok(handle)
    }

    /// Returns the latest exact counters for a live import handle.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, and stale handles.
    pub fn import_progress(
        &self,
        import: BoundaryHandle,
    ) -> Result<ImportProgressSnapshot, BoundaryError> {
        if self.was_cancelled_import(import) {
            return Err(cancelled_import_error());
        }
        let importer = self.imports.get(import)?;
        let phase = if importer.is_complete() {
            ImportPhase::Ready
        } else {
            ImportPhase::Importing
        };
        Ok(import_progress(importer.progress(), phase))
    }

    /// Advances one import by bounded records and complete-record bytes.
    ///
    /// A fatal importer failure disposes the import before returning its
    /// payload-free structured error. Recoverable malformed or truncated
    /// framing becomes bounded diagnostics and a [`ImportAdvance::Ready`]
    /// result, as defined by `packet-core`.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-limit budgets, invalid handles, fatal capture
    /// errors, and resource-limit violations.
    pub fn advance_import(
        &mut self,
        import: BoundaryHandle,
        max_records: u32,
        max_bytes: u64,
    ) -> Result<ImportAdvance, BoundaryError> {
        if self.was_cancelled_import(import) {
            return Err(cancelled_import_error());
        }
        if max_records == 0
            || max_records > MAX_IMPORT_STEP_RECORDS
            || max_bytes == 0
            || max_bytes > MAX_IMPORT_STEP_BYTES
        {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_ARGUMENT,
                "capture import step budget is outside the supported range",
            ));
        }

        let step = self.imports.get_mut(import)?.step(max_records, max_bytes);
        let step = match step {
            Ok(step) => step,
            Err(error) => {
                let progress = self.imports.get(import)?.progress();
                let removal = self.imports.remove(import)?;
                drop(removal.value);
                return Err(map_import_error(error)
                    .with_import_progress(import_progress(progress, ImportPhase::Failed)));
            }
        };
        Ok(match step {
            CoreImportStep::Progress(progress) => {
                ImportAdvance::Progress(import_progress(progress, ImportPhase::Importing))
            }
            CoreImportStep::NeedsBudget {
                progress,
                minimum_bytes,
            } => ImportAdvance::NeedsBudget {
                progress: import_progress(progress, ImportPhase::Importing),
                minimum_bytes,
            },
            CoreImportStep::Ready(progress) => {
                ImportAdvance::Ready(import_progress(progress, ImportPhase::Ready))
            }
        })
    }

    /// Consumes a ready importer and atomically publishes its validated dataset.
    ///
    /// Dataset capacity is checked before consuming the importer. A full
    /// dataset registry therefore leaves the ready import intact for retry.
    /// No dataset handle is returned unless canonical model validation and
    /// registry publication both succeed.
    ///
    /// # Errors
    ///
    /// Rejects imports that are not ready, invalid handles, dataset registry
    /// exhaustion, and final canonical model failures.
    pub fn finish_import(
        &mut self,
        import: BoundaryHandle,
    ) -> Result<PublishedDataset, BoundaryError> {
        if self.was_cancelled_import(import) {
            return Err(cancelled_import_error());
        }
        let importer = self.imports.get(import)?;
        if !importer.is_complete() {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_STATE,
                "capture import is not ready to publish",
            ));
        }
        let progress = importer.progress();
        // Reserve the publication slot before consuming the ready importer.
        // A fallible registry allocation therefore cannot turn an otherwise
        // retryable ready import into an unpublished dropped dataset.
        self.datasets.reserve_insert_capacity()?;

        let removal = self.imports.remove(import)?;
        if removal.status != DisposeStatus::Disposed {
            return Err(internal_registry_error());
        }
        let importer = removal.value.ok_or_else(internal_registry_error)?;
        let failed_progress = import_progress(progress, ImportPhase::Failed);
        let dataset = importer
            .finish()
            .map_err(|error| map_import_error(error).with_import_progress(failed_progress))?;
        let dataset = self
            .register_dataset(dataset)
            .map_err(|error| error.with_import_progress(failed_progress))?;
        Ok(PublishedDataset {
            dataset,
            progress: import_progress(progress, ImportPhase::Published),
        })
    }

    /// Cancels a live import and releases all capture and parser allocations.
    ///
    /// Repeating cancellation for the same generation is idempotent and does
    /// not affect any importer that later reuses the registry slot.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, and unrelated stale handles.
    pub fn cancel_import(
        &mut self,
        import: BoundaryHandle,
    ) -> Result<ImportCancelReport, BoundaryError> {
        if self.was_cancelled_import(import) {
            return Ok(ImportCancelReport {
                status: DisposeStatus::AlreadyDisposed,
                progress: None,
            });
        }
        let removal = self.imports.remove(import)?;
        let progress = removal
            .value
            .map(ImportEntry::cancel)
            .map(|progress| import_progress(progress, ImportPhase::Cancelled));
        if removal.status == DisposeStatus::Disposed {
            self.remember_cancelled_import(import);
        }
        Ok(ImportCancelReport {
            status: removal.status,
            progress,
        })
    }

    /// Transfers one validated immutable dataset into boundary ownership.
    ///
    /// This is the importer integration seam. No capture bytes are copied by
    /// the registry; the dataset is moved into its handle slot.
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryErrorCode::REGISTRY_LIMIT`] when the bounded dataset
    /// registry cannot allocate a slot.
    pub fn register_dataset(
        &mut self,
        dataset: CaptureDataset,
    ) -> Result<BoundaryHandle, BoundaryError> {
        self.datasets.ensure_insert_capacity()?;
        let byte_length = dataset.metadata().byte_length;
        let packet_count = dataset.metadata().packet_count;
        let packet_limit = u64::from(packet_limit_for_capture(byte_length));
        if byte_length > MAX_CAPTURE_BYTES || packet_count > packet_limit {
            return Err(BoundaryError::new(
                BoundaryErrorCode::RESOURCE_LIMIT,
                "dataset exceeds a boundary capture or packet limit",
            )
            .with_resource_limit(if byte_length > MAX_CAPTURE_BYTES {
                MAX_CAPTURE_BYTES
            } else {
                packet_limit
            }));
        }
        for (actual, limit, message) in [
            (
                u64::try_from(dataset.sections().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_SECTIONS),
                "dataset exceeds the section limit",
            ),
            (
                u64::try_from(dataset.interfaces().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_INTERFACES),
                "dataset exceeds the interface limit",
            ),
            (
                u64::try_from(dataset.layers().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_LAYERS),
                "dataset exceeds the decoded-layer limit",
            ),
            (
                u64::try_from(dataset.fields().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_FIELDS),
                "dataset exceeds the decoded-field limit",
            ),
            (
                u64::try_from(dataset.field_children().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_FIELD_CHILDREN),
                "dataset exceeds the field-child limit",
            ),
            (
                u64::try_from(dataset.diagnostics().len()).map_err(|_| arithmetic_error())?,
                u64::from(MAX_CAPTURE_DIAGNOSTICS),
                "dataset exceeds the diagnostic limit",
            ),
            (
                dataset
                    .interned_string_bytes()
                    .ok_or_else(arithmetic_error)?,
                u64::from(MAX_CAPTURE_STRING_BYTES),
                "dataset exceeds the interned-string byte limit",
            ),
        ] {
            if actual > limit {
                return Err(
                    BoundaryError::new(BoundaryErrorCode::RESOURCE_LIMIT, message)
                        .with_resource_limit(limit),
                );
            }
        }
        let stats = self.resource_stats()?;
        let resulting_owned = stats
            .current_owned_capture_bytes
            .checked_add(byte_length)
            .ok_or_else(arithmetic_error)?;
        if resulting_owned > MAX_TOTAL_CAPTURE_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::RESOURCE_LIMIT,
                "dataset registry exceeds the cumulative byte limit",
            )
            .with_resource_limit(MAX_TOTAL_CAPTURE_BYTES));
        }
        let index_bytes = dataset
            .retained_index_bytes()
            .ok_or_else(arithmetic_error)?;
        resulting_dataset_logical_bytes(
            stats.total_logical_bytes_upper_bound,
            byte_length,
            index_bytes,
        )?;
        let handle = self.datasets.insert(dataset)?;
        self.peak_owned_capture_bytes = self.peak_owned_capture_bytes.max(resulting_owned);
        Ok(handle)
    }

    /// Returns the exact packet count for a live dataset.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, and stale handles.
    pub fn dataset_packet_count(&self, dataset: BoundaryHandle) -> Result<u64, BoundaryError> {
        Ok(self.datasets.get(dataset)?.metadata().packet_count)
    }

    /// Returns the bounded number of diagnostics retained by a dataset.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, and stale dataset handles.
    pub fn dataset_diagnostic_count(&self, dataset: BoundaryHandle) -> Result<u32, BoundaryError> {
        u32::try_from(self.datasets.get(dataset)?.diagnostics().len())
            .map_err(|_| arithmetic_error())
    }

    /// Resolves one structured diagnostic and its safe interned message.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, and stale dataset handles, as well as an
    /// invalid string-arena reference in a supposedly canonical dataset.
    pub fn dataset_diagnostic(
        &self,
        dataset: BoundaryHandle,
        index: u32,
    ) -> Result<Option<DatasetDiagnostic<'_>>, BoundaryError> {
        let dataset = self.datasets.get(dataset)?;
        let Some(diagnostic) = dataset.diagnostics().get(index as usize).copied() else {
            return Ok(None);
        };
        let message = dataset.string(diagnostic.message).ok_or_else(|| {
            BoundaryError::new(
                BoundaryErrorCode::INTERNAL_INVARIANT,
                "diagnostic message is outside the canonical string arena",
            )
        })?;
        Ok(Some(DatasetDiagnostic {
            diagnostic,
            message,
        }))
    }

    /// Creates a packet cursor at an exact zero-based dataset row.
    ///
    /// # Errors
    ///
    /// Rejects invalid dataset handles, starts beyond the packet count, and a
    /// full cursor registry.
    pub fn create_packet_cursor(
        &mut self,
        dataset: BoundaryHandle,
        start_row: u64,
    ) -> Result<BoundaryHandle, BoundaryError> {
        let packet_count = self.datasets.get(dataset)?.metadata().packet_count;
        if start_row > packet_count {
            return Err(BoundaryError::new(
                BoundaryErrorCode::CURSOR_OUT_OF_RANGE,
                "packet cursor starts beyond the dataset",
            ));
        }
        self.packet_cursors.insert(PacketCursor {
            dataset,
            next_row: start_row,
            pending_batch: None,
        })
    }

    /// Encodes and stages the next bounded packet batch without advancing.
    ///
    /// A successful read must be resolved with [`Self::commit_packet_batch`] or
    /// [`Self::discard_packet_batch`] before another read. Exact timestamps and
    /// 64-bit evidence offsets remain integers in the binary payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid/stale handles, requests above
    /// [`MAX_PACKET_BATCH_ROWS`], and any checked size/offset overflow.
    pub fn read_packet_batch(
        &mut self,
        cursor: BoundaryHandle,
        requested_rows: u32,
    ) -> Result<PacketBatch, BoundaryError> {
        self.read_packet_batch_limited(
            cursor,
            requested_rows,
            u32::try_from(MAX_PACKET_BATCH_BYTES).map_err(|_| arithmetic_error())?,
        )
    }

    /// Encodes the largest requested row prefix that fits a byte budget.
    ///
    /// The budget is inclusive and the returned payload never exceeds it or
    /// [`MAX_PACKET_BATCH_BYTES`]. Invalid budgets and planning errors are
    /// rejected before the cursor is mutated.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-hard-limit byte budgets, row requests above
    /// [`MAX_PACKET_BATCH_ROWS`], budgets unable to hold the fixed schema (or
    /// one row when rows remain), invalid handles, and checked arithmetic
    /// failures.
    pub fn read_packet_batch_limited(
        &mut self,
        cursor: BoundaryHandle,
        requested_rows: u32,
        requested_bytes: u32,
    ) -> Result<PacketBatch, BoundaryError> {
        let batch = self.prepare_packet_batch_limited(cursor, requested_rows, requested_bytes)?;
        self.stage_prepared_packet_batch(cursor, &batch)?;
        Ok(batch)
    }

    pub(crate) fn prepare_packet_batch_limited(
        &self,
        cursor: BoundaryHandle,
        requested_rows: u32,
        requested_bytes: u32,
    ) -> Result<PacketBatch, BoundaryError> {
        let requested_bytes = usize::try_from(requested_bytes).map_err(|_| arithmetic_error())?;
        if requested_bytes == 0 || requested_bytes > MAX_PACKET_BATCH_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_ARGUMENT,
                "packet batch byte budget is outside the supported range",
            ));
        }
        if requested_rows > MAX_PACKET_BATCH_ROWS {
            return Err(BoundaryError::new(
                BoundaryErrorCode::BATCH_ROW_LIMIT,
                "packet batch exceeds the row limit",
            ));
        }
        let cursor_state = *self.packet_cursors.get(cursor)?;
        if cursor_state.pending_batch.is_some() {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_STATE,
                "packet cursor has an uncommitted batch",
            ));
        }
        let dataset = self.datasets.get(cursor_state.dataset)?;
        let total_rows = dataset.metadata().packet_count;
        let remaining = total_rows
            .checked_sub(cursor_state.next_row)
            .ok_or_else(internal_registry_error)?;
        let available_rows = remaining.min(u64::from(requested_rows));
        let available_rows = u32::try_from(available_rows).map_err(|_| arithmetic_error())?;
        let fitted_rows =
            fitting_row_count(available_rows, MAX_PACKET_BATCH_ROWS, requested_bytes)?;
        let requested_end = cursor_state
            .next_row
            .checked_add(u64::from(fitted_rows))
            .ok_or_else(arithmetic_error)?;
        let next_row = requested_end;
        let start = usize::try_from(cursor_state.next_row).map_err(|_| arithmetic_error())?;
        let end = usize::try_from(next_row).map_err(|_| arithmetic_error())?;
        let Some(packets) = dataset.packets().get(start..end) else {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INTERNAL_INVARIANT,
                "cursor range is outside the canonical packet arena",
            ));
        };
        let batch = encode_packet_batch(
            packets,
            cursor_state.next_row,
            next_row,
            total_rows,
            API_VERSION,
            MAX_PACKET_BATCH_ROWS,
            requested_bytes,
        )?;
        Ok(batch)
    }

    pub(crate) fn stage_prepared_packet_batch(
        &mut self,
        cursor: BoundaryHandle,
        batch: &PacketBatch,
    ) -> Result<(), BoundaryError> {
        let cursor_state = self.packet_cursors.get_mut(cursor)?;
        if cursor_state.pending_batch.is_some() {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_STATE,
                "packet cursor has an uncommitted batch",
            ));
        }
        if cursor_state.next_row != batch.start_row() {
            return Err(internal_registry_error());
        }
        cursor_state.pending_batch = Some(PendingPacketBatch {
            schema_version: crate::BATCH_SCHEMA_VERSION,
            start_row: batch.start_row(),
            next_row: batch.next_row(),
        });
        Ok(())
    }

    /// Commits one previously encoded packet batch and advances its cursor.
    ///
    /// The schema version and exact start/next range must match the pending
    /// response. A mismatch leaves the response pending so the caller can
    /// discard it or retry the correct acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects invalid/stale handles, unsupported schema versions, cursors
    /// without a pending response, and mismatched response ranges.
    pub fn commit_packet_batch(
        &mut self,
        cursor: BoundaryHandle,
        schema_version: u16,
        start_row: u64,
        next_row: u64,
    ) -> Result<(), BoundaryError> {
        self.resolve_packet_batch(cursor, schema_version, start_row, next_row, true)
    }

    /// Discards one previously encoded packet batch without advancing its cursor.
    ///
    /// The schema version and exact start/next range must match the pending
    /// response. A mismatch leaves the response pending.
    ///
    /// # Errors
    ///
    /// Rejects invalid/stale handles, unsupported schema versions, cursors
    /// without a pending response, and mismatched response ranges.
    pub fn discard_packet_batch(
        &mut self,
        cursor: BoundaryHandle,
        schema_version: u16,
        start_row: u64,
        next_row: u64,
    ) -> Result<(), BoundaryError> {
        self.resolve_packet_batch(cursor, schema_version, start_row, next_row, false)
    }

    fn resolve_packet_batch(
        &mut self,
        cursor: BoundaryHandle,
        schema_version: u16,
        start_row: u64,
        next_row: u64,
        commit: bool,
    ) -> Result<(), BoundaryError> {
        let cursor = self.packet_cursors.get_mut(cursor)?;
        let Some(pending) = cursor.pending_batch else {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_STATE,
                "packet cursor has no pending batch",
            ));
        };
        if schema_version != pending.schema_version {
            return Err(BoundaryError::new(
                BoundaryErrorCode::UNSUPPORTED_VERSION,
                "packet batch schema version is unsupported",
            ));
        }
        if start_row != pending.start_row || next_row != pending.next_row {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_ARGUMENT,
                "packet batch acknowledgement range does not match the pending response",
            ));
        }
        if cursor.next_row != pending.start_row || pending.next_row < pending.start_row {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INTERNAL_INVARIANT,
                "packet cursor pending range is inconsistent",
            ));
        }
        if commit {
            cursor.next_row = pending.next_row;
        }
        cursor.pending_batch = None;
        Ok(())
    }

    /// Returns bounded counts and byte totals without capture-derived content.
    ///
    /// Returned batches are owned by the caller, so `retained_batch_bytes` is
    /// always zero. Transient import bytes count the one owned source capture
    /// per importer. Reader buffers and not-yet-finalized packet arenas are
    /// reported as conservative upper bounds derived from the stable limits;
    /// exact current capacities do not cross the `packet-core` ownership seam.
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryErrorCode::ARITHMETIC_OVERFLOW`] if a count or byte
    /// total cannot be represented exactly.
    pub fn resource_stats(&self) -> Result<ResourceStats, BoundaryError> {
        let transient_import_input_bytes =
            self.imports.values().try_fold(0_u64, |total, importer| {
                total
                    .checked_add(importer.progress().total_bytes)
                    .ok_or_else(arithmetic_error)
            })?;
        let retained_capture_bytes = self.datasets.values().try_fold(0_u64, |total, dataset| {
            total
                .checked_add(dataset.metadata().byte_length)
                .ok_or_else(arithmetic_error)
        })?;
        let (retained_packet_index_bytes, retained_index_bytes) = self.datasets.values().try_fold(
            (0_u64, 0_u64),
            |(packet_total, index_total), dataset| {
                let packet_bytes = dataset
                    .retained_packet_index_bytes()
                    .ok_or_else(arithmetic_error)?;
                let index_bytes = dataset
                    .retained_index_bytes()
                    .ok_or_else(arithmetic_error)?;
                Ok((
                    packet_total
                        .checked_add(packet_bytes)
                        .ok_or_else(arithmetic_error)?,
                    index_total
                        .checked_add(index_bytes)
                        .ok_or_else(arithmetic_error)?,
                ))
            },
        )?;
        let retained_logical_bytes = retained_capture_bytes
            .checked_add(retained_index_bytes)
            .ok_or_else(arithmetic_error)?;
        let current_owned_capture_bytes = retained_capture_bytes
            .checked_add(transient_import_input_bytes)
            .ok_or_else(arithmetic_error)?;
        let transient_parser_buffer_bytes_upper_bound =
            self.imports.values().try_fold(0_u64, |total, importer| {
                total
                    .checked_add(importer.parser_buffer_bytes_upper_bound)
                    .ok_or_else(arithmetic_error)
            })?;
        let transient_packet_index_bytes_upper_bound =
            self.imports.values().try_fold(0_u64, |total, importer| {
                total
                    .checked_add(importer.packet_index_bytes_upper_bound)
                    .ok_or_else(arithmetic_error)
            })?;
        let transient_auxiliary_bytes_upper_bound =
            self.imports.values().try_fold(0_u64, |total, importer| {
                total
                    .checked_add(importer.auxiliary_bytes_upper_bound)
                    .ok_or_else(arithmetic_error)
            })?;
        let total_logical_bytes_upper_bound = retained_logical_bytes
            .checked_add(transient_import_input_bytes)
            .and_then(|total| total.checked_add(transient_parser_buffer_bytes_upper_bound))
            .and_then(|total| total.checked_add(transient_packet_index_bytes_upper_bound))
            .and_then(|total| total.checked_add(transient_auxiliary_bytes_upper_bound))
            .ok_or_else(arithmetic_error)?;
        Ok(ResourceStats {
            active_imports: u32::try_from(self.imports.active_count)
                .map_err(|_| arithmetic_error())?,
            active_datasets: u32::try_from(self.datasets.active_count)
                .map_err(|_| arithmetic_error())?,
            active_packet_cursors: u32::try_from(self.packet_cursors.active_count)
                .map_err(|_| arithmetic_error())?,
            retained_capture_bytes,
            transient_import_input_bytes,
            retained_packet_index_bytes,
            retained_index_bytes,
            retained_logical_bytes,
            transient_parser_buffer_bytes_upper_bound,
            transient_packet_index_bytes_upper_bound,
            transient_auxiliary_bytes_upper_bound,
            total_logical_bytes_upper_bound,
            current_owned_capture_bytes,
            peak_owned_capture_bytes: self.peak_owned_capture_bytes,
            peak_transient_import_input_bytes: self.peak_transient_import_input_bytes,
            retained_batch_bytes: 0,
        })
    }

    fn clear_cancelled_import(&mut self, handle: BoundaryHandle) {
        if let Some(index) = import_slot_index(handle) {
            self.cancelled_imports[index] = None;
        }
    }

    fn remember_cancelled_import(&mut self, handle: BoundaryHandle) {
        if let Some(index) = import_slot_index(handle) {
            self.cancelled_imports[index] = Some(handle);
        }
    }

    fn was_cancelled_import(&self, handle: BoundaryHandle) -> bool {
        import_slot_index(handle).is_some_and(|index| self.cancelled_imports[index] == Some(handle))
    }

    /// Borrows a checked, bounded range from the retained capture buffer.
    ///
    /// # Errors
    ///
    /// Rejects requests over [`MAX_EVIDENCE_BYTES`], overflowing ranges,
    /// out-of-capture ranges, and invalid dataset handles.
    pub fn read_evidence(
        &self,
        dataset: BoundaryHandle,
        offset: u64,
        length: u32,
    ) -> Result<EvidenceView<'_>, BoundaryError> {
        if length > MAX_EVIDENCE_BYTES {
            return Err(BoundaryError::new(
                BoundaryErrorCode::EVIDENCE_BYTE_LIMIT,
                "evidence request exceeds the byte limit",
            ));
        }
        let end = offset
            .checked_add(u64::from(length))
            .ok_or_else(arithmetic_error)?;
        let capture = self.datasets.get(dataset)?;
        if end > capture.metadata().byte_length {
            return Err(BoundaryError::new(
                BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE,
                "evidence range is outside the capture",
            ));
        }
        let start = usize::try_from(offset).map_err(|_| arithmetic_error())?;
        let end = usize::try_from(end).map_err(|_| arithmetic_error())?;
        let Some(bytes) = capture.bytes().get(start..end) else {
            return Err(BoundaryError::new(
                BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE,
                "evidence range is outside the capture",
            ));
        };
        Ok(EvidenceView { offset, bytes })
    }

    /// Disposes a dataset and every packet cursor that depends on it.
    ///
    /// Repeating disposal for the same handle generation succeeds with
    /// [`DisposeStatus::AlreadyDisposed`]. Older unrelated generations remain
    /// stale and cannot affect a reused slot.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, or unrelated stale handles.
    pub fn dispose_dataset(
        &mut self,
        dataset: BoundaryHandle,
    ) -> Result<DisposeReport, BoundaryError> {
        let expected_status = self.datasets.preflight_remove(dataset)?;
        let cursor_plan = if expected_status == DisposeStatus::Disposed {
            Some(
                self.packet_cursors
                    .plan_remove_where(|cursor| cursor.dataset == dataset)?,
            )
        } else {
            None
        };
        let cascaded = cursor_plan.as_ref().map_or(0, RemoveWherePlan::removed);
        let cascaded_packet_cursors = u32::try_from(cascaded).map_err(|_| arithmetic_error())?;

        let removal = self.datasets.remove(dataset)?;
        debug_assert_eq!(removal.status, expected_status);
        if let Some(plan) = cursor_plan {
            let removed = self.packet_cursors.apply_remove_where(plan);
            debug_assert_eq!(removed, cascaded);
        }
        drop(removal.value);
        Ok(DisposeReport {
            status: removal.status,
            cascaded_packet_cursors,
        })
    }

    /// Disposes one packet cursor idempotently.
    ///
    /// # Errors
    ///
    /// Rejects malformed, wrong-kind, or unrelated stale handles.
    pub fn dispose_packet_cursor(
        &mut self,
        cursor: BoundaryHandle,
    ) -> Result<DisposeStatus, BoundaryError> {
        let removal = self.packet_cursors.remove(cursor)?;
        let _ = removal.value;
        Ok(removal.status)
    }
}

impl Default for BoundaryState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BoundaryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryState")
            .field("import_count", &self.imports.active_count)
            .field("dataset_count", &self.datasets.active_count)
            .field("packet_cursor_count", &self.packet_cursors.active_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketCursor {
    dataset: BoundaryHandle,
    next_row: u64,
    pending_batch: Option<PendingPacketBatch>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPacketBatch {
    schema_version: u16,
    start_row: u64,
    next_row: u64,
}

struct Registry<T> {
    kind: HandleKind,
    max_slots: usize,
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    active_count: usize,
}

impl<T> Registry<T> {
    fn new(kind: HandleKind, max_slots: usize) -> Self {
        Self {
            kind,
            max_slots,
            slots: Vec::new(),
            free: Vec::new(),
            active_count: 0,
        }
    }

    fn insert(&mut self, value: T) -> Result<BoundaryHandle, BoundaryError> {
        let next_active_count = self
            .active_count
            .checked_add(1)
            .ok_or_else(arithmetic_error)?;
        if let Some(&index) = self.free.last() {
            let slot = self
                .slots
                .get_mut(index as usize)
                .ok_or_else(internal_registry_error)?;
            if slot.retired || slot.value.is_some() {
                return Err(internal_registry_error());
            }
            let handle = BoundaryHandle::encode(self.kind, slot.generation, index)
                .ok_or_else(internal_registry_error)?;
            self.free.pop();
            slot.last_disposed_generation = None;
            slot.value = Some(value);
            self.active_count = next_active_count;
            return Ok(handle);
        }

        if self.slots.len() >= self.max_slots {
            return Err(BoundaryError::new(
                BoundaryErrorCode::REGISTRY_LIMIT,
                "boundary handle registry reached its slot limit",
            ));
        }
        let index = u32::try_from(self.slots.len()).map_err(|_| {
            BoundaryError::new(
                BoundaryErrorCode::REGISTRY_LIMIT,
                "boundary handle registry exhausted its index space",
            )
        })?;
        let generation = 1;
        let handle = BoundaryHandle::encode(self.kind, generation, index)
            .ok_or_else(internal_registry_error)?;
        reserve_registry_capacity(&mut self.slots, 1, self.max_slots)?;
        self.slots.push(Slot {
            generation,
            last_disposed_generation: None,
            retired: false,
            value: Some(value),
        });
        self.active_count = next_active_count;
        Ok(handle)
    }

    fn ensure_insert_capacity(&self) -> Result<(), BoundaryError> {
        if self.free.is_empty() && self.slots.len() >= self.max_slots {
            return Err(BoundaryError::new(
                BoundaryErrorCode::REGISTRY_LIMIT,
                "boundary handle registry reached its slot limit",
            ));
        }
        self.active_count
            .checked_add(1)
            .map(|_| ())
            .ok_or_else(arithmetic_error)
    }

    fn reserve_insert_capacity(&mut self) -> Result<(), BoundaryError> {
        self.ensure_insert_capacity()?;
        if self.free.is_empty() {
            reserve_registry_capacity(&mut self.slots, 1, self.max_slots)?;
        }
        Ok(())
    }

    fn get(&self, handle: BoundaryHandle) -> Result<&T, BoundaryError> {
        let decoded = self.decode_for_registry(handle)?;
        let slot = self.slot(decoded)?;
        if slot.generation != decoded.generation || slot.value.is_none() {
            return Err(stale_handle_error());
        }
        slot.value.as_ref().ok_or_else(internal_registry_error)
    }

    fn get_mut(&mut self, handle: BoundaryHandle) -> Result<&mut T, BoundaryError> {
        let decoded = self.decode_for_registry(handle)?;
        let slot = self.slot_mut(decoded)?;
        if slot.generation != decoded.generation || slot.value.is_none() {
            return Err(stale_handle_error());
        }
        slot.value.as_mut().ok_or_else(internal_registry_error)
    }

    fn remove(&mut self, handle: BoundaryHandle) -> Result<Removal<T>, BoundaryError> {
        let status = self.preflight_remove(handle)?;
        if status == DisposeStatus::AlreadyDisposed {
            return Ok(Removal {
                status,
                value: None,
            });
        }

        let decoded = self.decode_for_registry(handle)?;
        let slot = self.slot(decoded)?;
        let reusable = slot.generation != MAX_GENERATION;
        let next_active_count = self
            .active_count
            .checked_sub(1)
            .ok_or_else(internal_registry_error)?;

        let slot = self.slot_mut(decoded)?;
        let value = slot.value.take();
        slot.last_disposed_generation = Some(decoded.generation);
        if reusable {
            slot.generation += 1;
        } else {
            slot.retired = true;
        }
        self.active_count = next_active_count;
        if reusable {
            self.free.push(decoded.index);
        }
        Ok(Removal {
            status: DisposeStatus::Disposed,
            value,
        })
    }

    fn preflight_remove(&mut self, handle: BoundaryHandle) -> Result<DisposeStatus, BoundaryError> {
        let decoded = self.decode_for_registry(handle)?;
        let slot = self.slot(decoded)?;
        if slot.last_disposed_generation == Some(decoded.generation) {
            return Ok(DisposeStatus::AlreadyDisposed);
        }
        if slot.generation != decoded.generation || slot.value.is_none() {
            return Err(stale_handle_error());
        }
        self.active_count
            .checked_sub(1)
            .ok_or_else(internal_registry_error)?;
        if slot.generation != MAX_GENERATION {
            reserve_registry_capacity(&mut self.free, 1, self.max_slots)?;
        }
        Ok(DisposeStatus::Disposed)
    }

    fn plan_remove_where(
        &mut self,
        predicate: impl Fn(&T) -> bool,
    ) -> Result<RemoveWherePlan, BoundaryError> {
        let mut matching = Vec::new();
        reserve_registry_capacity(&mut matching, self.active_count, self.max_slots)?;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.value.as_ref().is_some_and(&predicate) {
                if matching.len() == matching.capacity() {
                    return Err(internal_registry_error());
                }
                matching.push(u32::try_from(index).map_err(|_| internal_registry_error())?);
            }
        }

        let removed = matching.len();
        let next_active_count = self
            .active_count
            .checked_sub(removed)
            .ok_or_else(internal_registry_error)?;
        let reusable = matching
            .iter()
            .filter(|&&index| self.slots[index as usize].generation != MAX_GENERATION)
            .count();
        reserve_registry_capacity(&mut self.free, reusable, self.max_slots)?;

        Ok(RemoveWherePlan {
            matching,
            next_active_count,
        })
    }

    fn apply_remove_where(&mut self, plan: RemoveWherePlan) -> usize {
        let removed = plan.removed();
        for index in plan.matching {
            let slot = &mut self.slots[index as usize];
            let generation = slot.generation;
            slot.value = None;
            slot.last_disposed_generation = Some(generation);
            if generation == MAX_GENERATION {
                slot.retired = true;
            } else {
                slot.generation += 1;
                self.free.push(index);
            }
        }
        self.active_count = plan.next_active_count;
        removed
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(|slot| slot.value.as_ref())
    }

    fn decode_for_registry(&self, handle: BoundaryHandle) -> Result<DecodedHandle, BoundaryError> {
        let decoded = handle.decode()?;
        if decoded.kind != self.kind {
            return Err(BoundaryError::new(
                BoundaryErrorCode::WRONG_HANDLE_KIND,
                "handle kind does not match the boundary operation",
            ));
        }
        Ok(decoded)
    }

    fn slot(&self, decoded: DecodedHandle) -> Result<&Slot<T>, BoundaryError> {
        self.slots.get(decoded.index as usize).ok_or_else(|| {
            BoundaryError::new(
                BoundaryErrorCode::INVALID_HANDLE,
                "handle slot was never allocated",
            )
        })
    }

    fn slot_mut(&mut self, decoded: DecodedHandle) -> Result<&mut Slot<T>, BoundaryError> {
        self.slots.get_mut(decoded.index as usize).ok_or_else(|| {
            BoundaryError::new(
                BoundaryErrorCode::INVALID_HANDLE,
                "handle slot was never allocated",
            )
        })
    }
}

struct Slot<T> {
    generation: u32,
    last_disposed_generation: Option<u32>,
    retired: bool,
    value: Option<T>,
}

struct Removal<T> {
    status: DisposeStatus,
    value: Option<T>,
}

#[derive(Debug)]
struct RemoveWherePlan {
    matching: Vec<u32>,
    next_active_count: usize,
}

impl RemoveWherePlan {
    fn removed(&self) -> usize {
        self.matching.len()
    }
}

fn arithmetic_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::ARITHMETIC_OVERFLOW,
        "boundary offset arithmetic overflowed",
    )
}

fn internal_registry_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::INTERNAL_INVARIANT,
        "boundary handle registry invariant failed",
    )
}

fn reserve_registry_capacity<T>(
    storage: &mut Vec<T>,
    additional: usize,
    max_slots: usize,
) -> Result<(), BoundaryError> {
    storage.try_reserve(additional).map_err(|_| {
        BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "boundary handle registry could not reserve storage",
        )
        .with_resource_limit(u64::try_from(max_slots).unwrap_or(u64::MAX))
    })
}

fn stale_handle_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::STALE_HANDLE,
        "handle generation is stale",
    )
}

fn cancelled_import_error() -> BoundaryError {
    BoundaryError::new(BoundaryErrorCode::CANCELLED, "capture import was cancelled")
}

fn import_slot_index(handle: BoundaryHandle) -> Option<usize> {
    if handle.kind() != Some(HandleKind::Import) {
        return None;
    }
    let slot_token = handle.words().low;
    let index = usize::try_from(slot_token.checked_sub(1)?).ok()?;
    (index < MAX_IMPORT_HANDLES).then_some(index)
}

fn packet_index_bytes_for_limit(max_packets: u32) -> Result<u64, BoundaryError> {
    // packet-core selects a cap-aware geometric target and retains at most the
    // configured total. The eight-slot floor conservatively covers the
    // allocator's minimum non-empty capacity for very small limits.
    arena_reservation_bytes::<packet_core::PacketRecord>(max_packets)
}

fn parser_buffer_bytes_for_capture(
    capture_bytes: u64,
    max_block_bytes: u32,
) -> Result<u64, BoundaryError> {
    // `circular::Buffer` requests one sentinel byte beyond the largest block,
    // and its internal `Vec::resize` may retain geometric spare capacity.
    capture_bytes
        .min(u64::from(max_block_bytes))
        .checked_add(1)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(arithmetic_error)
}

fn import_auxiliary_bytes_upper_bound(limits: ImportLimits) -> Result<u64, BoundaryError> {
    // The importer can intern at most one interface name per interface, one
    // safe message per diagnostic, and the decoder's fixed safe vocabulary.
    // packet-core's fixed-width arena vectors grow geometrically only up to
    // their configured total, so one capped arena is sufficient here. The
    // string finalization allocations remain accounted separately below.
    let string_count = u64::from(limits.max_interfaces)
        .checked_add(u64::from(limits.max_diagnostics))
        .and_then(|count| count.checked_add(u64::from(DECODER_VOCABULARY_COUNT_UPPER_BOUND)))
        .ok_or_else(arithmetic_error)?;
    let tree_pointer_reservation = type_bytes::<usize>()?
        .checked_mul(4)
        .ok_or_else(arithmetic_error)?;
    let string_map_entry_bytes = type_bytes::<Box<str>>()?
        .checked_add(type_bytes::<StringId>()?)
        .and_then(|bytes| bytes.checked_add(tree_pointer_reservation))
        .ok_or_else(arithmetic_error)?;
    let finalization_string_slots = type_bytes::<Option<Box<str>>>()?
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_mul(string_count))
        .ok_or_else(arithmetic_error)?;
    let validation_scratch = u64::from(limits.max_interfaces)
        .checked_add(u64::from(limits.max_layers))
        .and_then(|bytes| bytes.checked_add(u64::from(limits.max_diagnostics)))
        .and_then(|bytes| bytes.checked_add(u64::from(limits.max_field_children)))
        .and_then(|bytes| bytes.checked_add(u64::from(limits.max_fields).checked_mul(2)?))
        .ok_or_else(arithmetic_error)?;

    [
        arena_reservation_bytes::<SectionMetadata>(limits.max_sections)?,
        arena_reservation_bytes::<InterfaceMetadata>(limits.max_interfaces)?,
        arena_reservation_bytes::<i64>(limits.max_interfaces)?,
        arena_reservation_bytes::<LayerFact>(limits.max_layers)?,
        arena_reservation_bytes::<DecodedField>(limits.max_fields)?,
        arena_reservation_bytes::<FieldId>(limits.max_field_children)?,
        arena_reservation_bytes::<Diagnostic>(limits.max_diagnostics)?,
        decoder_scratch_bytes_upper_bound(limits.max_decoded_items_per_block)
            .ok_or_else(arithmetic_error)?,
        u64::from(limits.max_string_bytes),
        string_count
            .checked_mul(string_map_entry_bytes)
            .ok_or_else(arithmetic_error)?,
        finalization_string_slots,
        validation_scratch,
    ]
    .into_iter()
    .try_fold(0_u64, |total, bytes| {
        total.checked_add(bytes).ok_or_else(arithmetic_error)
    })
}

fn arena_reservation_bytes<T>(count: u32) -> Result<u64, BoundaryError> {
    // Cap-aware geometric growth never requests more than `count`. Eight
    // slots conservatively cover the allocator's minimum non-empty capacity
    // when a caller configures a smaller logical limit.
    let slots = u64::from(count).max(8);
    slots
        .checked_mul(type_bytes::<T>()?)
        .ok_or_else(arithmetic_error)
}

fn type_bytes<T>() -> Result<u64, BoundaryError> {
    u64::try_from(mem::size_of::<T>()).map_err(|_| arithmetic_error())
}

fn resulting_import_logical_bytes(
    current: u64,
    input: u64,
    packet_index: u64,
    parser_buffer: u64,
    auxiliary: u64,
) -> Result<u64, BoundaryError> {
    let total = current
        .checked_add(input)
        .and_then(|value| value.checked_add(packet_index))
        .and_then(|value| value.checked_add(parser_buffer))
        .and_then(|value| value.checked_add(auxiliary))
        .ok_or_else(arithmetic_error)?;
    ensure_logical_memory_limit(total)?;
    Ok(total)
}

fn resulting_dataset_logical_bytes(
    current: u64,
    capture: u64,
    index: u64,
) -> Result<u64, BoundaryError> {
    let total = current
        .checked_add(capture)
        .and_then(|value| value.checked_add(index))
        .ok_or_else(arithmetic_error)?;
    ensure_logical_memory_limit(total)?;
    Ok(total)
}

fn ensure_logical_memory_limit(total: u64) -> Result<(), BoundaryError> {
    if total > MAX_TOTAL_LOGICAL_BYTES {
        return Err(BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "capture registry exceeds the logical memory envelope",
        )
        .with_resource_limit(MAX_TOTAL_LOGICAL_BYTES));
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn allocate_import_copy_buffer(input_bytes: u64) -> Result<Vec<u8>, BoundaryError> {
    let input_bytes = usize::try_from(input_bytes).map_err(|_| {
        BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "capture length cannot be represented by this boundary",
        )
        .with_resource_limit(MAX_CAPTURE_BYTES)
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(input_bytes).map_err(|_| {
        BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "boundary could not allocate the admitted capture input",
        )
        .with_resource_limit(u64::try_from(input_bytes).unwrap_or(MAX_CAPTURE_BYTES))
    })?;
    bytes.resize(input_bytes, 0);
    Ok(bytes)
}

/// Returns the packet ceiling derived for an exact capture byte length.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // The guarded cast cannot truncate.
pub const fn packet_limit_for_capture(input_bytes: u64) -> u32 {
    let proportional = input_bytes / CAPTURE_BYTES_PER_PACKET as u64;
    let proportional = if proportional > u32::MAX as u64 {
        u32::MAX
    } else {
        proportional as u32
    };
    let admitted = CAPTURE_PACKET_BASE_ALLOWANCE.saturating_add(proportional);
    if admitted < MAX_CAPTURE_PACKETS {
        admitted
    } else {
        MAX_CAPTURE_PACKETS
    }
}

fn browser_import_limits(input_bytes: u64, requested: ImportLimits) -> ImportLimits {
    let layers_per_packet = requested
        .max_layers_per_packet
        .min(MAX_CAPTURE_LAYERS_PER_PACKET);
    let fields_per_packet = requested
        .max_fields_per_packet
        .min(MAX_CAPTURE_FIELDS_PER_PACKET);
    let children_per_packet = requested
        .max_field_children_per_packet
        .min(MAX_CAPTURE_FIELD_CHILDREN_PER_PACKET);
    ImportLimits {
        max_capture_bytes: requested.max_capture_bytes.min(MAX_CAPTURE_BYTES),
        max_block_bytes: requested.max_block_bytes.min(MAX_CAPTURE_BLOCK_BYTES),
        max_decoded_items_per_block: requested
            .max_decoded_items_per_block
            .min(MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK),
        max_decoded_items_per_step: requested
            .max_decoded_items_per_step
            .min(MAX_CAPTURE_DECODED_ITEMS_PER_STEP),
        max_packets: requested
            .max_packets
            .min(packet_limit_for_capture(input_bytes)),
        max_sections: requested.max_sections.min(MAX_CAPTURE_SECTIONS),
        max_interfaces: requested.max_interfaces.min(MAX_CAPTURE_INTERFACES),
        max_layers: proportional_decode_limit(
            input_bytes,
            CAPTURE_BYTES_PER_DECODED_LAYER,
            CAPTURE_DECODED_LAYER_BASE_ALLOWANCE,
            requested.max_layers,
            MAX_CAPTURE_LAYERS,
        ),
        max_layers_per_packet: layers_per_packet,
        max_fields: proportional_decode_limit(
            input_bytes,
            CAPTURE_BYTES_PER_DECODED_FIELD,
            CAPTURE_DECODED_FIELD_BASE_ALLOWANCE,
            requested.max_fields,
            MAX_CAPTURE_FIELDS,
        ),
        max_fields_per_packet: fields_per_packet,
        max_field_children: proportional_decode_limit(
            input_bytes,
            CAPTURE_BYTES_PER_FIELD_CHILD,
            CAPTURE_FIELD_CHILD_BASE_ALLOWANCE,
            requested.max_field_children,
            MAX_CAPTURE_FIELD_CHILDREN,
        ),
        max_field_children_per_packet: children_per_packet,
        max_diagnostics: requested.max_diagnostics.min(MAX_CAPTURE_DIAGNOSTICS),
        max_string_bytes: requested.max_string_bytes.min(MAX_CAPTURE_STRING_BYTES),
    }
}

fn proportional_decode_limit(
    input_bytes: u64,
    bytes_per_item: u32,
    baseline_total: u32,
    requested_total: u32,
    boundary_total: u32,
) -> u32 {
    let proportional = input_bytes.div_ceil(u64::from(bytes_per_item));
    let proportional = u32::try_from(proportional).unwrap_or(u32::MAX);
    requested_total
        .min(boundary_total)
        .min(proportional.max(baseline_total))
}

fn import_progress(progress: CoreImportProgress, phase: ImportPhase) -> ImportProgressSnapshot {
    ImportProgressSnapshot {
        phase,
        consumed_bytes: progress.consumed_bytes,
        total_bytes: progress.total_bytes,
        records_processed: progress.records_processed,
        packets_retained: progress.packets_retained,
        diagnostics: progress.diagnostics,
    }
}

fn map_import_error(error: ImportError) -> BoundaryError {
    match error {
        ImportError::InvalidLimits | ImportError::InvalidStepBudget => BoundaryError::new(
            BoundaryErrorCode::INVALID_ARGUMENT,
            "capture import arguments are invalid",
        ),
        ImportError::InvalidHeader => BoundaryError::new(
            BoundaryErrorCode::CAPTURE_FORMAT,
            "capture header is invalid or unsupported",
        ),
        ImportError::TruncatedInput { offset } => BoundaryError::new(
            BoundaryErrorCode::TRUNCATED_CAPTURE,
            "capture input ends before its initial header is complete",
        )
        .with_input_offset(offset),
        ImportError::ResourceLimit { limit, offset, .. } => BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "capture import reached a configured resource limit",
        )
        .with_resource_context(offset, limit),
        ImportError::NotReady => BoundaryError::new(
            BoundaryErrorCode::INVALID_STATE,
            "capture import is not ready to publish",
        ),
        ImportError::OwnershipInvariant => BoundaryError::new(
            BoundaryErrorCode::INTERNAL_INVARIANT,
            "capture importer ownership invariant failed",
        ),
        ImportError::Model(_) => BoundaryError::new(
            BoundaryErrorCode::MALFORMED_CAPTURE,
            "capture could not produce a valid canonical dataset",
        ),
        ImportError::Arithmetic => arithmetic_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundaryState, CAPTURE_BYTES_PER_DECODED_FIELD, CAPTURE_BYTES_PER_DECODED_LAYER,
        CAPTURE_BYTES_PER_FIELD_CHILD, CAPTURE_DECODED_FIELD_BASE_ALLOWANCE,
        CAPTURE_DECODED_LAYER_BASE_ALLOWANCE, CAPTURE_FIELD_CHILD_BASE_ALLOWANCE, DisposeStatus,
        ImportAdvance, Registry, allocate_import_copy_buffer, import_auxiliary_bytes_upper_bound,
        packet_index_bytes_for_limit, parser_buffer_bytes_for_capture, proportional_decode_limit,
        resulting_dataset_logical_bytes, resulting_import_logical_bytes,
    };
    use crate::{
        BoundaryErrorCode, HandleKind, ImportLimits, MAX_CAPTURE_BYTES, MAX_IMPORT_STEP_BYTES,
        MAX_IMPORT_STEP_RECORDS, MAX_TOTAL_LOGICAL_BYTES, handle::MAX_GENERATION,
    };
    use protocol_decoders::{
        DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
        DECODER_MAX_LAYERS_PER_PACKET,
    };

    fn vlan_header(inner_ether_type: u16) -> Vec<u8> {
        let mut frame = Vec::with_capacity(18);
        frame.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame.extend(0x8100_u16.to_be_bytes());
        frame.extend(100_u16.to_be_bytes());
        frame.extend(inner_ether_type.to_be_bytes());
        assert_eq!(frame.len(), 18);
        frame
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        assert_eq!(header.len() % 2, 0);
        let mut sum = 0_u32;
        for pair in header.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !u16::try_from(sum).expect("folded checksum fits u16")
    }

    fn maximal_ipv4_field_decode() -> Vec<u8> {
        const IPV4_HEADER_LENGTH: usize = 60;
        const TCP_HEADER_LENGTH: usize = 60;

        let mut frame = vlan_header(0x0800);
        let ipv4_start = frame.len();
        frame.extend([0x4f, 0x00]);
        frame.extend(120_u16.to_be_bytes());
        frame.extend(0x1234_u16.to_be_bytes());
        frame.extend(0_u16.to_be_bytes());
        frame.extend([64, 6]);
        frame.extend(0_u16.to_be_bytes());
        frame.extend([192, 0, 2, 1]);
        frame.extend([198, 51, 100, 2]);
        for _ in 0..20 {
            // A generic two-byte option maximizes structured option fields
            // within IPv4's 40-byte IHL-bounded option area.
            frame.extend([0x1e, 2]);
        }
        assert_eq!(frame.len(), ipv4_start + IPV4_HEADER_LENGTH);
        let checksum = ipv4_checksum(&frame[ipv4_start..ipv4_start + IPV4_HEADER_LENGTH]);
        frame[ipv4_start + 10..ipv4_start + 12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            ipv4_checksum(&frame[ipv4_start..ipv4_start + IPV4_HEADER_LENGTH]),
            0
        );

        let tcp_start = frame.len();
        frame.extend(12_345_u16.to_be_bytes());
        frame.extend(443_u16.to_be_bytes());
        frame.extend(0x0102_0304_u32.to_be_bytes());
        frame.extend(0x0506_0708_u32.to_be_bytes());
        frame.extend([0xf0, 0xff]);
        frame.extend(4_096_u16.to_be_bytes());
        frame.extend(0_u16.to_be_bytes());
        frame.extend(0_u16.to_be_bytes());
        for _ in 0..20 {
            // A generic two-byte option maximizes structured option fields
            // within TCP's 40-byte data-offset-bounded option area.
            frame.extend([0x1e, 2]);
        }
        assert_eq!(frame.len(), tcp_start + TCP_HEADER_LENGTH);
        let tcp_checksum = ipv4_transport_checksum(
            &frame[ipv4_start + 12..ipv4_start + 16],
            &frame[ipv4_start + 16..ipv4_start + 20],
            6,
            &frame[tcp_start..],
        );
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        assert_eq!(
            ipv4_transport_checksum(
                &frame[ipv4_start + 12..ipv4_start + 16],
                &frame[ipv4_start + 16..ipv4_start + 20],
                6,
                &frame[tcp_start..],
            ),
            0
        );
        frame
    }

    fn ipv4_transport_checksum(
        source: &[u8],
        destination: &[u8],
        protocol: u8,
        message: &[u8],
    ) -> u16 {
        let length = u16::try_from(message.len())
            .expect("synthetic transport message length fits u16")
            .to_be_bytes();
        let protocol = [0, protocol];
        let mut sum = 0_u32;
        for bytes in [source, destination, &protocol, &length, message] {
            for pair in bytes.chunks_exact(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
            if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
                sum += u32::from(last) << 8;
            }
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !u16::try_from(sum).expect("folded checksum fits u16")
    }

    fn maximal_ipv6_layer_decode() -> Vec<u8> {
        let mut frame = vlan_header(0x86dd);
        frame.extend(0x6000_0000_u32.to_be_bytes());
        frame.extend(72_u16.to_be_bytes());
        frame.extend([60, 64]);
        frame.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        for extension_index in 0..9 {
            let next_header = if extension_index < 8 { 60 } else { 253 };
            frame.extend([next_header, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(frame.len(), 18 + 40 + 72);
        frame
    }

    struct MaximumLayerTestDecoder;

    impl packet_core::PacketDecoder for MaximumLayerTestDecoder {
        fn decode(
            &mut self,
            input: packet_core::PacketDecodeInput<'_>,
            sink: &mut packet_core::PacketDecodeSink<'_>,
        ) -> Result<(), packet_core::ImportError> {
            let protocol = sink.intern("test_maximum_layer")?;
            for _ in 0..DECODER_MAX_LAYERS_PER_PACKET {
                sink.add_layer(protocol, input.data_range(), None)?;
            }
            Ok(())
        }
    }

    fn repeated_legacy_pcap(frame: &[u8], packet_count: u32) -> Box<[u8]> {
        let frame_length = u32::try_from(frame.len()).expect("synthetic frame length fits u32");
        let packet_count = usize::try_from(packet_count).expect("packet count fits usize");
        let mut capture = Vec::with_capacity(24 + packet_count * (16 + frame.len()));
        capture.extend([0xd4, 0xc3, 0xb2, 0xa1]);
        capture.extend(2_u16.to_le_bytes());
        capture.extend(4_u16.to_le_bytes());
        capture.extend(0_i32.to_le_bytes());
        capture.extend(0_u32.to_le_bytes());
        capture.extend(65_535_u32.to_le_bytes());
        capture.extend(1_u32.to_le_bytes());
        for packet_id in 0..packet_count {
            capture.extend(
                u32::try_from(packet_id)
                    .expect("synthetic timestamp fits u32")
                    .to_le_bytes(),
            );
            capture.extend(0_u32.to_le_bytes());
            capture.extend(frame_length.to_le_bytes());
            capture.extend(frame_length.to_le_bytes());
            capture.extend(frame);
        }
        capture.into_boxed_slice()
    }

    #[test]
    fn registry_retires_a_slot_before_generation_wrap() {
        let mut registry = Registry::new(HandleKind::Dataset, 1);
        let original = registry.insert(7_u8).expect("slot is available");
        registry.slots[0].generation = MAX_GENERATION;
        let maximum = crate::BoundaryHandle::encode(HandleKind::Dataset, MAX_GENERATION, 0)
            .expect("maximum generation is valid");
        assert_eq!(
            *registry.get(maximum).expect("updated test slot is live"),
            7
        );
        assert_eq!(
            registry.remove(maximum).expect("removal succeeds").status,
            DisposeStatus::Disposed
        );
        assert!(registry.slots[0].retired);
        assert_eq!(
            registry
                .insert(8)
                .expect_err("retired slot cannot wrap or be reused")
                .code(),
            BoundaryErrorCode::REGISTRY_LIMIT
        );
        assert!(registry.get(original).is_err());
    }

    #[test]
    fn registry_reuses_slots_without_reviving_stale_handles() {
        let mut registry = Registry::new(HandleKind::PacketCursor, 1);
        let first = registry.insert(1_u8).expect("first insert succeeds");
        assert_eq!(
            registry.remove(first).expect("dispose succeeds").status,
            DisposeStatus::Disposed
        );
        let second = registry.insert(2_u8).expect("slot is reusable");
        assert_ne!(first, second);
        assert_eq!(
            registry
                .get(first)
                .expect_err("old handle stays stale")
                .code(),
            BoundaryErrorCode::STALE_HANDLE
        );
        let Err(stale) = registry.remove(first) else {
            panic!("a disposed generation cannot affect a reused slot")
        };
        assert_eq!(stale.code(), BoundaryErrorCode::STALE_HANDLE);
        assert_eq!(*registry.get(second).expect("new owner remains live"), 2);
    }

    #[test]
    fn registry_reservation_failure_is_structured_and_non_mutating() {
        let mut registry = Registry::new(HandleKind::Dataset, 1);
        let handle = registry.insert(7_u8).expect("first insert succeeds");
        let generation = registry.slots[0].generation;
        registry.active_count = usize::MAX;

        let error = registry
            .plan_remove_where(|_| true)
            .expect_err("impossible reservation must fail before removal");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(error.resource_limit(), Some(1));
        assert_eq!(registry.slots[0].generation, generation);
        assert_eq!(registry.slots[0].last_disposed_generation, None);
        assert_eq!(registry.slots[0].value, Some(7));
        assert!(registry.free.is_empty());
        assert_eq!(
            *registry.get(handle).expect("live slot remains readable"),
            7
        );
    }

    #[test]
    fn cascade_preflight_failure_leaves_dataset_and_cursor_live() {
        let empty_dataset =
            packet_core::CaptureDataset::from_parts(packet_core::CaptureDatasetParts {
                metadata: packet_core::CaptureMetadata {
                    format: packet_core::CaptureFormat::Pcap,
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
            .expect("empty canonical dataset is valid");
        let mut state = BoundaryState::new();
        let dataset = state
            .register_dataset(empty_dataset)
            .expect("dataset slot is available");
        let cursor = state
            .create_packet_cursor(dataset, 0)
            .expect("dependent cursor slot is available");

        state.packet_cursors.active_count = usize::MAX;
        let error = state
            .dispose_dataset(dataset)
            .expect_err("cursor cascade allocation fails before either registry mutates");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert!(state.datasets.get(dataset).is_ok(), "dataset remains live");
        assert!(
            state.packet_cursors.get(cursor).is_ok(),
            "dependent cursor remains live"
        );
    }

    #[test]
    fn input_copy_allocation_failure_is_a_controlled_resource_error() {
        let error = allocate_import_copy_buffer(u64::MAX)
            .expect_err("unrepresentable allocation is rejected without panicking");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert!(error.resource_limit().is_some());

        let bytes = allocate_import_copy_buffer(32).expect("small allocation succeeds");
        assert_eq!(bytes, vec![0_u8; 32]);
        assert_eq!(bytes.capacity(), 32);
    }

    #[test]
    fn capped_vector_reservations_cover_small_allocations_and_parser_spare_capacity() {
        let packet_bytes = u64::try_from(core::mem::size_of::<packet_core::PacketRecord>())
            .expect("packet record size is representable");
        assert_eq!(packet_index_bytes_for_limit(7), Ok(8 * packet_bytes));
        assert_eq!(packet_index_bytes_for_limit(1), Ok(8 * packet_bytes));
        assert_eq!(packet_index_bytes_for_limit(13), Ok(13 * packet_bytes));
        assert_eq!(parser_buffer_bytes_for_capture(3, 4), Ok(8));
        assert_eq!(parser_buffer_bytes_for_capture(100, 4), Ok(10));
    }

    #[test]
    fn decoded_arena_bases_respect_custom_caps_and_preserve_post_base_density() {
        let requested = ImportLimits {
            max_layers: 100,
            max_layers_per_packet: 4,
            max_fields: 200,
            max_fields_per_packet: 25,
            max_field_children: 100,
            max_field_children_per_packet: 21,
            ..ImportLimits::default()
        };
        let admitted = BoundaryState::new()
            .admit_import_input_with_limits(1, requested)
            .expect("valid caller totals remain authoritative")
            .limits();
        assert_eq!(admitted.max_layers, requested.max_layers);
        assert_eq!(admitted.max_fields, requested.max_fields);
        assert_eq!(admitted.max_field_children, requested.max_field_children);

        for (baseline, density) in [
            (
                CAPTURE_DECODED_LAYER_BASE_ALLOWANCE,
                CAPTURE_BYTES_PER_DECODED_LAYER,
            ),
            (
                CAPTURE_DECODED_FIELD_BASE_ALLOWANCE,
                CAPTURE_BYTES_PER_DECODED_FIELD,
            ),
            (
                CAPTURE_FIELD_CHILD_BASE_ALLOWANCE,
                CAPTURE_BYTES_PER_FIELD_CHILD,
            ),
        ] {
            let first_post_base_byte = u64::from(baseline)
                .checked_mul(u64::from(density))
                .and_then(|value| value.checked_add(1))
                .expect("test threshold is representable");
            assert_eq!(
                proportional_decode_limit(
                    first_post_base_byte,
                    density,
                    baseline,
                    u32::MAX,
                    u32::MAX,
                ),
                baseline + 1
            );
        }
    }

    #[test]
    fn base_allowance_imports_1024_ipv4_field_max_packets_without_saturation() {
        const PACKETS: u32 = 1_024;

        let capture = repeated_legacy_pcap(&maximal_ipv4_field_decode(), PACKETS);
        let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
        let mut state = BoundaryState::new();
        let admission = state
            .admit_import_input(capture_length)
            .expect("small-capture decode baseline is admitted");
        assert_eq!(
            admission.limits().max_layers,
            CAPTURE_DECODED_LAYER_BASE_ALLOWANCE
        );
        assert_eq!(
            admission.limits().max_fields,
            CAPTURE_DECODED_FIELD_BASE_ALLOWANCE
        );
        assert_eq!(
            admission.limits().max_field_children,
            CAPTURE_FIELD_CHILD_BASE_ALLOWANCE
        );

        let import = state
            .begin_import(capture)
            .expect("the synthetic VLAN/IPv4 capture begins importing");
        loop {
            match state
                .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
                .expect("the decode baseline prevents arena saturation")
            {
                ImportAdvance::Progress(_) => {}
                ImportAdvance::Ready(progress) => {
                    assert_eq!(progress.packets_retained, u64::from(PACKETS));
                    assert_eq!(progress.diagnostics, 0);
                    break;
                }
                ImportAdvance::NeedsBudget { .. } => {
                    panic!("the maximum boundary step budget covers every synthetic record")
                }
            }
        }
        let published = state
            .finish_import(import)
            .expect("the fully decoded capture publishes");
        let dataset = state
            .datasets
            .get(published.dataset)
            .expect("published dataset remains registered");
        let packet_count = usize::try_from(PACKETS).expect("packet count fits usize");
        let fields_per_packet =
            usize::try_from(DECODER_MAX_FIELDS_PER_PACKET).expect("field count fits usize");
        let children_per_packet =
            usize::try_from(DECODER_MAX_FIELD_CHILDREN_PER_PACKET).expect("child count fits usize");
        assert_eq!(dataset.packets().len(), packet_count);
        assert_eq!(dataset.layers().len(), packet_count * 4);
        assert_eq!(dataset.fields().len(), packet_count * fields_per_packet);
        assert_eq!(
            dataset.field_children().len(),
            packet_count * children_per_packet
        );
        assert!(dataset.diagnostics().is_empty());
        assert!(
            dataset
                .packets()
                .iter()
                .all(|packet| packet.layers.length() == 4)
        );
    }

    #[test]
    fn base_allowance_imports_1024_ipv6_layer_max_packets_without_saturation() {
        const PACKETS: u32 = 1_024;

        let capture = repeated_legacy_pcap(&maximal_ipv6_layer_decode(), PACKETS);
        let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
        let mut state = BoundaryState::new();
        let admission = state
            .admit_import_input(capture_length)
            .expect("small-capture decode baseline is admitted");
        assert_eq!(
            admission.limits().max_layers,
            CAPTURE_DECODED_LAYER_BASE_ALLOWANCE
        );

        let import = state
            .begin_import(capture)
            .expect("the synthetic VLAN/IPv6 capture begins importing");
        loop {
            match state
                .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
                .expect("the decode baseline prevents layer-arena saturation")
            {
                ImportAdvance::Progress(_) => {}
                ImportAdvance::Ready(progress) => {
                    assert_eq!(progress.packets_retained, u64::from(PACKETS));
                    assert_eq!(progress.diagnostics, PACKETS);
                    break;
                }
                ImportAdvance::NeedsBudget { .. } => {
                    panic!("the maximum boundary step budget covers every synthetic record")
                }
            }
        }
        let published = state
            .finish_import(import)
            .expect("the fully decoded capture publishes");
        let dataset = state
            .datasets
            .get(published.dataset)
            .expect("published dataset remains registered");
        let packet_count = usize::try_from(PACKETS).expect("packet count fits usize");
        let layers_per_packet =
            usize::try_from(DECODER_MAX_LAYERS_PER_PACKET).expect("layer count fits usize");
        let fields_per_packet =
            usize::try_from(DECODER_MAX_FIELDS_PER_PACKET).expect("field count fits usize");
        let children_per_packet =
            usize::try_from(DECODER_MAX_FIELD_CHILDREN_PER_PACKET).expect("child count fits usize");
        assert_eq!(dataset.packets().len(), packet_count);
        assert_eq!(dataset.layers().len(), packet_count * layers_per_packet);
        assert!(dataset.fields().len() <= packet_count * fields_per_packet);
        assert!(dataset.field_children().len() <= packet_count * children_per_packet);
        assert_eq!(dataset.diagnostics().len(), packet_count);
        assert!(
            dataset
                .diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code == packet_core::DiagnosticCode::RESOURCE_LIMIT)
        );
        assert!(
            dataset
                .packets()
                .iter()
                .all(|packet| packet.layers.length() == DECODER_MAX_LAYERS_PER_PACKET)
        );
    }

    #[test]
    fn ipv4_packet_beyond_the_field_max_baseline_fails_closed_and_reclaims_import() {
        const PACKETS: u32 = 1_025;
        let capture = repeated_legacy_pcap(&maximal_ipv4_field_decode(), PACKETS);
        let mut state = BoundaryState::new();
        let import = state
            .begin_import(capture)
            .expect("the capture and packet metadata fit pre-copy admission");
        let failure = state
            .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
            .expect_err("decoded fields beyond the exact baseline fail closed");
        assert_eq!(failure.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(
            failure.resource_limit(),
            Some(u64::from(CAPTURE_DECODED_FIELD_BASE_ALLOWANCE))
        );
        let progress = failure
            .terminal_import_progress()
            .expect("fatal decode saturation carries exact import progress");
        assert_eq!(progress.phase, super::ImportPhase::Failed);
        assert_eq!(progress.packets_retained, 1_024);

        let cleanup = state
            .resource_stats()
            .expect("fatal import cleanup is exact");
        assert_eq!(cleanup.active_imports, 0);
        assert_eq!(cleanup.active_datasets, 0);
        assert_eq!(cleanup.transient_import_input_bytes, 0);
        assert_eq!(cleanup.current_owned_capture_bytes, 0);
        assert_eq!(cleanup.total_logical_bytes_upper_bound, 0);
    }

    #[test]
    fn packet_beyond_the_layer_max_baseline_fails_closed_and_reclaims_import() {
        const PACKETS: u32 = 1_025;

        // The real 12-layer IPv6 limit-marker path necessarily emits one
        // diagnostic per packet and is covered above. This accounting decoder
        // isolates layer exhaustion so the independent layer base can be
        // tested past 1,024 packets without first reaching the diagnostic cap.
        let capture = repeated_legacy_pcap(&[0], PACKETS);
        let capture_length = u64::try_from(capture.len()).expect("capture length fits u64");
        let mut state = BoundaryState::new();
        let admission = state
            .admit_import_input(capture_length)
            .expect("the synthetic capture fits pre-copy admission");
        assert_eq!(
            admission.limits().max_layers,
            CAPTURE_DECODED_LAYER_BASE_ALLOWANCE
        );
        let importer = packet_core::CaptureImporter::new_with_decoder(
            capture,
            admission.limits(),
            Box::new(MaximumLayerTestDecoder),
        )
        .expect("the admitted synthetic capture constructs an importer");
        let import = state
            .imports
            .insert(super::ImportEntry {
                importer,
                parser_buffer_bytes_upper_bound: admission.parser_buffer_bytes_upper_bound,
                packet_index_bytes_upper_bound: admission.packet_index_bytes_upper_bound,
                auxiliary_bytes_upper_bound: admission.auxiliary_bytes_upper_bound,
            })
            .expect("the import registry has capacity");

        let failure = state
            .advance_import(import, MAX_IMPORT_STEP_RECORDS, MAX_IMPORT_STEP_BYTES)
            .expect_err("the 1,025th maximum-layer packet fails closed");
        assert_eq!(failure.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(
            failure.resource_limit(),
            Some(u64::from(CAPTURE_DECODED_LAYER_BASE_ALLOWANCE))
        );
        let progress = failure
            .terminal_import_progress()
            .expect("fatal decode saturation carries exact import progress");
        assert_eq!(progress.phase, super::ImportPhase::Failed);
        assert_eq!(progress.packets_retained, 1_024);

        let cleanup = state
            .resource_stats()
            .expect("fatal import cleanup is exact");
        assert_eq!(cleanup.active_imports, 0);
        assert_eq!(cleanup.active_datasets, 0);
        assert_eq!(cleanup.transient_import_input_bytes, 0);
        assert_eq!(cleanup.current_owned_capture_bytes, 0);
        assert_eq!(cleanup.total_logical_bytes_upper_bound, 0);
    }

    #[test]
    fn cumulative_logical_limit_includes_import_auxiliary_and_exact_dataset_bytes() {
        let bounded_limits = BoundaryState::new()
            .admit_import_input_with_limits(1, ImportLimits::default())
            .expect("the browser clamps platform-neutral defaults")
            .limits();
        let auxiliary = import_auxiliary_bytes_upper_bound(bounded_limits)
            .expect("default auxiliary reservation is representable");
        assert!(auxiliary > 0);

        let fixed_import_bytes = 11_u64;
        let at_import_limit = MAX_TOTAL_LOGICAL_BYTES - fixed_import_bytes - auxiliary;
        assert_eq!(
            resulting_import_logical_bytes(at_import_limit, 1, 2, 8, auxiliary),
            Ok(MAX_TOTAL_LOGICAL_BYTES)
        );
        let import_error = resulting_import_logical_bytes(at_import_limit + 1, 1, 2, 8, auxiliary)
            .expect_err("one byte beyond the cumulative import cap is rejected");
        assert_eq!(import_error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(import_error.resource_limit(), Some(MAX_TOTAL_LOGICAL_BYTES));

        assert_eq!(
            resulting_dataset_logical_bytes(MAX_TOTAL_LOGICAL_BYTES - 9, 4, 5),
            Ok(MAX_TOTAL_LOGICAL_BYTES)
        );
        let dataset_error = resulting_dataset_logical_bytes(MAX_TOTAL_LOGICAL_BYTES - 8, 4, 5)
            .expect_err("exact dataset registration cannot exceed the cumulative cap");
        assert_eq!(dataset_error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(
            dataset_error.resource_limit(),
            Some(MAX_TOTAL_LOGICAL_BYTES)
        );
    }

    #[test]
    fn decoded_arena_reservations_preserve_the_max_capture_admission_contract() {
        let admission = BoundaryState::new()
            .admit_import_input_with_limits(MAX_CAPTURE_BYTES, ImportLimits::default())
            .expect("the advertised maximum capture remains admissible in an empty boundary");
        assert!(admission.auxiliary_bytes_upper_bound() > 0);
        assert!(admission.resulting_logical_bytes_upper_bound() <= MAX_TOTAL_LOGICAL_BYTES);
    }
}
