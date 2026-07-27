//! `wasm-bindgen` facade for the production module-worker boundary.

use js_sys::{
    Array, ArrayBuffer, BigInt, Error, Object, Reflect, Uint8Array, Uint16Array, Uint32Array,
};
use packet_core::{DiagnosticScope, PacketId, PacketRelativeRange, Recovery, Severity};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};

use crate::{
    API_VERSION, BATCH_SCHEMA_VERSION, BoundaryError, BoundaryErrorCode, BoundaryHandle,
    BoundaryState, CAPTURE_BYTES_PER_DECODED_FIELD, CAPTURE_BYTES_PER_DECODED_LAYER,
    CAPTURE_BYTES_PER_FIELD_CHILD, CAPTURE_BYTES_PER_PACKET, CAPTURE_DECODED_FIELD_BASE_ALLOWANCE,
    CAPTURE_DECODED_LAYER_BASE_ALLOWANCE, CAPTURE_FIELD_CHILD_BASE_ALLOWANCE,
    CAPTURE_PACKET_BASE_ALLOWANCE, DatasetDiagnostic, DisposeStatus, HandleKind, ImportAdvance,
    ImportPhase, ImportProgressSnapshot, MAX_CAPTURE_BLOCK_BYTES, MAX_CAPTURE_BYTES,
    MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK, MAX_CAPTURE_DECODED_ITEMS_PER_STEP,
    MAX_CAPTURE_DIAGNOSTICS, MAX_CAPTURE_FIELD_CHILDREN, MAX_CAPTURE_FIELD_CHILDREN_PER_PACKET,
    MAX_CAPTURE_FIELDS, MAX_CAPTURE_FIELDS_PER_PACKET, MAX_CAPTURE_INTERFACES, MAX_CAPTURE_LAYERS,
    MAX_CAPTURE_LAYERS_PER_PACKET, MAX_CAPTURE_PACKETS, MAX_CAPTURE_SECTIONS,
    MAX_CAPTURE_STRING_BYTES, MAX_DATASET_HANDLES, MAX_EVIDENCE_BYTES, MAX_IMPORT_HANDLES,
    MAX_IMPORT_STEP_BYTES, MAX_IMPORT_STEP_RECORDS, MAX_PACKET_BATCH_BYTES, MAX_PACKET_BATCH_ROWS,
    MAX_PACKET_CORRELATION_MATCHES, MAX_PACKET_CURSOR_HANDLES, MAX_PACKET_DETAIL_BYTES,
    MAX_PACKET_EVIDENCE_BYTES, MAX_TOTAL_CAPTURE_BYTES, MAX_TOTAL_LOGICAL_BYTES,
    PACKET_DETAIL_SCHEMA_VERSION, ResourceStats, boundary::allocate_import_copy_buffer,
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Object)]
    type CatchableObject;

    #[wasm_bindgen(catch, constructor, js_class = "Object")]
    fn try_new_object_raw() -> Result<CatchableObject, JsValue>;

    #[wasm_bindgen(js_name = Array)]
    type CatchableArray;

    #[wasm_bindgen(catch, constructor, js_class = "Array")]
    fn try_new_array_raw(length: u32) -> Result<CatchableArray, JsValue>;

    #[wasm_bindgen(js_name = Uint8Array)]
    type CatchableUint8Array;

    #[wasm_bindgen(catch, constructor, js_class = "Uint8Array")]
    fn try_new_u8_array_raw(length: u32) -> Result<CatchableUint8Array, JsValue>;

    #[wasm_bindgen(js_name = Uint16Array)]
    type CatchableUint16Array;

    #[wasm_bindgen(catch, constructor, js_class = "Uint16Array")]
    fn try_new_u16_array_raw(length: u32) -> Result<CatchableUint16Array, JsValue>;

    #[wasm_bindgen(js_name = Uint32Array)]
    type CatchableUint32Array;

    #[wasm_bindgen(catch, constructor, js_class = "Uint32Array")]
    fn try_new_u32_array_raw(length: u32) -> Result<CatchableUint32Array, JsValue>;
}

fn allocation_error() -> JsValue {
    web_error(
        "resource_limit",
        "JavaScript boundary allocation reached the available resource limit",
    )
}

fn try_new_object() -> Result<Object, JsValue> {
    CatchableObject::try_new_object_raw()
        .map(JsCast::unchecked_into)
        .map_err(|_| allocation_error())
}

fn try_new_array(length: u32) -> Result<Array, JsValue> {
    CatchableArray::try_new_array_raw(length)
        .map(JsCast::unchecked_into)
        .map_err(|_| allocation_error())
}

fn try_new_u16_array(length: u32) -> Result<Uint16Array, JsValue> {
    CatchableUint16Array::try_new_u16_array_raw(length)
        .map(JsCast::unchecked_into)
        .map_err(|_| allocation_error())
}

fn try_new_u32_array(length: u32) -> Result<Uint32Array, JsValue> {
    CatchableUint32Array::try_new_u32_array_raw(length)
        .map(JsCast::unchecked_into)
        .map_err(|_| allocation_error())
}

fn copy_to_js_u8_array(bytes: &[u8]) -> Result<Uint8Array, JsValue> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| web_error("resource_limit", "binary boundary output exceeds u32"))?;
    let output: Uint8Array = CatchableUint8Array::try_new_u8_array_raw(length)
        .map(JsCast::unchecked_into)
        .map_err(|_| allocation_error())?;
    output.copy_from(bytes);
    Ok(output)
}

/// Returns the supported worker command API version.
#[wasm_bindgen(js_name = apiVersion)]
#[must_use]
pub fn api_version() -> u32 {
    API_VERSION
}

/// Returns the supported binary packet-batch schema version.
#[wasm_bindgen(js_name = batchSchemaVersion)]
#[must_use]
pub fn batch_schema_version() -> u32 {
    u32::from(BATCH_SCHEMA_VERSION)
}

/// Returns the supported binary packet-detail schema version.
#[wasm_bindgen(js_name = detailSchemaVersion)]
#[must_use]
pub fn detail_schema_version() -> u32 {
    u32::from(PACKET_DETAIL_SCHEMA_VERSION)
}

fn capability_u64(value: u64) -> Result<f64, JsValue> {
    u32::try_from(value).map(f64::from).map_err(|_| {
        web_error(
            "internal_invariant",
            "boundary capability exceeds its exact JavaScript number range",
        )
    })
}

fn capability_usize(value: usize) -> Result<f64, JsValue> {
    u32::try_from(value).map(f64::from).map_err(|_| {
        web_error(
            "internal_invariant",
            "boundary capability exceeds its exact JavaScript number range",
        )
    })
}

fn set_capability_numbers(result: &Object, values: &[(&str, f64)]) -> Result<(), JsValue> {
    for &(name, value) in values {
        set_number(result, name, value)?;
    }
    Ok(())
}

fn set_core_capabilities(result: &Object) -> Result<(), JsValue> {
    set_capability_numbers(
        result,
        &[
            ("apiVersion", f64::from(API_VERSION)),
            ("batchSchemaVersion", f64::from(BATCH_SCHEMA_VERSION)),
            (
                "detailSchemaVersion",
                f64::from(PACKET_DETAIL_SCHEMA_VERSION),
            ),
            ("maxCaptureBytes", capability_u64(MAX_CAPTURE_BYTES)?),
            (
                "maxTotalCaptureBytes",
                capability_u64(MAX_TOTAL_CAPTURE_BYTES)?,
            ),
            ("maxBlockBytes", f64::from(MAX_CAPTURE_BLOCK_BYTES)),
            (
                "maxDecodedItemsPerBlock",
                f64::from(MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK),
            ),
            (
                "maxDecodedItemsPerStep",
                f64::from(MAX_CAPTURE_DECODED_ITEMS_PER_STEP),
            ),
            (
                "maxTotalLogicalBytes",
                capability_u64(MAX_TOTAL_LOGICAL_BYTES)?,
            ),
            ("maxEvidenceBytes", f64::from(MAX_EVIDENCE_BYTES)),
            ("maxImportStepBytes", capability_u64(MAX_IMPORT_STEP_BYTES)?),
            ("maxImportStepRecords", f64::from(MAX_IMPORT_STEP_RECORDS)),
            ("maxDiagnostics", f64::from(MAX_CAPTURE_DIAGNOSTICS)),
            (
                "maxInternedStringBytes",
                f64::from(MAX_CAPTURE_STRING_BYTES),
            ),
            ("maxSections", f64::from(MAX_CAPTURE_SECTIONS)),
            ("maxInterfaces", f64::from(MAX_CAPTURE_INTERFACES)),
        ],
    )
}

fn set_packet_capabilities(result: &Object) -> Result<(), JsValue> {
    set_capability_numbers(
        result,
        &[
            ("maxPackets", f64::from(MAX_CAPTURE_PACKETS)),
            (
                "packetAdmissionBase",
                f64::from(CAPTURE_PACKET_BASE_ALLOWANCE),
            ),
            (
                "packetAdmissionBytesPerPacket",
                f64::from(CAPTURE_BYTES_PER_PACKET),
            ),
        ],
    )?;
    set_string(
        result,
        "packetAdmissionRule",
        "min(maxPackets, packetAdmissionBase + floor(captureBytes / packetAdmissionBytesPerPacket))",
    )
}

fn set_decoded_arena_capabilities(result: &Object) -> Result<(), JsValue> {
    set_capability_numbers(
        result,
        &[
            (
                "decodedLayerAdmissionBytesPerItem",
                f64::from(CAPTURE_BYTES_PER_DECODED_LAYER),
            ),
            (
                "decodedLayerAdmissionBase",
                f64::from(CAPTURE_DECODED_LAYER_BASE_ALLOWANCE),
            ),
            (
                "decodedFieldAdmissionBytesPerItem",
                f64::from(CAPTURE_BYTES_PER_DECODED_FIELD),
            ),
            (
                "decodedFieldAdmissionBase",
                f64::from(CAPTURE_DECODED_FIELD_BASE_ALLOWANCE),
            ),
            (
                "fieldChildAdmissionBytesPerItem",
                f64::from(CAPTURE_BYTES_PER_FIELD_CHILD),
            ),
            (
                "fieldChildAdmissionBase",
                f64::from(CAPTURE_FIELD_CHILD_BASE_ALLOWANCE),
            ),
            ("maxLayers", f64::from(MAX_CAPTURE_LAYERS)),
            (
                "maxLayersPerPacket",
                f64::from(MAX_CAPTURE_LAYERS_PER_PACKET),
            ),
            ("maxFields", f64::from(MAX_CAPTURE_FIELDS)),
            (
                "maxFieldsPerPacket",
                f64::from(MAX_CAPTURE_FIELDS_PER_PACKET),
            ),
            ("maxFieldChildren", f64::from(MAX_CAPTURE_FIELD_CHILDREN)),
            (
                "maxFieldChildrenPerPacket",
                f64::from(MAX_CAPTURE_FIELD_CHILDREN_PER_PACKET),
            ),
        ],
    )?;
    set_string(
        result,
        "decodedArenaAdmissionRule",
        "min(requestedTotal, globalTotal, max(arenaBase, ceil(captureBytes / admissionBytesPerItem)))",
    )
}

fn set_registry_and_output_capabilities(result: &Object) -> Result<(), JsValue> {
    set_capability_numbers(
        result,
        &[
            ("maxImportHandles", capability_usize(MAX_IMPORT_HANDLES)?),
            ("maxDatasetHandles", capability_usize(MAX_DATASET_HANDLES)?),
            (
                "maxPacketCursorHandles",
                capability_usize(MAX_PACKET_CURSOR_HANDLES)?,
            ),
            (
                "maxPacketBatchBytes",
                capability_usize(MAX_PACKET_BATCH_BYTES)?,
            ),
            ("maxPacketBatchRows", f64::from(MAX_PACKET_BATCH_ROWS)),
            (
                "maxPacketDetailBytes",
                capability_usize(MAX_PACKET_DETAIL_BYTES)?,
            ),
            (
                "maxPacketEvidenceBytes",
                f64::from(MAX_PACKET_EVIDENCE_BYTES),
            ),
            (
                "maxCorrelationMatches",
                f64::from(MAX_PACKET_CORRELATION_MATCHES),
            ),
        ],
    )
}

/// Returns the immutable resource and compatibility limits for this build.
#[wasm_bindgen]
pub fn capabilities() -> Result<JsValue, JsValue> {
    let result = try_new_object()?;
    set_core_capabilities(&result)?;
    set_packet_capabilities(&result)?;
    set_decoded_arena_capabilities(&result)?;
    set_registry_and_output_capabilities(&result)?;
    Ok(result.into())
}

/// Worker-owned state for one versioned `WireLens` Wasm boundary instance.
#[wasm_bindgen]
pub struct WireLensBoundary {
    state: BoundaryState,
}

#[wasm_bindgen]
impl WireLensBoundary {
    /// Creates an empty boundary after validating compatibility before mutation.
    #[wasm_bindgen(constructor)]
    pub fn new(api_version: f64) -> Result<Self, JsValue> {
        let api_version = exact_u32(api_version, "API version")?;
        if api_version != API_VERSION {
            return Err(web_error(
                "unsupported_version",
                "worker API version is unsupported",
            ));
        }
        Ok(Self {
            state: BoundaryState::new(),
        })
    }

    /// Copies one complete worker-owned byte array into bounded Rust ownership.
    #[wasm_bindgen(js_name = beginImport)]
    pub fn begin_import(&mut self, input: &Uint8Array) -> Result<u64, JsValue> {
        let byte_length = u64::from(input.length());
        let admission = self
            .state
            .admit_import_input(byte_length)
            .map_err(boundary_error_to_js)?;
        let mut bytes = allocate_import_copy_buffer(byte_length).map_err(boundary_error_to_js)?;
        input.copy_to(&mut bytes);
        let handle = self
            .state
            .begin_import_with_limits(bytes.into_boxed_slice(), admission.limits())
            .map_err(boundary_error_to_js)?;
        Ok(handle.raw())
    }

    /// Advances one bounded parse step or finalizes after a prior validating checkpoint.
    #[wasm_bindgen(js_name = stepImport)]
    pub fn step_import(
        &mut self,
        raw_handle: u64,
        max_records: f64,
        max_bytes: f64,
    ) -> Result<JsValue, JsValue> {
        let handle = BoundaryHandle::from_raw(raw_handle);
        let max_records = exact_u32(max_records, "import record budget")?;
        let max_bytes = exact_u32(max_bytes, "import byte budget")?;
        if max_records == 0
            || max_records > MAX_IMPORT_STEP_RECORDS
            || max_bytes == 0
            || u64::from(max_bytes) > MAX_IMPORT_STEP_BYTES
        {
            return Err(web_error(
                "invalid_argument",
                "capture import step budget is outside the supported range",
            ));
        }
        let current = self
            .state
            .import_progress(handle)
            .map_err(boundary_error_to_js)?;
        if step_call_action(current.phase) == StepCallAction::Finalize {
            let published = self
                .state
                .finish_import(handle)
                .map_err(boundary_error_to_js)?;
            let result =
                self.diagnostics(published.dataset)
                    .and_then(|(warning_codes, warnings)| {
                        import_step_result(
                            "complete",
                            published.progress,
                            Some((published.dataset, warning_codes, warnings)),
                        )
                    });
            if result.is_err() {
                // Publication is not observable until its handle is encoded in
                // the JS result. Roll back if result construction fails so the
                // caller is never left with an unreachable live dataset.
                let _ = self.state.dispose_dataset(published.dataset);
            }
            return result;
        }
        let advance = self
            .state
            .advance_import(handle, max_records, u64::from(max_bytes))
            .map_err(boundary_error_to_js)?;

        match advance {
            ImportAdvance::Progress(progress) | ImportAdvance::Ready(progress) => {
                import_step_result("in_progress", progress, None)
            }
            ImportAdvance::NeedsBudget {
                progress,
                minimum_bytes,
            } => {
                let result = import_step_result("in_progress", progress, None)?;
                let object: Object = result.unchecked_into();
                set_u64_lanes(&object, "minimumBytes", minimum_bytes)?;
                Ok(object.into())
            }
        }
    }

    /// Cancels a live import and releases its owned capture and parser state.
    #[wasm_bindgen(js_name = cancelImport)]
    pub fn cancel_import(&mut self, raw_handle: u64) -> Result<JsValue, JsValue> {
        let handle = BoundaryHandle::from_raw(raw_handle);
        let report = self
            .state
            .cancel_import(handle)
            .map_err(boundary_error_to_js)?;
        match report.status {
            DisposeStatus::Disposed => cancellation_result("cancelled", report.progress),
            DisposeStatus::AlreadyDisposed => cancellation_result("already_terminal", None),
        }
    }

    /// Disposes an import, dataset, or packet cursor by its encoded handle kind.
    #[wasm_bindgen]
    pub fn dispose(&mut self, raw_handle: u64) -> Result<JsValue, JsValue> {
        let handle = BoundaryHandle::from_raw(raw_handle);
        match handle.kind() {
            Some(HandleKind::Import) => {
                let report = self
                    .state
                    .cancel_import(handle)
                    .map_err(boundary_error_to_js)?;
                disposal_result(report.status, None)
            }
            Some(HandleKind::Dataset) => {
                let report = self
                    .state
                    .dispose_dataset(handle)
                    .map_err(boundary_error_to_js)?;
                disposal_result(report.status, Some(report.cascaded_packet_cursors))
            }
            Some(HandleKind::PacketCursor) => {
                let status = self
                    .state
                    .dispose_packet_cursor(handle)
                    .map_err(boundary_error_to_js)?;
                disposal_result(status, None)
            }
            None => Err(web_error("invalid_handle", "handle kind is invalid")),
        }
    }

    /// Opens a bounded packet cursor at an exact row representable by the v0.1 capture cap.
    #[wasm_bindgen(js_name = openPacketCursor)]
    pub fn open_packet_cursor(&mut self, raw_dataset: u64, start_row: f64) -> Result<u64, JsValue> {
        let start_row = exact_u32(start_row, "packet cursor start row")?;
        self.state
            .create_packet_cursor(BoundaryHandle::from_raw(raw_dataset), u64::from(start_row))
            .map(BoundaryHandle::raw)
            .map_err(boundary_error_to_js)
    }

    /// Returns one JavaScript-owned, transferable, versioned binary packet batch.
    #[wasm_bindgen(js_name = readPacketBatch)]
    pub fn read_packet_batch(
        &mut self,
        raw_cursor: u64,
        schema_version: f64,
        max_rows: f64,
        max_bytes: f64,
    ) -> Result<Uint8Array, JsValue> {
        let schema_version = exact_u32(schema_version, "batch schema version")?;
        if schema_version != u32::from(BATCH_SCHEMA_VERSION) {
            return Err(web_error(
                "unsupported_version",
                "packet batch schema version is unsupported",
            ));
        }
        let max_rows = exact_u32(max_rows, "packet batch row budget")?;
        let max_bytes = exact_u32(max_bytes, "packet batch byte budget")?;
        let cursor = BoundaryHandle::from_raw(raw_cursor);
        let batch = self
            .state
            .prepare_packet_batch_limited(cursor, max_rows, max_bytes)
            .map_err(boundary_error_to_js)?;
        // Allocate/copy the JS-owned payload before staging the transaction. A
        // binding allocation exception therefore cannot strand the cursor in
        // an unresolvable pending state.
        let bytes = copy_to_js_u8_array(batch.bytes())?;
        self.state
            .stage_prepared_packet_batch(cursor, &batch)
            .map_err(boundary_error_to_js)?;
        Ok(bytes)
    }

    /// Commits a validated packet batch and advances its cursor exactly once.
    #[wasm_bindgen(js_name = commitPacketBatch)]
    pub fn commit_packet_batch(
        &mut self,
        raw_cursor: u64,
        schema_version: f64,
        start_row: u64,
        next_row: u64,
    ) -> Result<(), JsValue> {
        let schema_version = exact_batch_schema_version(schema_version)?;
        self.state
            .commit_packet_batch(
                BoundaryHandle::from_raw(raw_cursor),
                schema_version,
                start_row,
                next_row,
            )
            .map_err(boundary_error_to_js)
    }

    /// Rejects a packet batch and makes the same cursor range readable again.
    #[wasm_bindgen(js_name = discardPacketBatch)]
    pub fn discard_packet_batch(
        &mut self,
        raw_cursor: u64,
        schema_version: f64,
        start_row: u64,
        next_row: u64,
    ) -> Result<(), JsValue> {
        let schema_version = exact_batch_schema_version(schema_version)?;
        self.state
            .discard_packet_batch(
                BoundaryHandle::from_raw(raw_cursor),
                schema_version,
                start_row,
                next_row,
            )
            .map_err(boundary_error_to_js)
    }

    /// Returns one JavaScript-owned, transferable packet-detail batch.
    #[wasm_bindgen(js_name = readPacketDetail)]
    pub fn read_packet_detail(
        &self,
        raw_dataset: u64,
        packet_id: f64,
        detail_schema_version: f64,
        max_bytes: f64,
    ) -> Result<Uint8Array, JsValue> {
        let packet_id = exact_u32(packet_id, "packet identity")?;
        let schema_version = exact_u32(detail_schema_version, "packet detail schema version")?;
        if schema_version != u32::from(PACKET_DETAIL_SCHEMA_VERSION) {
            return Err(web_error(
                "unsupported_version",
                "packet detail schema version is unsupported",
            ));
        }
        let max_bytes = exact_u32(max_bytes, "packet detail byte budget")?;
        let detail = self
            .state
            .read_packet_detail(
                BoundaryHandle::from_raw(raw_dataset),
                PacketId(packet_id),
                max_bytes,
            )
            .map_err(boundary_error_to_js)?;
        copy_to_js_u8_array(detail.bytes())
    }

    /// Copies one checked packet-relative evidence page to JavaScript ownership.
    #[wasm_bindgen(js_name = readPacketEvidence)]
    pub fn read_packet_evidence(
        &self,
        raw_dataset: u64,
        packet_id: f64,
        relative_start: f64,
        max_bytes: f64,
    ) -> Result<Uint8Array, JsValue> {
        let evidence = self
            .state
            .read_packet_evidence(
                BoundaryHandle::from_raw(raw_dataset),
                PacketId(exact_u32(packet_id, "packet identity")?),
                exact_u32(relative_start, "packet-relative evidence start")?,
                exact_u32(max_bytes, "packet evidence byte budget")?,
            )
            .map_err(boundary_error_to_js)?;
        copy_to_js_u8_array(evidence.bytes())
    }

    /// Returns matching global field identities in deterministic primary-first order.
    #[wasm_bindgen(js_name = correlatePacketRange)]
    pub fn correlate_packet_range(
        &self,
        raw_dataset: u64,
        packet_id: f64,
        relative_start: f64,
        length: f64,
    ) -> Result<Uint32Array, JsValue> {
        let packet_id = PacketId(exact_u32(packet_id, "packet identity")?);
        let relative_start = exact_u32(relative_start, "packet-relative selection start")?;
        let length = exact_u32(length, "packet-relative selection length")?;
        let selection = PacketRelativeRange::new(relative_start, length).ok_or_else(|| {
            web_error(
                "invalid_argument",
                "packet-relative selection range overflows",
            )
        })?;
        let matches = self
            .state
            .correlate_packet_range(BoundaryHandle::from_raw(raw_dataset), packet_id, selection)
            .map_err(boundary_error_to_js)?;
        let length = u32::try_from(matches.matches().len()).map_err(|_| {
            web_error(
                "internal_invariant",
                "packet correlation result exceeds its advertised limit",
            )
        })?;
        let result = try_new_u32_array(length)?;
        for (index, field) in matches.matches().iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| {
                web_error(
                    "internal_invariant",
                    "packet correlation result index exceeds u32",
                )
            })?;
            result.set_index(index, field.field_id.0);
        }
        Ok(result)
    }

    /// Copies one checked evidence range into a JavaScript-owned byte array.
    #[wasm_bindgen(js_name = readEvidence)]
    pub fn read_evidence(
        &self,
        raw_dataset: u64,
        start_high: f64,
        start_low: f64,
        length: f64,
    ) -> Result<Uint8Array, JsValue> {
        let start_high = exact_u32(start_high, "evidence offset high word")?;
        let start_low = exact_u32(start_low, "evidence offset low word")?;
        let length = exact_u32(length, "evidence byte length")?;
        let offset = (u64::from(start_high) << u32::BITS) | u64::from(start_low);
        let evidence = self
            .state
            .read_evidence(BoundaryHandle::from_raw(raw_dataset), offset, length)
            .map_err(boundary_error_to_js)?;
        copy_to_js_u8_array(evidence.bytes())
    }

    /// Returns payload-free logical ownership counters with exact 64-bit lanes.
    #[wasm_bindgen(js_name = resourceStats)]
    pub fn resource_stats(&self) -> Result<JsValue, JsValue> {
        resource_stats_object(self.state.resource_stats().map_err(boundary_error_to_js)?)
    }

    /// Returns current WebAssembly linear-memory bytes as an exact JavaScript `BigInt`.
    #[wasm_bindgen(js_name = wasmMemoryBytes)]
    #[allow(clippy::unused_self)] // Instance method keeps the worker facade lifecycle uniform.
    pub fn wasm_memory_bytes(&self) -> u64 {
        let memory: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
        let buffer: ArrayBuffer = memory.buffer().unchecked_into();
        u64::from(buffer.byte_length())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepCallAction {
    Advance,
    Finalize,
}

fn step_call_action(phase: ImportPhase) -> StepCallAction {
    if phase == ImportPhase::Ready {
        StepCallAction::Finalize
    } else {
        StepCallAction::Advance
    }
}

impl WireLensBoundary {
    fn diagnostics(&self, dataset: BoundaryHandle) -> Result<(Uint16Array, Array), JsValue> {
        let length = self
            .state
            .dataset_diagnostic_count(dataset)
            .map_err(boundary_error_to_js)?;
        let codes = try_new_u16_array(length)?;
        let warnings = try_new_array(length)?;
        for index in 0..length {
            let diagnostic = self
                .state
                .dataset_diagnostic(dataset, index)
                .map_err(boundary_error_to_js)?
                .ok_or_else(|| {
                    web_error(
                        "internal_invariant",
                        "diagnostic arena changed while producing the completion result",
                    )
                })?;
            codes.set_index(index, diagnostic.diagnostic.code.0);
            warnings.set(index, diagnostic_object(diagnostic)?.into());
        }
        Ok((codes, warnings))
    }
}

fn import_step_result(
    state: &str,
    progress: ImportProgressSnapshot,
    published: Option<(BoundaryHandle, Uint16Array, Array)>,
) -> Result<JsValue, JsValue> {
    let result = try_new_object()?;
    set_string(&result, "state", state)?;
    set_value(&result, "progress", &progress_object(progress)?.into())?;
    if let Some((dataset, warning_codes, warnings)) = published {
        set_value(
            &result,
            "datasetHandle",
            &BigInt::from(dataset.raw()).into(),
        )?;
        set_value(&result, "warningCodes", &warning_codes.into())?;
        set_value(&result, "warnings", &warnings.into())?;
    }
    Ok(result.into())
}

fn diagnostic_object(diagnostic: DatasetDiagnostic<'_>) -> Result<Object, JsValue> {
    let result = try_new_object()?;
    set_number(&result, "code", f64::from(diagnostic.diagnostic.code.0))?;
    set_string(
        &result,
        "severity",
        match diagnostic.diagnostic.severity {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Fatal => "fatal",
        },
    )?;
    set_string(
        &result,
        "recovery",
        match diagnostic.diagnostic.recovery {
            Recovery::Continued => "continued",
            Recovery::RecordSkipped => "record_skipped",
            Recovery::CaptureRejected => "capture_rejected",
        },
    )?;
    match diagnostic.diagnostic.scope {
        DiagnosticScope::Capture => set_string(&result, "scope", "capture")?,
        DiagnosticScope::Packet(packet_id) => {
            set_string(&result, "scope", "packet")?;
            set_number(&result, "packetId", f64::from(packet_id.0))?;
        }
    }
    if let Some(evidence) = diagnostic.diagnostic.byte_range {
        set_u64_lanes(&result, "evidenceStart", evidence.start())?;
        set_number(&result, "evidenceLength", f64::from(evidence.length()))?;
    }
    set_string(&result, "message", diagnostic.message)?;
    Ok(result)
}

fn cancellation_result(
    status: &str,
    progress: Option<ImportProgressSnapshot>,
) -> Result<JsValue, JsValue> {
    let result = try_new_object()?;
    set_string(&result, "status", status)?;
    if let Some(progress) = progress {
        set_value(&result, "progress", &progress_object(progress)?.into())?;
    }
    Ok(result.into())
}

fn disposal_result(
    status: DisposeStatus,
    dependent_cursors: Option<u32>,
) -> Result<JsValue, JsValue> {
    let result = try_new_object()?;
    let status = match status {
        DisposeStatus::Disposed => "disposed",
        DisposeStatus::AlreadyDisposed => "already_disposed",
    };
    set_string(&result, "status", status)?;
    if let Some(dependent_cursors) = dependent_cursors {
        set_number(&result, "dependentCursors", f64::from(dependent_cursors))?;
    }
    Ok(result.into())
}

fn resource_stats_object(stats: ResourceStats) -> Result<JsValue, JsValue> {
    let result = try_new_object()?;
    set_number(&result, "imports", f64::from(stats.active_imports))?;
    set_number(&result, "datasets", f64::from(stats.active_datasets))?;
    set_number(&result, "cursors", f64::from(stats.active_packet_cursors))?;
    set_u64_lanes(
        &result,
        "retainedCaptureBytes",
        stats.retained_capture_bytes,
    )?;
    set_u64_lanes(
        &result,
        "transientImportInputBytes",
        stats.transient_import_input_bytes,
    )?;
    set_u64_lanes(
        &result,
        "retainedPacketIndexBytes",
        stats.retained_packet_index_bytes,
    )?;
    set_u64_lanes(&result, "retainedIndexBytes", stats.retained_index_bytes)?;
    set_u64_lanes(
        &result,
        "retainedLogicalBytes",
        stats.retained_logical_bytes,
    )?;
    set_u64_lanes(
        &result,
        "transientParserBufferBytesUpperBound",
        stats.transient_parser_buffer_bytes_upper_bound,
    )?;
    set_u64_lanes(
        &result,
        "transientPacketIndexBytesUpperBound",
        stats.transient_packet_index_bytes_upper_bound,
    )?;
    set_u64_lanes(
        &result,
        "transientAuxiliaryBytesUpperBound",
        stats.transient_auxiliary_bytes_upper_bound,
    )?;
    set_u64_lanes(
        &result,
        "totalLogicalBytesUpperBound",
        stats.total_logical_bytes_upper_bound,
    )?;
    set_u64_lanes(
        &result,
        "currentOwnedCaptureBytes",
        stats.current_owned_capture_bytes,
    )?;
    set_u64_lanes(
        &result,
        "peakOwnedCaptureBytes",
        stats.peak_owned_capture_bytes,
    )?;
    set_u64_lanes(
        &result,
        "peakTransientImportInputBytes",
        stats.peak_transient_import_input_bytes,
    )?;
    set_u64_lanes(&result, "retainedBatchBytes", stats.retained_batch_bytes)?;
    Ok(result.into())
}

fn progress_object(progress: ImportProgressSnapshot) -> Result<Object, JsValue> {
    let result = try_new_object()?;
    let phase = match progress.phase {
        ImportPhase::Importing => "parsing",
        ImportPhase::Ready => "validating",
        ImportPhase::Published => "complete",
        ImportPhase::Cancelled => "cancelled",
        ImportPhase::Failed => "failed",
    };
    set_string(&result, "phase", phase)?;
    set_u64_lanes(&result, "bytesConsumed", progress.consumed_bytes)?;
    set_u64_lanes(&result, "totalBytes", progress.total_bytes)?;
    set_u64_lanes(&result, "records", progress.records_processed)?;
    set_u64_lanes(&result, "packetsRetained", progress.packets_retained)?;
    set_number(&result, "diagnostics", f64::from(progress.diagnostics))?;
    Ok(result)
}

fn boundary_error_to_js(error: BoundaryError) -> JsValue {
    let code = error_code_name(error.code());
    let result = Error::new(error.message());
    set_error_property(&result, "code", &JsValue::from_str(code));
    if let Some(offset) = error.input_offset() {
        set_error_u64_lanes(&result, "inputOffset", offset);
    }
    if let Some(limit) = error.resource_limit() {
        set_error_u64_lanes(&result, "resourceLimit", limit);
    }
    if let Some(progress) = error.terminal_import_progress()
        && let Ok(progress) = progress_object(progress)
    {
        set_error_property(&result, "progress", &progress.into());
    }
    result.into()
}

fn error_code_name(code: BoundaryErrorCode) -> &'static str {
    match code {
        BoundaryErrorCode::INVALID_HANDLE => "invalid_handle",
        BoundaryErrorCode::STALE_HANDLE => "stale_handle",
        BoundaryErrorCode::WRONG_HANDLE_KIND => "wrong_handle_kind",
        BoundaryErrorCode::REGISTRY_LIMIT
        | BoundaryErrorCode::BATCH_ROW_LIMIT
        | BoundaryErrorCode::BATCH_BYTE_LIMIT
        | BoundaryErrorCode::EVIDENCE_BYTE_LIMIT
        | BoundaryErrorCode::RESOURCE_LIMIT => "resource_limit",
        BoundaryErrorCode::CURSOR_OUT_OF_RANGE
        | BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE
        | BoundaryErrorCode::INVALID_ARGUMENT => "invalid_argument",
        BoundaryErrorCode::UNSUPPORTED_VERSION => "unsupported_version",
        BoundaryErrorCode::INVALID_STATE => "invalid_state",
        BoundaryErrorCode::CAPTURE_FORMAT => "unsupported_format",
        BoundaryErrorCode::MALFORMED_CAPTURE => "malformed_capture",
        BoundaryErrorCode::TRUNCATED_CAPTURE => "truncated_capture",
        BoundaryErrorCode::CANCELLED => "cancelled",
        _ => "internal_invariant",
    }
}

fn exact_u32(value: f64, label: &str) -> Result<u32, JsValue> {
    if !value.is_finite() || value.fract() != 0.0 || !(0.0..=f64::from(u32::MAX)).contains(&value) {
        return Err(web_error(
            "invalid_argument",
            &format!("{label} must be an unsigned 32-bit integer"),
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u32)
}

fn exact_batch_schema_version(value: f64) -> Result<u16, JsValue> {
    let value = exact_u32(value, "batch schema version")?;
    u16::try_from(value).map_err(|_| {
        web_error(
            "unsupported_version",
            "packet batch schema version is unsupported",
        )
    })
}

fn web_error(code: &str, message: &str) -> JsValue {
    let result = Error::new(message);
    set_error_property(&result, "code", &JsValue::from_str(code));
    result.into()
}

fn set_error_property(error: &Error, name: &str, value: &JsValue) {
    let _ = Reflect::set(error.as_ref(), &JsValue::from_str(name), value);
}

fn set_error_u64_lanes(error: &Error, prefix: &str, value: u64) {
    let (high, low) = split_u64(value);
    set_error_property(
        error,
        &format!("{prefix}Hi"),
        &JsValue::from_f64(f64::from(high)),
    );
    set_error_property(
        error,
        &format!("{prefix}Lo"),
        &JsValue::from_f64(f64::from(low)),
    );
}

fn set_u64_lanes(object: &Object, prefix: &str, value: u64) -> Result<(), JsValue> {
    let (high, low) = split_u64(value);
    set_number(object, &format!("{prefix}Hi"), f64::from(high))?;
    set_number(object, &format!("{prefix}Lo"), f64::from(low))
}

#[allow(clippy::cast_possible_truncation)]
const fn split_u64(value: u64) -> (u32, u32) {
    ((value >> u32::BITS) as u32, value as u32)
}

fn set_string(object: &Object, name: &str, value: &str) -> Result<(), JsValue> {
    set_value(object, name, &JsValue::from_str(value))
}

fn set_number(object: &Object, name: &str, value: f64) -> Result<(), JsValue> {
    set_value(object, name, &JsValue::from_f64(value))
}

fn set_value(object: &Object, name: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(name), value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{StepCallAction, error_code_name, step_call_action};
    use crate::{BoundaryErrorCode, ImportPhase};

    #[test]
    fn ready_phase_requires_a_follow_up_call_before_finalization() {
        assert_eq!(
            step_call_action(ImportPhase::Importing),
            StepCallAction::Advance
        );
        assert_eq!(
            step_call_action(ImportPhase::Ready),
            StepCallAction::Finalize
        );
    }

    #[test]
    fn stale_handles_keep_their_public_error_category() {
        assert_eq!(
            error_code_name(BoundaryErrorCode::STALE_HANDLE),
            "stale_handle"
        );
        assert_eq!(
            error_code_name(BoundaryErrorCode::INVALID_HANDLE),
            "invalid_handle"
        );
    }
}
