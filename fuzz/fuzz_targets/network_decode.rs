#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_core::{
    CaptureDataset, CaptureImporter, DiagnosticScope, FieldValue, ImportLimits, ImportProgress,
    ImportStep,
};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, DECODER_VOCABULARY_COUNT_UPPER_BOUND, LinkLayerDecoder,
};

const HEX_PREFIX: &[u8] = b"hex:";
const MAX_NETWORK_BYTES: usize = 4_096;
const MAX_FUZZ_INPUT_BYTES: usize = MAX_NETWORK_BYTES + 1;
const MAX_ENCODED_BYTES: usize = HEX_PREFIX.len() + (MAX_FUZZ_INPUT_BYTES * 2) + 128;
const ETHERNET_HEADER_BYTES: usize = 14;
const VLAN_HEADER_BYTES: usize = 18;
const LEGACY_HEADER_BYTES: usize = 24;
const LEGACY_RECORD_HEADER_BYTES: usize = 16;
const PCAPNG_SECTION_BYTES: usize = 28;
const PCAPNG_INTERFACE_BYTES: usize = 20;
const PCAPNG_PACKET_OVERHEAD_BYTES: usize = 32;
const MAX_FRAME_BYTES: usize = VLAN_HEADER_BYTES + MAX_NETWORK_BYTES;
const MAX_PCAPNG_PACKET_BYTES: usize = PCAPNG_PACKET_OVERHEAD_BYTES + align4(MAX_FRAME_BYTES);
const MAX_WRAPPED_CAPTURE_BYTES: usize =
    PCAPNG_SECTION_BYTES + PCAPNG_INTERFACE_BYTES + MAX_PCAPNG_PACKET_BYTES;
const MAX_WRAPPED_BLOCK_BYTES: u32 = MAX_PCAPNG_PACKET_BYTES as u32;
const MAX_DRIVER_STEPS: usize = 16;
const INITIAL_STEP_BYTE_BUDGET: u64 = 31;

#[derive(Clone, Copy)]
struct Selector(u8);

impl Selector {
    fn ipv6(self) -> bool {
        self.0 & 1 != 0
    }

    fn vlan(self) -> bool {
        self.0 & 2 != 0
    }

    fn pcapng(self) -> bool {
        self.0 & 4 != 0
    }
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn fuzz_limits() -> ImportLimits {
    ImportLimits {
        max_capture_bytes: MAX_WRAPPED_CAPTURE_BYTES as u64,
        max_block_bytes: MAX_WRAPPED_BLOCK_BYTES,
        max_decoded_items_per_block: 16,
        max_decoded_items_per_step: 16,
        max_packets: 1,
        max_sections: 1,
        max_interfaces: 1,
        max_diagnostics: 32,
        max_layers: DECODER_MAX_LAYERS_PER_PACKET,
        max_layers_per_packet: DECODER_MAX_LAYERS_PER_PACKET,
        max_fields: DECODER_MAX_FIELDS_PER_PACKET,
        max_fields_per_packet: DECODER_MAX_FIELDS_PER_PACKET,
        max_field_children: DECODER_MAX_FIELD_CHILDREN_PER_PACKET,
        max_field_children_per_packet: DECODER_MAX_FIELD_CHILDREN_PER_PACKET,
        max_string_bytes: 16 * 1024,
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_text_seed(data: &[u8]) -> Option<Vec<u8>> {
    let encoded = data.strip_prefix(HEX_PREFIX)?;
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let mut high_nibble = None;
    for &byte in encoded {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = hex_value(byte)?;
        if let Some(high) = high_nibble.take() {
            if decoded.len() == MAX_FUZZ_INPUT_BYTES {
                return None;
            }
            decoded.push((high << 4) | nibble);
        } else {
            high_nibble = Some(nibble);
        }
    }
    if high_nibble.is_some() {
        return None;
    }
    Some(decoded)
}

fn bounded_input(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_ENCODED_BYTES {
        return None;
    }
    if data.starts_with(HEX_PREFIX) {
        if let Some(decoded) = decode_text_seed(data) {
            return Some(decoded);
        }
    }
    (data.len() <= MAX_FUZZ_INPUT_BYTES).then(|| data.to_vec())
}

fn ethernet_frame(selector: Selector, network_bytes: &[u8]) -> Vec<u8> {
    let header_bytes = if selector.vlan() {
        VLAN_HEADER_BYTES
    } else {
        ETHERNET_HEADER_BYTES
    };
    let mut frame = Vec::with_capacity(header_bytes + network_bytes.len());
    frame.extend([0x02, 0, 0, 0, 0, 1]);
    frame.extend([0x02, 0, 0, 0, 0, 2]);
    let ether_type = if selector.ipv6() { 0x86dd_u16 } else { 0x0800 };
    if selector.vlan() {
        frame.extend(0x8100_u16.to_be_bytes());
        frame.extend(100_u16.to_be_bytes());
    }
    frame.extend(ether_type.to_be_bytes());
    frame.extend_from_slice(network_bytes);
    frame
}

fn legacy_pcap(frame: &[u8]) -> Vec<u8> {
    let frame_length = u32::try_from(frame.len()).expect("bounded frame length fits u32");
    let mut capture =
        Vec::with_capacity(LEGACY_HEADER_BYTES + LEGACY_RECORD_HEADER_BYTES + frame.len());
    capture.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    capture.extend(2_u16.to_le_bytes());
    capture.extend(4_u16.to_le_bytes());
    capture.extend(0_i32.to_le_bytes());
    capture.extend(0_u32.to_le_bytes());
    capture.extend(65_535_u32.to_le_bytes());
    capture.extend(1_u32.to_le_bytes());
    capture.extend(1_700_000_000_u32.to_le_bytes());
    capture.extend(123_456_u32.to_le_bytes());
    capture.extend(frame_length.to_le_bytes());
    capture.extend(frame_length.to_le_bytes());
    capture.extend_from_slice(frame);
    capture
}

fn pcapng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let block_length = u32::try_from(12 + body.len()).expect("bounded block length fits u32");
    assert_eq!(block_length % 4, 0);
    let mut block = Vec::with_capacity(block_length as usize);
    block.extend(block_type.to_le_bytes());
    block.extend(block_length.to_le_bytes());
    block.extend_from_slice(body);
    block.extend(block_length.to_le_bytes());
    block
}

fn pcapng(frame: &[u8]) -> Vec<u8> {
    let mut section = Vec::with_capacity(16);
    section.extend(0x1a2b_3c4d_u32.to_le_bytes());
    section.extend(1_u16.to_le_bytes());
    section.extend(0_u16.to_le_bytes());
    section.extend((-1_i64).to_le_bytes());

    let mut interface = Vec::with_capacity(8);
    interface.extend(1_u16.to_le_bytes());
    interface.extend(0_u16.to_le_bytes());
    interface.extend(65_535_u32.to_le_bytes());

    let frame_length = u32::try_from(frame.len()).expect("bounded frame length fits u32");
    let mut packet = Vec::with_capacity(20 + align4(frame.len()));
    packet.extend(0_u32.to_le_bytes());
    packet.extend(0_u32.to_le_bytes());
    packet.extend(123_u32.to_le_bytes());
    packet.extend(frame_length.to_le_bytes());
    packet.extend(frame_length.to_le_bytes());
    packet.extend_from_slice(frame);
    packet.resize(20 + align4(frame.len()), 0);

    let mut capture = Vec::with_capacity(
        PCAPNG_SECTION_BYTES + PCAPNG_INTERFACE_BYTES + PCAPNG_PACKET_OVERHEAD_BYTES + frame.len(),
    );
    capture.extend(pcapng_block(0x0a0d_0d0a, &section));
    capture.extend(pcapng_block(1, &interface));
    capture.extend(pcapng_block(6, &packet));
    capture
}

fn wrapped_capture(input: &[u8]) -> Vec<u8> {
    let (selector, network_bytes) = input
        .split_first()
        .map_or((Selector(0), &[][..]), |(&selector, bytes)| {
            (Selector(selector & 7), bytes)
        });
    assert!(network_bytes.len() <= MAX_NETWORK_BYTES);
    let frame = ethernet_frame(selector, network_bytes);
    let capture = if selector.pcapng() {
        pcapng(&frame)
    } else {
        legacy_pcap(&frame)
    };
    assert!(capture.len() <= MAX_WRAPPED_CAPTURE_BYTES);
    capture
}

fn decoded_importer(bytes: Box<[u8]>) -> CaptureImporter {
    CaptureImporter::new_with_decoder(bytes, fuzz_limits(), Box::new(LinkLayerDecoder::new()))
        .expect("the deterministic capture wrapper is valid")
}

fn assert_monotonic(previous: ImportProgress, current: ImportProgress) {
    assert_eq!(current.total_bytes, previous.total_bytes);
    assert!(current.consumed_bytes >= previous.consumed_bytes);
    assert!(current.consumed_bytes <= current.total_bytes);
    assert!(current.records_processed >= previous.records_processed);
    assert!(current.packets_retained >= previous.packets_retained);
    assert!(current.packets_retained <= current.records_processed);
    assert!(current.diagnostics >= previous.diagnostics);
}

fn assert_valid_dataset(dataset: &CaptureDataset) {
    dataset
        .validate()
        .expect("a completed network decode preserves canonical model invariants");
    assert_eq!(dataset.metadata().packet_count, 1);
    assert_eq!(dataset.packets().len(), 1);
    assert_eq!(dataset.sections().len(), 1);
    assert_eq!(dataset.interfaces().len(), 1);
    assert!(dataset.layers().len() <= DECODER_MAX_LAYERS_PER_PACKET as usize);
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
    assert!(dataset.interned_string_count() <= DECODER_VOCABULARY_COUNT_UPPER_BOUND as usize);
    assert!(
        dataset
            .interned_string_bytes()
            .is_some_and(|bytes| bytes <= u64::from(fuzz_limits().max_string_bytes))
    );

    let packet = dataset.packets()[0];
    assert_eq!(packet.layers.start(), 0);
    assert_eq!(packet.layers.end() as usize, dataset.layers().len());
    assert_eq!(packet.diagnostics.start(), 0);
    assert_eq!(
        packet.diagnostics.end() as usize,
        dataset.diagnostics().len()
    );
    let contains = |range: packet_core::ByteRange| {
        range.start() >= packet.data.start() && range.end() <= packet.data.end()
    };
    for layer in dataset.layers() {
        assert!(contains(layer.byte_range));
    }
    for field in dataset.fields() {
        assert!(contains(field.byte_range));
        if let FieldValue::Bytes(range) = field.value {
            assert!(contains(range));
        }
    }
    for child in dataset.field_children() {
        assert!((child.0 as usize) < dataset.fields().len());
    }
    for diagnostic in dataset.diagnostics() {
        assert_eq!(diagnostic.scope, DiagnosticScope::Packet(packet.id));
        if let Some(range) = diagnostic.byte_range {
            assert!(contains(range));
        }
    }
}

fn exercise_cancellation(bytes: &[u8]) {
    let mut importer = decoded_importer(bytes.to_vec().into_boxed_slice());
    let before = importer.progress();
    let _ = importer.step(1, INITIAL_STEP_BYTE_BUDGET);
    let cancelled = importer.cancel();
    assert_monotonic(before, cancelled);
}

fn exercise_to_terminal(bytes: Vec<u8>) {
    let mut importer = decoded_importer(bytes.into_boxed_slice());
    let mut previous = importer.progress();
    let mut byte_budget = INITIAL_STEP_BYTE_BUDGET;

    for _ in 0..MAX_DRIVER_STEPS {
        let outcome = importer
            .step(1, byte_budget)
            .expect("the bounded network decoder handles every packet byte sequence");
        match outcome {
            ImportStep::NeedsBudget {
                progress,
                minimum_bytes,
            } => {
                assert_eq!(progress, previous);
                assert!(minimum_bytes > byte_budget);
                assert!(minimum_bytes <= u64::from(fuzz_limits().max_block_bytes));
                byte_budget = minimum_bytes;
            }
            ImportStep::Progress(progress) => {
                assert_monotonic(previous, progress);
                assert!(progress.consumed_bytes > previous.consumed_bytes);
                assert!(progress.consumed_bytes - previous.consumed_bytes <= byte_budget);
                assert!(progress.records_processed - previous.records_processed <= 1);
                previous = progress;
                byte_budget = INITIAL_STEP_BYTE_BUDGET;
            }
            ImportStep::Ready(progress) => {
                assert_monotonic(previous, progress);
                assert!(importer.is_complete());
                assert_eq!(
                    importer
                        .step(1, INITIAL_STEP_BYTE_BUDGET)
                        .expect("a completed importer remains ready"),
                    ImportStep::Ready(progress)
                );
                let dataset = importer
                    .finish()
                    .expect("a ready network import finalizes into a valid dataset");
                assert_valid_dataset(&dataset);
                return;
            }
        }
    }

    panic!("bounded network importer did not reach a terminal result");
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = bounded_input(data) else {
        return;
    };
    let capture = wrapped_capture(&input);
    exercise_cancellation(&capture);
    exercise_to_terminal(capture);
});
