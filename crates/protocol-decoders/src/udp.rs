//! Bounded UDP decoding.

use packet_core::{
    ByteRange, DiagnosticCode, FieldValue, ImportError, PacketDecodeInput, PacketDecodeSink,
    Severity,
};

use crate::{
    ChildIds, NetworkPayload, NetworkVersion, ProtocolFinding, TransportDecode, TransportPayload,
    TransportProtocol, add_named_field, checksum::transport_checksum_valid, finish_layer,
    packet_slice, read_u16, record_finding,
};

const HEADER_LENGTH: usize = 8;
const PROTOCOL_NUMBER: u8 = 17;

const PRIORITY_CHECKSUM: u8 = 10;
const PRIORITY_TRUNCATED: u8 = 100;
const PRIORITY_MALFORMED: u8 = 120;

const MESSAGE_TRUNCATED_HEADER: &str =
    "UDP header ends before all eight fixed-header bytes are available";
const MESSAGE_HEADER_EXCEEDS_DATAGRAM: &str =
    "The enclosing network payload is shorter than the eight-byte UDP header";
const MESSAGE_INVALID_LENGTH: &str = "UDP length is smaller than its eight-byte header";
const MESSAGE_LENGTH_EXCEEDS_NETWORK: &str =
    "UDP length exceeds the enclosing network payload length";
const MESSAGE_TRUNCATED_DATAGRAM: &str =
    "UDP datagram ends before all bytes declared by its length are available";
const MESSAGE_INVALID_CHECKSUM: &str =
    "UDP checksum does not validate; capture offload may explain the observed value";
const MESSAGE_ZERO_IPV6_CHECKSUM: &str =
    "UDP over IPv6 carries a zero checksum, which is not valid for ordinary IPv6 UDP traffic";

#[allow(clippy::too_many_lines)]
pub(crate) fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
) -> Result<TransportDecode, ImportError> {
    let bytes = packet_slice(input, network.payload_range)?;
    let available = bytes.len();
    let layer_range = payload_range(network, 0, available.min(HEADER_LENGTH))?;
    let root = add_named_field(sink, "udp", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    if available >= 2 {
        add_u16(sink, &mut children, "source_port", bytes, network, 0)?;
    }
    if available >= 4 {
        add_u16(sink, &mut children, "destination_port", bytes, network, 2)?;
    }
    if available >= 6 {
        add_u16(sink, &mut children, "length", bytes, network, 4)?;
    }
    if available >= HEADER_LENGTH {
        add_u16(sink, &mut children, "checksum", bytes, network, 6)?;
    }

    if available < HEADER_LENGTH {
        let declared_length = network.declared_length as usize;
        let finding = if network.fragment.is_complete_datagram() && declared_length < HEADER_LENGTH
        {
            Some(ProtocolFinding {
                priority: PRIORITY_MALFORMED,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: evidence_or_selector(layer_range, network.selector_range),
                message: MESSAGE_HEADER_EXCEEDS_DATAGRAM,
            })
        } else if available < declared_length {
            Some(ProtocolFinding {
                priority: PRIORITY_TRUNCATED,
                code: DiagnosticCode::TRUNCATED_PROTOCOL,
                severity: Severity::Error,
                evidence: evidence_or_selector(layer_range, network.selector_range),
                message: MESSAGE_TRUNCATED_HEADER,
            })
        } else {
            None
        };
        finish_layer(sink, "udp", layer_range, root, &children)?;
        return Ok(TransportDecode::new(None, finding));
    }

    let source_port = read_u16(bytes, 0).ok_or(ImportError::Arithmetic)?;
    let destination_port = read_u16(bytes, 2).ok_or(ImportError::Arithmetic)?;
    let declared_length = usize::from(read_u16(bytes, 4).ok_or(ImportError::Arithmetic)?);
    let checksum = read_u16(bytes, 6).ok_or(ImportError::Arithmetic)?;
    let length_range = payload_range(network, 4, 2)?;
    let checksum_range = payload_range(network, 6, 2)?;
    let mut finding = None;

    if network.fragment.is_complete_datagram()
        && network.version == NetworkVersion::Ipv6
        && checksum == 0
    {
        record_finding(
            &mut finding,
            Some(ProtocolFinding {
                priority: PRIORITY_CHECKSUM,
                code: DiagnosticCode::INVALID_PROTOCOL_CHECKSUM,
                severity: Severity::Warning,
                evidence: checksum_range,
                message: MESSAGE_ZERO_IPV6_CHECKSUM,
            }),
        );
    }

    if declared_length < HEADER_LENGTH {
        record_finding(
            &mut finding,
            Some(ProtocolFinding {
                priority: PRIORITY_MALFORMED,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: length_range,
                message: MESSAGE_INVALID_LENGTH,
            }),
        );
        finish_layer(sink, "udp", layer_range, root, &children)?;
        return Ok(TransportDecode::new(None, finding));
    }

    // The UDP length describes the complete datagram rather than one fragment.
    // A first fragment may expose the fixed header, but cannot establish the
    // complete payload extent or checksum domain without reassembly.
    if !network.fragment.is_complete_datagram() {
        finish_layer(sink, "udp", layer_range, root, &children)?;
        return Ok(TransportDecode::new(None, finding));
    }

    if u64::try_from(declared_length).map_err(|_| ImportError::Arithmetic)?
        > u64::from(network.declared_length)
    {
        record_finding(
            &mut finding,
            Some(ProtocolFinding {
                priority: PRIORITY_MALFORMED,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: length_range,
                message: MESSAGE_LENGTH_EXCEEDS_NETWORK,
            }),
        );
        finish_layer(sink, "udp", layer_range, root, &children)?;
        return Ok(TransportDecode::new(None, finding));
    }

    if declared_length > available {
        record_finding(
            &mut finding,
            Some(ProtocolFinding {
                priority: PRIORITY_TRUNCATED,
                code: DiagnosticCode::TRUNCATED_PROTOCOL,
                severity: Severity::Error,
                evidence: length_range,
                message: MESSAGE_TRUNCATED_DATAGRAM,
            }),
        );
        finish_layer(sink, "udp", layer_range, root, &children)?;
        return Ok(TransportDecode::new(None, finding));
    }

    let datagram_range = payload_range(network, 0, declared_length)?;
    if checksum != 0 {
        if let Some(checksum_valid) =
            transport_checksum_valid(input, network, PROTOCOL_NUMBER, datagram_range)?
        {
            children.push(add_named_field(
                sink,
                "checksum_valid",
                FieldValue::Boolean(checksum_valid),
                checksum_range,
            )?)?;
            if !checksum_valid {
                record_finding(
                    &mut finding,
                    Some(ProtocolFinding {
                        priority: PRIORITY_CHECKSUM,
                        code: DiagnosticCode::INVALID_PROTOCOL_CHECKSUM,
                        severity: Severity::Warning,
                        evidence: checksum_range,
                        message: MESSAGE_INVALID_CHECKSUM,
                    }),
                );
            }
        }
    }

    let application_length = declared_length
        .checked_sub(HEADER_LENGTH)
        .ok_or(ImportError::Arithmetic)?;
    let application_range = payload_range(network, HEADER_LENGTH, application_length)?;
    let application_length =
        u32::try_from(application_length).map_err(|_| ImportError::Arithmetic)?;
    finish_layer(sink, "udp", layer_range, root, &children)?;

    Ok(TransportDecode::new(
        Some(TransportPayload {
            protocol: TransportProtocol::Udp,
            source_port,
            destination_port,
            payload_range: application_range,
            declared_length: application_length,
        }),
        finding,
    ))
}

fn payload_range(
    network: NetworkPayload,
    offset: usize,
    length: usize,
) -> Result<ByteRange, ImportError> {
    let offset = u32::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    network
        .payload_range
        .child(offset, length)
        .ok_or(ImportError::Arithmetic)
}

const fn evidence_or_selector(range: ByteRange, selector: ByteRange) -> ByteRange {
    if range.length() == 0 { selector } else { range }
}

fn add_u16(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    bytes: &[u8],
    network: NetworkPayload,
    offset: usize,
) -> Result<(), ImportError> {
    let value = read_u16(bytes, offset).ok_or(ImportError::Arithmetic)?;
    let range = payload_range(network, offset, 2)?;
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Unsigned(u64::from(value)),
        range,
    )?)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use packet_core::{
        CaptureImporter, ImportLimits, ImportStep, PacketDecodeInput, PacketDecodeSink,
        PacketDecoder,
    };

    use super::*;
    use crate::{FragmentPosition, NetworkChecksumContext};

    #[derive(Clone)]
    struct PayloadProbe {
        fragment: FragmentPosition,
        declared_length: u32,
        observed: Arc<Mutex<Option<TransportPayload>>>,
    }

    impl PacketDecoder for PayloadProbe {
        fn decode(
            &mut self,
            input: PacketDecodeInput<'_>,
            sink: &mut PacketDecodeSink<'_>,
        ) -> Result<(), ImportError> {
            let data = input.data_range();
            let payload_length = data
                .length()
                .checked_sub(8)
                .ok_or(ImportError::Arithmetic)?;
            let network = NetworkPayload {
                version: NetworkVersion::Ipv4,
                next_header: PROTOCOL_NUMBER,
                selector_range: data.child(0, 1).ok_or(ImportError::Arithmetic)?,
                payload_range: data
                    .child(8, payload_length)
                    .ok_or(ImportError::Arithmetic)?,
                declared_length: self.declared_length,
                fragment: self.fragment,
                checksum_context: NetworkChecksumContext {
                    source_address: data.child(0, 4).ok_or(ImportError::Arithmetic)?,
                    destination_address: Some(data.child(4, 4).ok_or(ImportError::Arithmetic)?),
                },
            };
            let decoded = super::decode(input, sink, network)?;
            *self.observed.lock().expect("probe lock is not poisoned") = decoded.payload;
            Ok(())
        }
    }

    fn probe(
        udp_bytes: &[u8],
        declared_length: u32,
        fragment: FragmentPosition,
    ) -> Option<TransportPayload> {
        let mut packet = Vec::with_capacity(8 + udp_bytes.len());
        packet.extend([192, 0, 2, 1]);
        packet.extend([198, 51, 100, 9]);
        packet.extend(udp_bytes);
        let capture = legacy_capture(&packet);
        let observed = Arc::new(Mutex::new(None));
        let mut importer = CaptureImporter::new_with_decoder(
            capture.into_boxed_slice(),
            ImportLimits::default(),
            Box::new(PayloadProbe {
                fragment,
                declared_length,
                observed: Arc::clone(&observed),
            }),
        )
        .expect("synthetic UDP probe capture is valid");
        loop {
            match importer
                .step(16, 1024 * 1024)
                .expect("synthetic UDP probe import succeeds")
            {
                ImportStep::Progress(_) => {}
                ImportStep::NeedsBudget { minimum_bytes, .. } => {
                    importer
                        .step(1, minimum_bytes)
                        .expect("reported minimum makes progress");
                }
                ImportStep::Ready(_) => break,
            }
        }
        importer.finish().expect("probe dataset validates");
        *observed.lock().expect("probe lock is not poisoned")
    }

    fn legacy_capture(packet: &[u8]) -> Vec<u8> {
        let packet_length = u32::try_from(packet.len()).expect("packet length fits u32");
        let mut capture = Vec::with_capacity(40 + packet.len());
        capture.extend([0xd4, 0xc3, 0xb2, 0xa1]);
        capture.extend(2_u16.to_le_bytes());
        capture.extend(4_u16.to_le_bytes());
        capture.extend(0_i32.to_le_bytes());
        capture.extend(0_u32.to_le_bytes());
        capture.extend(65_535_u32.to_le_bytes());
        capture.extend(101_u32.to_le_bytes());
        capture.extend(1_u32.to_le_bytes());
        capture.extend(2_u32.to_le_bytes());
        capture.extend(packet_length.to_le_bytes());
        capture.extend(packet_length.to_le_bytes());
        capture.extend(packet);
        capture
    }

    fn udp_bytes(declared_length: u16, payload_and_padding: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + payload_and_padding.len());
        bytes.extend(53_000_u16.to_be_bytes());
        bytes.extend(53_u16.to_be_bytes());
        bytes.extend(declared_length.to_be_bytes());
        bytes.extend(0_u16.to_be_bytes());
        bytes.extend(payload_and_padding);
        bytes
    }

    #[test]
    fn hands_off_only_the_udp_declared_payload_without_network_padding() {
        let bytes = udp_bytes(11, &[1, 2, 3, 0xde, 0xad, 0xbe, 0xef]);
        let payload = probe(
            &bytes,
            u32::try_from(bytes.len()).expect("probe length fits u32"),
            FragmentPosition::Unfragmented,
        )
        .expect("sound UDP framing has a bounded application handoff");

        assert_eq!(payload.protocol, TransportProtocol::Udp);
        assert_eq!(payload.source_port, 53_000);
        assert_eq!(payload.destination_port, 53);
        assert_eq!(payload.payload_range, ByteRange::new(56, 3).unwrap());
        assert_eq!(payload.declared_length, 3);
    }

    #[test]
    fn first_fragments_and_unsound_lengths_do_not_reach_application_dispatch() {
        let fragment = udp_bytes(40, &[0; 8]);
        assert!(
            probe(
                &fragment,
                u32::try_from(fragment.len()).expect("probe length fits u32"),
                FragmentPosition::Initial {
                    more_fragments: true,
                },
            )
            .is_none()
        );

        let malformed = udp_bytes(7, &[]);
        assert!(
            probe(
                &malformed,
                u32::try_from(malformed.len()).expect("probe length fits u32"),
                FragmentPosition::Unfragmented,
            )
            .is_none()
        );
    }
}
