//! Bidirectional flow reconstruction for already-decoded protocol layers.

use std::collections::BTreeMap;

use crate::{
    ByteRange, CaptureDataset, CaptureTimestamp, FieldId, FieldValue, IndexRange, InterfaceId,
    LayerFact, PacketId, PacketRecord, TimestampResolution,
};

/// Identifier for one reconstructed flow.
/// Stable duration measured in interface packet timestamps.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpFlowDuration {
    /// Number of elapsed timestamp ticks.
    pub ticks: u64,
    /// Timestamp resolution used for ticks.
    pub resolution: TimestampResolution,
}

impl TcpFlowDuration {
    /// Returns `true` when this duration represents at least one tick.
    pub const fn is_nonzero(&self) -> bool {
        self.ticks > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId(pub u32);

/// Supported transport protocols for flow reconstruction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportProtocol {
    /// TCP flow protocol.
    Tcp,
    /// UDP flow protocol.
    Udp,
}

/// Canonical flow endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpAddress {
    /// IPv4 address as 4 network-order bytes.
    V4([u8; 4]),
    /// IPv6 address as 16 network-order bytes.
    V6([u8; 16]),
}

/// Canonical flow endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowEndpoint {
    /// IP address as normalized 4- or 16-byte network order bytes.
    pub address: IpAddress,
    /// Transport layer port.
    pub port: u16,
}

/// Packet direction within a canonical flow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlowDirection {
    /// Packet maps to `endpoint_a -> endpoint_b`.
    AToB,
    /// Packet maps to `endpoint_b -> endpoint_a`.
    BToA,
    /// Endpoints are structurally identical and direction is ambiguous.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct FlowKey {
    interface_id: InterfaceId,
    protocol: TransportProtocol,
    endpoint_a: FlowEndpoint,
    endpoint_b: FlowEndpoint,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FlowAccumulator {
    packets_from_a: u64,
    packets_from_b: u64,
    bytes_from_a: u64,
    bytes_from_b: u64,
    first_timestamp: Option<CaptureTimestamp>,
    last_timestamp: Option<CaptureTimestamp>,
}

impl FlowAccumulator {
    const fn packets_total(&self) -> u64 {
        self.packets_from_a + self.packets_from_b
    }

    const fn bytes_total(&self) -> u64 {
        self.bytes_from_a + self.bytes_from_b
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TcpDirectionAccumulator {
    last_sequence: Option<u32>,
    last_sequence_packet: Option<PacketEvidence>,
    last_ack: Option<u32>,
    last_ack_packet: Option<PacketEvidence>,
}

#[derive(Clone, Copy, Debug, Default)]
struct TcpFlowAccumulator {
    packets: FlowAccumulator,
    first_syn: Option<PacketEvidence>,
    first_syn_direction: Option<FlowDirection>,
    syn_ack: Option<PacketEvidence>,
    established_ack: Option<PacketEvidence>,
    repeated_syn: Option<PacketPairEvidence>,
    reset: Option<PacketEvidence>,
    fin_first: Option<(FlowDirection, PacketEvidence)>,
    fin_last: Option<(FlowDirection, PacketEvidence)>,
    retransmission: Option<TcpDirectionalIndicator>,
    duplicate_ack: Option<TcpDirectionalIndicator>,
    out_of_order: Option<TcpDirectionalIndicator>,
    first_syn_timestamp: Option<CaptureTimestamp>,
    established_ack_timestamp: Option<CaptureTimestamp>,
    first_data_timestamp: Option<CaptureTimestamp>,
    direction_a: TcpDirectionAccumulator,
    direction_b: TcpDirectionAccumulator,
}

#[derive(Clone, Debug, Default)]
struct PacketSizeAccumulator {
    sample_count: u64,
    min: Option<u32>,
    max: Option<u32>,
    total: u64,
    buckets: [u64; 8],
}

impl PacketSizeAccumulator {
    fn record(&mut self, size: u32) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.total = self.total.saturating_add(u64::from(size));
        self.min = Some(self.min.map_or(size, |value| value.min(size)));
        self.max = Some(self.max.map_or(size, |value| value.max(size)));

        let bucket = match size {
            0..=63 => 0,
            64..=127 => 1,
            128..=255 => 2,
            256..=511 => 3,
            512..=1023 => 4,
            1024..=2047 => 5,
            2048..=4095 => 6,
            _ => 7,
        };
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
    }
}

#[derive(Debug, Default)]
struct FlowMetricAccumulator {
    packets: FlowAccumulator,
    packet_sizes: PacketSizeAccumulator,
    tcp: Option<TcpFlowAccumulator>,
    first_dns_query: BTreeMap<u16, CaptureTimestamp>,
    dns_response_latency: Option<TcpFlowDuration>,
}

/// Single packet evidence reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketEvidence {
    /// Packet that supports a conclusion.
    pub packet_id: PacketId,
}

/// Optional second packet supporting a conclusion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketPairEvidence {
    /// Primary packet that establishes an observed behavior.
    pub first: PacketEvidence,
    /// Supporting packet that confirms directionality or repetition.
    pub second: Option<PacketEvidence>,
}

/// Confidence level for inferential conclusions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TcpHeuristicConfidence {
    /// Evidence is directly observed and complete in this capture slice.
    Certain,
    /// Evidence is partial and may change with more packets.
    Inferred,
}

/// TCP connection establishment outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TcpConnectionFailureCause {
    /// A reset packet was observed before a full handshake completion.
    Reset,
    /// Repeated SYN attempts were observed without a response.
    RepeatedSyn,
    /// The flow did not include a SYN-ACK sequence.
    OneSidedSyn,
}

/// TCP connection establishment result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpConnectionEstablishment {
    /// Insufficient packet evidence to infer setup behavior.
    NotObserved,
    /// Handshake was observed.
    Established {
        /// First SYN packet.
        syn: PacketEvidence,
        /// ACK packet that observed `SYN+ACK`.
        syn_ack: PacketEvidence,
        /// Final ACK packet that completed the handshake.
        final_ack: PacketEvidence,
        /// Confidence in the inference.
        confidence: TcpHeuristicConfidence,
    },
    /// Initial handshake attempt failed.
    Failed {
        /// Initial packet that started the attempt.
        syn: PacketEvidence,
        /// Packet that demonstrates failure or repeated attempts.
        evidence: PacketPairEvidence,
        /// Cause of failure.
        cause: TcpConnectionFailureCause,
        /// Confidence in the conclusion.
        confidence: TcpHeuristicConfidence,
    },
    /// Handshake did not complete before the capture ended.
    InProgress {
        /// Initial SYN packet.
        syn: PacketEvidence,
        /// Confidence in the conclusion.
        confidence: TcpHeuristicConfidence,
    },
}

/// TCP directionally localized directional indicator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpDirectionalIndicator {
    /// Direction that exhibited the behavior.
    pub direction: FlowDirection,
    /// Packet evidence for the behavior.
    pub packets: PacketPairEvidence,
    /// Confidence in the indicator.
    pub confidence: TcpHeuristicConfidence,
}

/// TCP connection termination conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpConnectionTermination {
    /// No FIN or RST packet was observed.
    NotObserved,
    /// FIN termination seen (possibly one-sided in partial captures).
    Fin {
        /// First observed FIN packet.
        first_fin: PacketEvidence,
        /// Optional second FIN to confirm bidirectional shutdown.
        second_fin: Option<PacketEvidence>,
        /// Confidence in observed completion state.
        confidence: TcpHeuristicConfidence,
    },
    /// RST reset observed.
    Reset {
        /// Packet carrying the reset flag.
        packet: PacketEvidence,
        /// Confidence in observed completion state.
        confidence: TcpHeuristicConfidence,
    },
}

/// Per-flow TCP analysis result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnectionHeuristic {
    /// Stable flow identifier, aligned with `BidirectionalFlow`.
    pub id: FlowId,
    /// Capture interface owning the flow.
    pub interface_id: InterfaceId,
    /// Canonicalized first endpoint.
    pub endpoint_a: FlowEndpoint,
    /// Canonicalized second endpoint.
    pub endpoint_b: FlowEndpoint,
    /// TCP setup result.
    pub establishment: TcpConnectionEstablishment,
    /// TCP teardown result.
    pub termination: TcpConnectionTermination,
    /// Outbound retransmission-like sequence behavior.
    pub retransmission: Option<TcpDirectionalIndicator>,
    /// Duplicate ACK behavior.
    pub duplicate_ack: Option<TcpDirectionalIndicator>,
    /// Out-of-order sequence behavior.
    pub out_of_order: Option<TcpDirectionalIndicator>,
    /// True when conclusions are limited by missing or one-sided observation.
    pub partial_capture: bool,
}

/// Packet-size distribution for a flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSizeDistribution {
    /// Number of packets used by this distribution.
    pub sample_count: u64,
    /// Smallest observed captured packet size.
    pub min_size_bytes: Option<u32>,
    /// Largest observed captured packet size.
    pub max_size_bytes: Option<u32>,
    /// Sum of captured bytes across all sampled packets.
    pub total_size_bytes: u64,
    /// Packet histogram with fixed bins.
    ///
    /// Bins (inclusive) are: 0-63, 64-127, 128-255, 256-511, 512-1023, 1024-2047,
    /// 2048-4095, and 4096+.
    pub buckets: [u64; 8],
}

impl From<PacketSizeAccumulator> for PacketSizeDistribution {
    fn from(accumulator: PacketSizeAccumulator) -> Self {
        Self {
            sample_count: accumulator.sample_count,
            min_size_bytes: accumulator.min,
            max_size_bytes: accumulator.max,
            total_size_bytes: accumulator.total,
            buckets: accumulator.buckets,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSequenceFlags {
    /// TCP SYN flag captured for the packet.
    pub syn: bool,
    /// TCP ACK flag captured for the packet.
    pub ack: bool,
    /// TCP FIN flag captured for the packet.
    pub fin: bool,
    /// TCP RST flag captured for the packet.
    pub rst: bool,
}

/// Message-level timing and metadata for packet-sequence timelines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSequenceMessage {
    /// Packet identifier for the timeline element.
    pub packet_id: PacketId,
    /// Relative timestamp from the flow start, when both timestamps are available.
    pub relative_offset: Option<TcpFlowDuration>,
    /// Absolute packet capture timestamp.
    pub timestamp: Option<CaptureTimestamp>,
    /// Canonical flow direction for this message.
    pub direction: FlowDirection,
    /// Captured packet bytes.
    pub packet_size_bytes: u32,
    /// Optional TCP flags.
    pub tcp_flags: Option<PacketSequenceFlags>,
}

/// Aggregated packet sequence group for timeline zoom.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketSequenceAggregate {
    /// Number of packets in the aggregate.
    pub packet_count: u64,
    /// First packet in the aggregate.
    pub first_packet: PacketId,
    /// Last packet in the aggregate.
    pub last_packet: PacketId,
    /// First packet size bytes.
    pub first_packet_size_bytes: u32,
    /// Last packet size bytes.
    pub last_packet_size_bytes: u32,
    /// Total bytes across the aggregate.
    pub total_packet_bytes: u64,
    /// Relative offset for the first packet in the aggregate.
    pub first_offset: Option<TcpFlowDuration>,
    /// Relative offset for the last packet in the aggregate.
    pub last_offset: Option<TcpFlowDuration>,
    /// Lowest relative offset in the aggregate.
    pub min_offset: Option<TcpFlowDuration>,
    /// Highest relative offset in the aggregate.
    pub max_offset: Option<TcpFlowDuration>,
}

/// Packet-sequence timeline element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketSequenceTimelineEntry {
    /// Single packet message with source evidence.
    Packet(PacketSequenceMessage),
    /// Aggregated packet segment.
    Aggregate(PacketSequenceAggregate),
}

/// Endpoint lane references for a timeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketSequenceLane {
    /// Endpoint represented by this lane.
    pub endpoint: FlowEndpoint,
    /// Message indices for the lane, in timeline order.
    pub message_indices: Box<[usize]>,
}

#[derive(Clone, Debug, Default)]
struct PacketSequenceTimelineAccumulator {
    flow: FlowAccumulator,
    messages: Vec<PacketSequenceMessage>,
}

/// Per-flow traffic and timing summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowMetrics {
    /// Stable zero-based flow identity.
    pub id: FlowId,
    /// Capture interface that owns this flow identity.
    pub interface_id: InterfaceId,
    /// Transport protocol for the flow.
    pub protocol: TransportProtocol,
    /// Canonical endpoint order (`endpoint_a` <= `endpoint_b`).
    pub endpoint_a: FlowEndpoint,
    /// Canonical endpoint order (`endpoint_b` >= `endpoint_a`).
    pub endpoint_b: FlowEndpoint,
    /// Total packet count across both directions.
    pub packets_total: u64,
    /// Total bytes across both directions.
    pub bytes_total: u64,
    /// Packets from `endpoint_a` to `endpoint_b`.
    pub packets_a_to_b: u64,
    /// Packets from `endpoint_b` to `endpoint_a`.
    pub packets_b_to_a: u64,
    /// Captured bytes from `endpoint_a` to `endpoint_b`.
    pub bytes_a_to_b: u64,
    /// Captured bytes from `endpoint_b` to `endpoint_a`.
    pub bytes_b_to_a: u64,
    /// First known packet timestamp for the flow.
    pub first_timestamp: Option<CaptureTimestamp>,
    /// Last known packet timestamp for the flow.
    pub last_timestamp: Option<CaptureTimestamp>,
    /// End-to-end duration between first and last timestamp, when resolvable.
    pub duration: Option<TcpFlowDuration>,
    /// Packet-size summary distribution.
    pub packet_size_distribution: PacketSizeDistribution,
    /// Estimated TCP handshake latency (SYN → final ACK), if inferable.
    pub handshake_latency: Option<TcpFlowDuration>,
    /// DNS request/response latency for the earliest inferable transaction, if any.
    pub dns_response_latency: Option<TcpFlowDuration>,
    /// Time to first post-handshake data packet for TCP flows, when inferable.
    pub time_to_first_data: Option<TcpFlowDuration>,
    /// True when results are likely constrained by a partial viewpoint.
    pub partial_capture: bool,
}

/// Per-flow packet sequence and timeline projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketSequenceTimeline {
    /// Stable flow identity.
    pub id: FlowId,
    /// Capture interface that owns this timeline.
    pub interface_id: InterfaceId,
    /// Transport protocol for the flow.
    pub protocol: TransportProtocol,
    /// Canonical endpoint order (`endpoint_a` <= `endpoint_b`).
    pub endpoint_a: FlowEndpoint,
    /// Canonical endpoint order (`endpoint_b` >= `endpoint_a`).
    pub endpoint_b: FlowEndpoint,
    /// Lane corresponding to `endpoint_a`.
    pub lane_a: PacketSequenceLane,
    /// Lane corresponding to `endpoint_b`.
    pub lane_b: PacketSequenceLane,
    /// First known packet timestamp for the flow.
    pub first_timestamp: Option<CaptureTimestamp>,
    /// Last known packet timestamp for the flow.
    pub last_timestamp: Option<CaptureTimestamp>,
    /// All timeline messages in canonical input order.
    pub messages: Box<[PacketSequenceMessage]>,
}

impl PacketSequenceTimeline {
    /// Returns timeline entries for a time window with optional point budget.
    ///
    /// Time windows are in flow-relative offsets and preserve source packet IDs even
    /// when aggregation is applied.
    pub fn zoom(
        &self,
        start: Option<TcpFlowDuration>,
        end: Option<TcpFlowDuration>,
        max_points: Option<usize>,
    ) -> Box<[PacketSequenceTimelineEntry]> {
        let in_range_indices: Vec<usize> = self
            .messages
            .iter()
            .enumerate()
            .filter_map(|(index, message)| {
                if timeline_message_in_offset_range(message.relative_offset, start, end) {
                    Some(index)
                } else {
                    None
                }
            })
            .collect();

        let Some(max_points) = max_points else {
            return in_range_indices
                .into_iter()
                .map(|index| PacketSequenceTimelineEntry::Packet(self.messages[index]))
                .collect::<Vec<_>>()
                .into_boxed_slice();
        };

        if max_points == 0 {
            return Vec::new().into_boxed_slice();
        }
        if in_range_indices.len() <= max_points {
            return in_range_indices
                .into_iter()
                .map(|index| PacketSequenceTimelineEntry::Packet(self.messages[index]))
                .collect::<Vec<_>>()
                .into_boxed_slice();
        }

        let bucket_size = in_range_indices.len().div_ceil(max_points);
        let mut output = Vec::new();
        for chunk in in_range_indices.chunks(bucket_size) {
            let first = self.messages[chunk[0]];
            let last = self.messages[chunk[chunk.len() - 1]];
            let mut total_packet_bytes = 0_u64;
            let mut min_offset = first.relative_offset;
            let mut max_offset = first.relative_offset;
            for &index in chunk {
                let message = self.messages[index];
                total_packet_bytes =
                    total_packet_bytes.saturating_add(u64::from(message.packet_size_bytes));
                match (message.relative_offset, min_offset) {
                    (Some(candidate), Some(current)) if candidate.ticks < current.ticks => {
                        min_offset = Some(candidate)
                    }
                    (Some(_), None) => min_offset = message.relative_offset,
                    (None, None) | (None, Some(_)) | (Some(_), Some(_)) => {}
                }
                match (message.relative_offset, max_offset) {
                    (Some(candidate), Some(current)) if candidate.ticks > current.ticks => {
                        max_offset = Some(candidate)
                    }
                    (Some(_), None) => max_offset = message.relative_offset,
                    (None, None) | (None, Some(_)) | (Some(_), Some(_)) => {}
                }
            }
            output.push(PacketSequenceTimelineEntry::Aggregate(
                PacketSequenceAggregate {
                    packet_count: chunk.len() as u64,
                    first_packet: first.packet_id,
                    last_packet: last.packet_id,
                    first_packet_size_bytes: first.packet_size_bytes,
                    last_packet_size_bytes: last.packet_size_bytes,
                    total_packet_bytes,
                    first_offset: first.relative_offset,
                    last_offset: last.relative_offset,
                    min_offset,
                    max_offset,
                },
            ));
        }

        output.into_boxed_slice()
    }
}

/// One deterministic bidirectional flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BidirectionalFlow {
    /// Stable zero-based flow identity.
    pub id: FlowId,
    /// Capture interface that owns this flow identity.
    pub interface_id: InterfaceId,
    /// Transport protocol for the flow.
    pub protocol: TransportProtocol,
    /// Canonical endpoint order (`endpoint_a` <= `endpoint_b`).
    pub endpoint_a: FlowEndpoint,
    /// Canonical endpoint order (`endpoint_b` >= `endpoint_a`).
    pub endpoint_b: FlowEndpoint,
    /// Packets from `endpoint_a` to `endpoint_b`.
    pub packets_a_to_b: u64,
    /// Packets from `endpoint_b` to `endpoint_a`.
    pub packets_b_to_a: u64,
    /// Captured bytes from `endpoint_a` to `endpoint_b`.
    pub bytes_a_to_b: u64,
    /// Captured bytes from `endpoint_b` to `endpoint_a`.
    pub bytes_b_to_a: u64,
    /// First known packet timestamp for the flow.
    pub first_timestamp: Option<CaptureTimestamp>,
    /// Last known packet timestamp for the flow.
    pub last_timestamp: Option<CaptureTimestamp>,
}

impl BidirectionalFlow {
    /// Total packets across both flow directions.
    #[must_use]
    pub const fn packets_total(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    /// Total captured bytes across both flow directions.
    #[must_use]
    pub const fn bytes_total(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }
}

/// Flow reconstruction error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowReconstructionError {
    /// A canonical dataset invariant was not met during flow reconstruction.
    DatasetInvariant,
}

impl CaptureDataset {
    /// Reconstructs bidirectional TCP and UDP flows from decoded fields.
    ///
    /// Deterministic ordering is preserved by sorting on `interface_id`,
    /// transport protocol, and canonicalized endpoints.
    ///
    /// Time complexity is O(P * L + P log F), where P is packet count, L is
    /// average layer/field traversal per packet, and F is active flow count.
    pub fn reconstruct_bidirectional_flows(
        &self,
    ) -> Result<Box<[BidirectionalFlow]>, FlowReconstructionError> {
        let mut flows: BTreeMap<FlowKey, FlowAccumulator> = BTreeMap::new();

        for packet in self.packets() {
            let Some((key, direction)) = packet_flow_key(self, packet)? else {
                continue;
            };
            let accumulator = flows.entry(key).or_default();
            apply_packet_to_flow(accumulator, packet, direction);
        }

        let mut output = Vec::new();
        for (index, (key, accumulator)) in flows.into_iter().enumerate() {
            let id = FlowId(
                u32::try_from(index).map_err(|_| FlowReconstructionError::DatasetInvariant)?,
            );
            output.push(BidirectionalFlow {
                id,
                interface_id: key.interface_id,
                protocol: key.protocol,
                endpoint_a: key.endpoint_a,
                endpoint_b: key.endpoint_b,
                packets_a_to_b: accumulator.packets_from_a,
                packets_b_to_a: accumulator.packets_from_b,
                bytes_a_to_b: accumulator.bytes_from_a,
                bytes_b_to_a: accumulator.bytes_from_b,
                first_timestamp: accumulator.first_timestamp,
                last_timestamp: accumulator.last_timestamp,
            });
        }
        Ok(output.into_boxed_slice())
    }

    /// Reconstructs per-flow TCP connection-state hypotheses from decoded fields.
    ///
    /// Deterministic ordering follows the canonical flow identity used for bidirectional
    /// flow reconstruction.
    ///
    /// Time complexity is O(P * L + P log F), where P is packet count, L is average
    /// layer/field traversal per packet, and F is active TCP flow count.
    pub fn reconstruct_tcp_connection_states(
        &self,
    ) -> Result<Box<[TcpConnectionHeuristic]>, FlowReconstructionError> {
        let mut flows: BTreeMap<FlowKey, TcpFlowAccumulator> = BTreeMap::new();

        for packet in self.packets() {
            let Some((key, direction)) = packet_flow_key(self, packet)? else {
                continue;
            };
            if key.protocol != TransportProtocol::Tcp {
                continue;
            }
            let tcp_packet = read_tcp_packet_data(self, packet)?;
            let accumulator = flows.entry(key).or_default();
            apply_tcp_packet_to_flow(accumulator, packet, direction, tcp_packet);
        }

        let mut output = Vec::new();
        for (index, (key, accumulator)) in flows.into_iter().enumerate() {
            let id = FlowId(
                u32::try_from(index).map_err(|_| FlowReconstructionError::DatasetInvariant)?,
            );
            output.push(TcpConnectionHeuristic {
                id,
                interface_id: key.interface_id,
                endpoint_a: key.endpoint_a,
                endpoint_b: key.endpoint_b,
                establishment: classify_tcp_connection_establishment(&accumulator),
                termination: classify_tcp_connection_termination(&accumulator),
                retransmission: classify_tcp_retransmission(&accumulator),
                duplicate_ack: classify_tcp_duplicate_ack(&accumulator),
                out_of_order: classify_tcp_out_of_order(&accumulator),
                partial_capture: classify_tcp_is_partial_capture(&accumulator),
            });
        }
        Ok(output.into_boxed_slice())
    }

    /// Reconstructs per-flow traffic and timing metrics from decoded fields.
    ///
    /// The returned list is deterministic and aligns with the same canonical flow key
    /// ordering used by bidirectional flow reconstruction.
    pub fn reconstruct_flow_metrics(&self) -> Result<Box<[FlowMetrics]>, FlowReconstructionError> {
        let mut flows: BTreeMap<FlowKey, FlowMetricAccumulator> = BTreeMap::new();

        for packet in self.packets() {
            let Some((key, direction)) = packet_flow_key(self, packet)? else {
                continue;
            };

            let tcp = read_tcp_packet_data(self, packet)?;
            let dns = read_dns_packet_data(self, packet)?;
            let accumulator = flows.entry(key).or_default();
            apply_packet_to_metrics(accumulator, packet, direction, tcp, dns);
        }

        let mut output = Vec::new();
        for (index, (key, accumulator)) in flows.into_iter().enumerate() {
            let id = FlowId(
                u32::try_from(index).map_err(|_| FlowReconstructionError::DatasetInvariant)?,
            );
            let duration = match (
                accumulator.packets.first_timestamp,
                accumulator.packets.last_timestamp,
            ) {
                (Some(first), Some(last)) => duration_from_timestamps(first, last),
                _ => None,
            };
            let handshake_latency = match &accumulator.tcp {
                Some(tcp) => tcp
                    .first_syn_timestamp
                    .and_then(|start| {
                        tcp.established_ack_timestamp
                            .and_then(|end| duration_from_timestamps(start, end))
                    })
                    .filter(|value| value.is_nonzero()),
                None => None,
            };
            let time_to_first_data = match &accumulator.tcp {
                Some(tcp) => tcp
                    .established_ack_timestamp
                    .and_then(|start| {
                        tcp.first_data_timestamp
                            .and_then(|end| duration_from_timestamps(start, end))
                    })
                    .filter(|value| value.is_nonzero()),
                None => None,
            };
            let partial_capture = accumulator
                .tcp
                .as_ref()
                .is_none_or(|tcp| classify_tcp_is_partial_capture(tcp))
                || match key.protocol {
                    TransportProtocol::Tcp | TransportProtocol::Udp => {
                        accumulator.packets.packets_from_a == 0
                            || accumulator.packets.packets_from_b == 0
                    }
                };

            output.push(FlowMetrics {
                id,
                interface_id: key.interface_id,
                protocol: key.protocol,
                endpoint_a: key.endpoint_a,
                endpoint_b: key.endpoint_b,
                packets_total: accumulator.packets.packets_total(),
                bytes_total: accumulator.packets.bytes_total(),
                packets_a_to_b: accumulator.packets.packets_from_a,
                packets_b_to_a: accumulator.packets.packets_from_b,
                bytes_a_to_b: accumulator.packets.bytes_from_a,
                bytes_b_to_a: accumulator.packets.bytes_from_b,
                first_timestamp: accumulator.packets.first_timestamp,
                last_timestamp: accumulator.packets.last_timestamp,
                duration,
                packet_size_distribution: PacketSizeDistribution::from(accumulator.packet_sizes),
                handshake_latency,
                dns_response_latency: accumulator.dns_response_latency,
                time_to_first_data,
                partial_capture,
            });
        }
        Ok(output.into_boxed_slice())
    }

    /// Reconstructs per-flow packet-sequence timelines from decoded fields.
    ///
    /// Output uses the same canonical flow key ordering used for bidirectional flow
    /// reconstruction.
    pub fn reconstruct_packet_sequence_timelines(
        &self,
    ) -> Result<Box<[PacketSequenceTimeline]>, FlowReconstructionError> {
        let mut flows: BTreeMap<FlowKey, PacketSequenceTimelineAccumulator> = BTreeMap::new();

        for packet in self.packets() {
            let Some((key, direction)) = packet_flow_key(self, packet)? else {
                continue;
            };
            let tcp = read_tcp_packet_data(self, packet)?;
            let accumulator = flows.entry(key).or_default();
            apply_packet_to_timeline(accumulator, packet, direction, tcp);
        }

        let mut output = Vec::new();
        for (index, (key, mut accumulator)) in flows.into_iter().enumerate() {
            let id = FlowId(
                u32::try_from(index).map_err(|_| FlowReconstructionError::DatasetInvariant)?,
            );
            let first_timestamp = accumulator.flow.first_timestamp;
            let last_timestamp = accumulator.flow.last_timestamp;

            if let Some(flow_start) = first_timestamp {
                for message in &mut accumulator.messages {
                    if let Some(timestamp) = message.timestamp {
                        message.relative_offset = duration_from_timestamps(flow_start, timestamp);
                    }
                }
            }

            let mut lane_a_indices = Vec::new();
            let mut lane_b_indices = Vec::new();
            for (index, message) in accumulator.messages.iter().enumerate() {
                match message.direction {
                    FlowDirection::AToB | FlowDirection::Unknown => lane_a_indices.push(index),
                    FlowDirection::BToA => lane_b_indices.push(index),
                }
            }

            output.push(PacketSequenceTimeline {
                id,
                interface_id: key.interface_id,
                protocol: key.protocol,
                endpoint_a: key.endpoint_a,
                endpoint_b: key.endpoint_b,
                lane_a: PacketSequenceLane {
                    endpoint: key.endpoint_a,
                    message_indices: lane_a_indices.into_boxed_slice(),
                },
                lane_b: PacketSequenceLane {
                    endpoint: key.endpoint_b,
                    message_indices: lane_b_indices.into_boxed_slice(),
                },
                first_timestamp,
                last_timestamp,
                messages: accumulator.messages.into_boxed_slice(),
            });
        }

        Ok(output.into_boxed_slice())
    }
}

fn apply_packet_to_flow(
    accumulator: &mut FlowAccumulator,
    packet: &PacketRecord,
    direction: FlowDirection,
) {
    let bytes = u64::from(packet.captured_length);
    match direction {
        FlowDirection::AToB | FlowDirection::Unknown => {
            accumulator.packets_from_a = accumulator.packets_from_a.saturating_add(1);
            accumulator.bytes_from_a = accumulator.bytes_from_a.saturating_add(bytes);
        }
        FlowDirection::BToA => {
            accumulator.packets_from_b = accumulator.packets_from_b.saturating_add(1);
            accumulator.bytes_from_b = accumulator.bytes_from_b.saturating_add(bytes);
        }
    }

    let Some(timestamp) = packet.timestamp else {
        return;
    };
    match accumulator.first_timestamp {
        None => accumulator.first_timestamp = Some(timestamp),
        Some(existing) => {
            if timestamp.cmp_instant(existing).is_lt() {
                accumulator.first_timestamp = Some(timestamp);
            }
        }
    }
    match accumulator.last_timestamp {
        None => accumulator.last_timestamp = Some(timestamp),
        Some(existing) => {
            if timestamp.cmp_instant(existing).is_gt() {
                accumulator.last_timestamp = Some(timestamp);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TcpPacketData {
    is_tcp: bool,
    sequence_number: Option<u32>,
    acknowledgment_number: Option<u32>,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct DnsPacketData {
    transaction_id: Option<u16>,
    is_response: Option<bool>,
    question_count: Option<u16>,
    answer_count: Option<u16>,
}

fn read_tcp_packet_data(
    dataset: &CaptureDataset,
    packet: &PacketRecord,
) -> Result<TcpPacketData, FlowReconstructionError> {
    let mut data = TcpPacketData::default();
    let mut saw_tcp_layer = false;
    let layer_start = usize::try_from(packet.layers.start())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layer_end = usize::try_from(packet.layers.end())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layers = dataset
        .layers()
        .get(layer_start..layer_end)
        .ok_or(FlowReconstructionError::DatasetInvariant)?;

    for layer in layers {
        let protocol = dataset
            .string(layer.protocol)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;
        if protocol != "tcp" {
            continue;
        }
        saw_tcp_layer = true;
        data.is_tcp = true;
        let Some(root) = layer.root_field else {
            continue;
        };
        let mut stack = Vec::new();
        stack.push(root);
        while let Some(field_id) = stack.pop() {
            let field = dataset
                .fields()
                .get(field_id.0 as usize)
                .ok_or(FlowReconstructionError::DatasetInvariant)?;
            let field_name = dataset
                .string(field.name)
                .ok_or(FlowReconstructionError::DatasetInvariant)?;
            match field_name {
                "sequence_number" => {
                    if let FieldValue::Unsigned(value) = field.value {
                        data.sequence_number = u32::try_from(value).ok();
                    }
                }
                "acknowledgment_number" => {
                    if let FieldValue::Unsigned(value) = field.value {
                        data.acknowledgment_number = u32::try_from(value).ok();
                    }
                }
                "syn" => {
                    if let FieldValue::Boolean(value) = field.value {
                        data.syn = value;
                    }
                }
                "ack" => {
                    if let FieldValue::Boolean(value) = field.value {
                        data.ack = value;
                    }
                }
                "fin" => {
                    if let FieldValue::Boolean(value) = field.value {
                        data.fin = value;
                    }
                }
                "rst" => {
                    if let FieldValue::Boolean(value) = field.value {
                        data.rst = value;
                    }
                }
                _ => {}
            }

            let children = field_children(dataset, field.children)?;
            for child in children.iter().rev() {
                stack.push(*child);
            }
        }
    }

    if !saw_tcp_layer {
        return Ok(TcpPacketData::default());
    }
    Ok(data)
}

fn read_dns_packet_data(
    dataset: &CaptureDataset,
    packet: &PacketRecord,
) -> Result<DnsPacketData, FlowReconstructionError> {
    let mut data = DnsPacketData::default();
    let mut saw_dns_layer = false;
    let layer_start = usize::try_from(packet.layers.start())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layer_end = usize::try_from(packet.layers.end())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layers = dataset
        .layers()
        .get(layer_start..layer_end)
        .ok_or(FlowReconstructionError::DatasetInvariant)?;

    for layer in layers {
        let protocol = dataset
            .string(layer.protocol)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;
        if protocol != "dns" {
            continue;
        }
        saw_dns_layer = true;
        let Some(root) = layer.root_field else {
            continue;
        };
        let mut stack = Vec::new();
        stack.push(root);
        while let Some(field_id) = stack.pop() {
            let field = dataset
                .fields()
                .get(field_id.0 as usize)
                .ok_or(FlowReconstructionError::DatasetInvariant)?;
            let field_name = dataset
                .string(field.name)
                .ok_or(FlowReconstructionError::DatasetInvariant)?;
            match field_name {
                "transaction_id" => {
                    if let FieldValue::Unsigned(value) = field.value {
                        data.transaction_id = u16::try_from(value).ok();
                    }
                }
                "is_response" => {
                    if let FieldValue::Boolean(value) = field.value {
                        data.is_response = Some(value);
                    }
                }
                "question_count" => {
                    if let FieldValue::Unsigned(value) = field.value {
                        data.question_count = u16::try_from(value).ok();
                    }
                }
                "answer_count" => {
                    if let FieldValue::Unsigned(value) = field.value {
                        data.answer_count = u16::try_from(value).ok();
                    }
                }
                _ => {}
            }

            let children = field_children(dataset, field.children)?;
            for child in children.iter().rev() {
                stack.push(*child);
            }
        }
    }

    if !saw_dns_layer {
        return Ok(DnsPacketData::default());
    }
    Ok(data)
}

fn apply_packet_to_timeline(
    accumulator: &mut PacketSequenceTimelineAccumulator,
    packet: &PacketRecord,
    direction: FlowDirection,
    tcp: TcpPacketData,
) {
    apply_packet_to_flow(&mut accumulator.flow, packet, direction);
    let tcp_flags = if tcp.is_tcp {
        Some(PacketSequenceFlags {
            syn: tcp.syn,
            ack: tcp.ack,
            fin: tcp.fin,
            rst: tcp.rst,
        })
    } else {
        None
    };
    accumulator.messages.push(PacketSequenceMessage {
        packet_id: packet.id,
        relative_offset: None,
        timestamp: packet.timestamp,
        direction,
        packet_size_bytes: packet.captured_length,
        tcp_flags,
    });
}

fn apply_tcp_packet_to_flow(
    accumulator: &mut TcpFlowAccumulator,
    packet: &PacketRecord,
    direction: FlowDirection,
    tcp: TcpPacketData,
) {
    let evidence = PacketEvidence {
        packet_id: packet.id,
    };
    apply_packet_to_flow(&mut accumulator.packets, packet, direction);
    let timestamp = packet.timestamp;

    if let FlowDirection::AToB | FlowDirection::BToA = direction {
        let directional_state = match direction {
            FlowDirection::AToB => &mut accumulator.direction_a,
            FlowDirection::BToA => &mut accumulator.direction_b,
            _ => unreachable!(),
        };

        if let Some(sequence) = tcp.sequence_number {
            if let (Some(last_seq), Some(previous_packet)) = (
                directional_state.last_sequence,
                directional_state.last_sequence_packet,
            ) {
                if last_seq == sequence && accumulator.retransmission.is_none() {
                    accumulator.retransmission = Some(TcpDirectionalIndicator {
                        direction,
                        confidence: TcpHeuristicConfidence::Inferred,
                        packets: PacketPairEvidence {
                            first: previous_packet,
                            second: Some(evidence),
                        },
                    });
                } else if sequence < last_seq && accumulator.out_of_order.is_none() {
                    accumulator.out_of_order = Some(TcpDirectionalIndicator {
                        direction,
                        confidence: TcpHeuristicConfidence::Inferred,
                        packets: PacketPairEvidence {
                            first: previous_packet,
                            second: Some(evidence),
                        },
                    });
                }
            }
            directional_state.last_sequence = Some(sequence);
            directional_state.last_sequence_packet = Some(evidence);
        }

        if let Some(ack) = tcp.acknowledgment_number {
            if let (Some(last_ack), Some(previous_packet)) = (
                directional_state.last_ack,
                directional_state.last_ack_packet,
            ) {
                if last_ack == ack && tcp.ack && accumulator.duplicate_ack.is_none() {
                    accumulator.duplicate_ack = Some(TcpDirectionalIndicator {
                        direction,
                        confidence: TcpHeuristicConfidence::Inferred,
                        packets: PacketPairEvidence {
                            first: previous_packet,
                            second: Some(evidence),
                        },
                    });
                }
            }
            directional_state.last_ack = Some(ack);
            directional_state.last_ack_packet = Some(evidence);
        }
    }

    if tcp.syn && !tcp.ack {
        if accumulator.first_syn.is_none() {
            accumulator.first_syn = Some(evidence);
            accumulator.first_syn_direction = Some(direction);
            if let Some(timestamp) = timestamp {
                accumulator.first_syn_timestamp = Some(timestamp);
            }
        } else if accumulator.first_syn_direction == Some(direction)
            && accumulator.repeated_syn.is_none()
        {
            accumulator.repeated_syn = Some(PacketPairEvidence {
                first: accumulator.first_syn.unwrap(),
                second: Some(evidence),
            });
        }
    }

    if let (Some(_syn), Some(syn_direction)) =
        (accumulator.first_syn, accumulator.first_syn_direction)
    {
        if tcp.syn && tcp.ack && direction != syn_direction && accumulator.syn_ack.is_none() {
            accumulator.syn_ack = Some(evidence);
        }
        if tcp.ack
            && direction == syn_direction
            && accumulator.syn_ack.is_some()
            && accumulator.established_ack.is_none()
        {
            accumulator.established_ack = Some(evidence);
            if let Some(timestamp) = timestamp {
                accumulator.established_ack_timestamp = Some(timestamp);
            }
        }
    }

    if tcp.sequence_number.is_some()
        && !tcp.syn
        && !tcp.fin
        && !tcp.rst
        && !tcp.ack
        && accumulator.first_data_timestamp.is_none()
        && let Some(timestamp) = timestamp
    {
        accumulator.first_data_timestamp = Some(timestamp);
    }

    if tcp.rst {
        accumulator.reset = Some(evidence);
    }

    if tcp.fin {
        if accumulator.fin_first.is_none() {
            accumulator.fin_first = Some((direction, evidence));
        } else if accumulator.fin_last.is_none() {
            accumulator.fin_last = Some((direction, evidence));
        }
    }
}

fn apply_packet_to_metrics(
    accumulator: &mut FlowMetricAccumulator,
    packet: &PacketRecord,
    direction: FlowDirection,
    tcp: TcpPacketData,
    dns: DnsPacketData,
) {
    apply_packet_to_flow(&mut accumulator.packets, packet, direction);
    accumulator.packet_sizes.record(packet.captured_length);

    if tcp.is_tcp {
        let tcp_accumulator = accumulator
            .tcp
            .get_or_insert_with(TcpFlowAccumulator::default);
        apply_tcp_packet_to_flow(tcp_accumulator, packet, direction, tcp);
    }

    let Some(packet_timestamp) = packet.timestamp else {
        return;
    };
    let Some(transaction_id) = dns.transaction_id else {
        return;
    };

    let is_response = dns.is_response.unwrap_or(false);
    if is_response {
        if let Some(query_timestamp) = accumulator.first_dns_query.remove(&transaction_id) {
            if let Some(dns_response_latency) =
                duration_from_timestamps(query_timestamp, packet_timestamp)
            {
                match accumulator.dns_response_latency {
                    None => accumulator.dns_response_latency = Some(dns_response_latency),
                    Some(existing) if dns_response_latency.ticks < existing.ticks => {
                        accumulator.dns_response_latency = Some(dns_response_latency);
                    }
                    Some(_) => {}
                }
            }
        }
        return;
    }

    if dns
        .question_count
        .is_none_or(|question_count| question_count > 0)
    {
        accumulator
            .first_dns_query
            .entry(transaction_id)
            .or_insert(packet_timestamp);
    }
}

fn classify_tcp_connection_establishment(
    accumulator: &TcpFlowAccumulator,
) -> TcpConnectionEstablishment {
    if let (Some(syn), Some(syn_ack), Some(ack)) = (
        accumulator.first_syn,
        accumulator.syn_ack,
        accumulator.established_ack,
    ) {
        return TcpConnectionEstablishment::Established {
            syn,
            syn_ack,
            final_ack: ack,
            confidence: TcpHeuristicConfidence::Certain,
        };
    }

    if let (Some(syn), Some(reset)) = (accumulator.first_syn, accumulator.reset) {
        return TcpConnectionEstablishment::Failed {
            syn,
            evidence: PacketPairEvidence {
                first: syn,
                second: Some(reset),
            },
            cause: TcpConnectionFailureCause::Reset,
            confidence: TcpHeuristicConfidence::Certain,
        };
    }

    if let (Some(syn), Some(repeated_syn)) = (accumulator.first_syn, accumulator.repeated_syn) {
        return TcpConnectionEstablishment::Failed {
            syn,
            evidence: repeated_syn,
            cause: TcpConnectionFailureCause::RepeatedSyn,
            confidence: TcpHeuristicConfidence::Inferred,
        };
    }

    if let Some(syn) = accumulator.first_syn {
        return TcpConnectionEstablishment::InProgress {
            syn,
            confidence: TcpHeuristicConfidence::Inferred,
        };
    }

    TcpConnectionEstablishment::NotObserved
}

fn classify_tcp_connection_termination(
    accumulator: &TcpFlowAccumulator,
) -> TcpConnectionTermination {
    if let Some(reset) = accumulator.reset {
        return TcpConnectionTermination::Reset {
            packet: reset,
            confidence: TcpHeuristicConfidence::Certain,
        };
    }

    if let Some((_, first_fin)) = accumulator.fin_first {
        let second_fin = accumulator.fin_last.map(|(_, packet)| packet);
        let confidence = if second_fin.is_some() {
            TcpHeuristicConfidence::Certain
        } else {
            TcpHeuristicConfidence::Inferred
        };
        return TcpConnectionTermination::Fin {
            first_fin,
            second_fin,
            confidence,
        };
    }

    TcpConnectionTermination::NotObserved
}

fn classify_tcp_retransmission(
    accumulator: &TcpFlowAccumulator,
) -> Option<TcpDirectionalIndicator> {
    accumulator.retransmission
}

fn classify_tcp_duplicate_ack(accumulator: &TcpFlowAccumulator) -> Option<TcpDirectionalIndicator> {
    accumulator.duplicate_ack
}

fn classify_tcp_out_of_order(accumulator: &TcpFlowAccumulator) -> Option<TcpDirectionalIndicator> {
    accumulator.out_of_order
}

fn classify_tcp_is_partial_capture(accumulator: &TcpFlowAccumulator) -> bool {
    if accumulator.packets.packets_from_a == 0 || accumulator.packets.packets_from_b == 0 {
        return true;
    }
    match classify_tcp_connection_establishment(accumulator) {
        TcpConnectionEstablishment::Established { confidence, .. }
            if confidence == TcpHeuristicConfidence::Certain => {}
        _ => return true,
    }
    if let TcpConnectionTermination::NotObserved = classify_tcp_connection_termination(accumulator)
    {
        return true;
    }
    false
}

fn duration_from_timestamps(
    start: CaptureTimestamp,
    end: CaptureTimestamp,
) -> Option<TcpFlowDuration> {
    if start.resolution() != end.resolution() {
        return None;
    }
    if end.cmp_instant(start).is_lt() {
        return None;
    }
    let ticks_per_second = start.resolution().ticks_per_second()?;

    let mut seconds_delta = end.seconds().checked_sub(start.seconds())?;
    let mut fraction_delta = end.fraction().checked_sub(start.fraction())?;
    if end.fraction() < start.fraction() {
        seconds_delta = seconds_delta.checked_sub(1)?;
        fraction_delta = fraction_delta.checked_add(ticks_per_second)?;
    }

    let total_ticks = u64::try_from(seconds_delta)
        .ok()?
        .checked_mul(ticks_per_second)?
        .checked_add(fraction_delta)?;
    Some(TcpFlowDuration {
        ticks: total_ticks,
        resolution: start.resolution(),
    })
}

fn timeline_message_in_offset_range(
    offset: Option<TcpFlowDuration>,
    start: Option<TcpFlowDuration>,
    end: Option<TcpFlowDuration>,
) -> bool {
    let Some(offset) = offset else {
        return true;
    };

    if let Some(start) = start {
        if offset.resolution != start.resolution || offset.ticks < start.ticks {
            return false;
        }
    }

    if let Some(end) = end {
        if offset.resolution != end.resolution || offset.ticks > end.ticks {
            return false;
        }
    }

    true
}

fn packet_flow_key(
    dataset: &CaptureDataset,
    packet: &PacketRecord,
) -> Result<Option<(FlowKey, FlowDirection)>, FlowReconstructionError> {
    let mut network: Option<(IpAddress, IpAddress)> = None;
    let mut transport: Option<(TransportProtocol, u16, u16)> = None;

    let layer_start = usize::try_from(packet.layers.start())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layer_end = usize::try_from(packet.layers.end())
        .map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let layers = dataset
        .layers()
        .get(layer_start..layer_end)
        .ok_or(FlowReconstructionError::DatasetInvariant)?;

    for layer in layers {
        let protocol = dataset
            .string(layer.protocol)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;
        match protocol {
            "ipv4" => {
                if let Some(network_fields) = read_ip_endpoints(dataset, layer, false)? {
                    network = Some(network_fields);
                }
            }
            "ipv6" => {
                if let Some(network_fields) = read_ip_endpoints(dataset, layer, true)? {
                    network = Some(network_fields);
                }
            }
            "tcp" => {
                if let Some((source_port, destination_port)) = read_transport_ports(dataset, layer)?
                {
                    transport = Some((TransportProtocol::Tcp, source_port, destination_port));
                }
            }
            "udp" => {
                if let Some((source_port, destination_port)) = read_transport_ports(dataset, layer)?
                {
                    transport = Some((TransportProtocol::Udp, source_port, destination_port));
                }
            }
            _ => {}
        }
    }

    let Some((source_address, destination_address)) = network else {
        return Ok(None);
    };
    let Some((protocol, source_port, destination_port)) = transport else {
        return Ok(None);
    };
    let source = FlowEndpoint {
        address: source_address,
        port: source_port,
    };
    let destination = FlowEndpoint {
        address: destination_address,
        port: destination_port,
    };

    let (endpoint_a, endpoint_b, direction) = if source < destination {
        (source, destination, FlowDirection::AToB)
    } else if destination < source {
        (destination, source, FlowDirection::BToA)
    } else {
        (source, destination, FlowDirection::Unknown)
    };
    Ok(Some((
        FlowKey {
            interface_id: packet.interface_id,
            protocol,
            endpoint_a,
            endpoint_b,
        },
        direction,
    )))
}

fn read_ip_endpoints(
    dataset: &CaptureDataset,
    layer: &LayerFact,
    is_ipv6: bool,
) -> Result<Option<(IpAddress, IpAddress)>, FlowReconstructionError> {
    let Some(root) = layer.root_field else {
        return Ok(None);
    };
    let mut source = None;
    let mut destination = None;
    let mut stack: Vec<FieldId> = Vec::new();
    stack.push(root);

    while let Some(field_id) = stack.pop() {
        let field = dataset
            .fields()
            .get(field_id.0 as usize)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;
        let field_name = dataset
            .string(field.name)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;

        match field_name {
            "source_address" => {
                if source.is_none() {
                    source = read_ip_address(dataset, field.value, is_ipv6)?;
                }
            }
            "destination_address" => {
                if destination.is_none() {
                    destination = read_ip_address(dataset, field.value, is_ipv6)?;
                }
            }
            _ => {}
        }

        if source.is_some() && destination.is_some() {
            break;
        }
        let children = field_children(dataset, field.children)?;
        for child in children.iter().rev() {
            stack.push(*child);
        }
    }

    match (source, destination) {
        (Some(source), Some(destination)) => Ok(Some((source, destination))),
        _ => Ok(None),
    }
}

fn read_transport_ports(
    dataset: &CaptureDataset,
    layer: &LayerFact,
) -> Result<Option<(u16, u16)>, FlowReconstructionError> {
    let Some(root) = layer.root_field else {
        return Ok(None);
    };
    let mut source_port = None;
    let mut destination_port = None;
    let mut stack: Vec<FieldId> = Vec::new();
    stack.push(root);

    while let Some(field_id) = stack.pop() {
        let field = dataset
            .fields()
            .get(field_id.0 as usize)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;
        let field_name = dataset
            .string(field.name)
            .ok_or(FlowReconstructionError::DatasetInvariant)?;

        match field_name {
            "source_port" => {
                if source_port.is_none()
                    && let FieldValue::Unsigned(value) = field.value
                {
                    source_port = u16::try_from(value).ok();
                }
            }
            "destination_port" => {
                if destination_port.is_none()
                    && let FieldValue::Unsigned(value) = field.value
                {
                    destination_port = u16::try_from(value).ok();
                }
            }
            _ => {}
        }

        if source_port.is_some() && destination_port.is_some() {
            break;
        }
        let children = field_children(dataset, field.children)?;
        for child in children.iter().rev() {
            stack.push(*child);
        }
    }

    match (source_port, destination_port) {
        (Some(source_port), Some(destination_port)) => Ok(Some((source_port, destination_port))),
        _ => Ok(None),
    }
}

fn read_ip_address(
    dataset: &CaptureDataset,
    value: FieldValue,
    is_ipv6: bool,
) -> Result<Option<IpAddress>, FlowReconstructionError> {
    let FieldValue::Bytes(range) = value else {
        return Ok(None);
    };
    let bytes = read_range_bytes(dataset, range)?;
    match (is_ipv6, bytes.len()) {
        (false, 4) => {
            let mut addr = [0_u8; 4];
            addr.copy_from_slice(bytes);
            Ok(Some(IpAddress::V4(addr)))
        }
        (true, 16) => {
            let mut addr = [0_u8; 16];
            addr.copy_from_slice(bytes);
            Ok(Some(IpAddress::V6(addr)))
        }
        _ => Ok(None),
    }
}

fn read_range_bytes<'a>(
    dataset: &'a CaptureDataset,
    range: ByteRange,
) -> Result<&'a [u8], FlowReconstructionError> {
    let start =
        usize::try_from(range.start()).map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let end =
        usize::try_from(range.end()).map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    dataset
        .bytes()
        .get(start..end)
        .ok_or(FlowReconstructionError::DatasetInvariant)
}

fn field_children(
    dataset: &CaptureDataset,
    range: IndexRange,
) -> Result<&[FieldId], FlowReconstructionError> {
    let start =
        usize::try_from(range.start()).map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    let end =
        usize::try_from(range.end()).map_err(|_| FlowReconstructionError::DatasetInvariant)?;
    dataset
        .field_children()
        .get(start..end)
        .ok_or(FlowReconstructionError::DatasetInvariant)
}

#[cfg(test)]
mod tests {
    use crate::model::CaptureDatasetParts;
    use crate::{
        ByteOrder, CaptureFormat, CaptureMetadata, CaptureTimestamp, DecodedField, FieldId,
        InterfaceId, InterfaceMetadata, LayerFact, LinkType, PacketId, PacketRecord, StringId,
        TimestampResolution,
    };

    use crate::{ByteRange, CaptureDataset, FieldValue, IndexRange};

    use super::*;

    #[derive(Clone, Copy)]
    enum NetworkSpec {
        V4([u8; 4], [u8; 4]),
        V6([u8; 16], [u8; 16]),
    }

    #[derive(Clone, Copy)]
    enum TransportSpec {
        Tcp(u16, u16),
        Udp(u16, u16),
    }

    #[derive(Clone, Copy)]
    struct TcpPacketSpec {
        sequence_number: Option<u32>,
        acknowledgment_number: Option<u32>,
        syn: bool,
        ack: bool,
        fin: bool,
        rst: bool,
    }

    #[derive(Clone, Copy)]
    struct DnsPacketSpec {
        transaction_id: u16,
        is_response: bool,
        question_count: u16,
        answer_count: u16,
    }

    #[derive(Clone, Copy)]
    struct PacketSpecWithDns {
        interface_id: InterfaceId,
        timestamp: Option<CaptureTimestamp>,
        network: NetworkSpec,
        transport: Option<TransportSpec>,
        tcp: Option<TcpPacketSpec>,
        dns: Option<DnsPacketSpec>,
        captured_length: u32,
    }

    struct PacketSpec {
        interface_id: InterfaceId,
        timestamp: Option<CaptureTimestamp>,
        network: NetworkSpec,
        transport: Option<TransportSpec>,
        tcp: Option<TcpPacketSpec>,
    }

    #[derive(Clone, Copy)]
    struct StringIds {
        ipv4: StringId,
        ipv6: StringId,
        tcp: StringId,
        udp: StringId,
        source_address: StringId,
        destination_address: StringId,
        source_port: StringId,
        destination_port: StringId,
        sequence_number: StringId,
        acknowledgment_number: StringId,
        syn: StringId,
        ack: StringId,
        fin: StringId,
        rst: StringId,
    }

    fn timestamp(seconds: i64, fraction: u64) -> CaptureTimestamp {
        CaptureTimestamp::new(seconds, fraction, TimestampResolution::Decimal(6))
            .expect("valid test timestamp")
    }

    fn timestamps_bounds(
        packets: &[PacketSpec],
    ) -> (Option<CaptureTimestamp>, Option<CaptureTimestamp>) {
        let mut earliest = None;
        let mut latest = None;
        for packet in packets {
            let Some(timestamp) = packet.timestamp else {
                continue;
            };
            if earliest
                .is_none_or(|existing: CaptureTimestamp| existing.cmp_instant(timestamp).is_gt())
            {
                earliest = Some(timestamp);
            }
            if latest
                .is_none_or(|existing: CaptureTimestamp| existing.cmp_instant(timestamp).is_lt())
            {
                latest = Some(timestamp);
            }
        }
        (earliest, latest)
    }

    fn timestamps_bounds_with_dns(
        packets: &[PacketSpecWithDns],
    ) -> (Option<CaptureTimestamp>, Option<CaptureTimestamp>) {
        let mut earliest = None;
        let mut latest = None;
        for packet in packets {
            let Some(timestamp) = packet.timestamp else {
                continue;
            };
            if earliest
                .is_none_or(|existing: CaptureTimestamp| existing.cmp_instant(timestamp).is_gt())
            {
                earliest = Some(timestamp);
            }
            if latest
                .is_none_or(|existing: CaptureTimestamp| existing.cmp_instant(timestamp).is_lt())
            {
                latest = Some(timestamp);
            }
        }
        (earliest, latest)
    }

    fn add_network_root(
        fields: &mut Vec<DecodedField>,
        field_children: &mut Vec<FieldId>,
        packet_data_start: u64,
        packet_range: ByteRange,
        network: NetworkSpec,
        ids: &StringIds,
        protocol: StringId,
    ) -> FieldId {
        let root = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: protocol,
            value: FieldValue::None,
            byte_range: packet_range,
            children: IndexRange::default(),
        });

        let source_id = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        let source_length: u32 = match network {
            NetworkSpec::V4(_, _) => 4,
            NetworkSpec::V6(_, _) => 16,
        };
        fields.push(DecodedField {
            name: ids.source_address,
            value: FieldValue::Bytes(
                ByteRange::new(packet_data_start, source_length)
                    .expect("source network range is valid"),
            ),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let destination_id = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.destination_address,
            value: FieldValue::Bytes(
                ByteRange::new(packet_data_start + u64::from(source_length), source_length)
                    .expect("destination network range is valid"),
            ),
            byte_range: packet_range,
            children: IndexRange::default(),
        });

        let children_start = u32::try_from(field_children.len()).expect("children index fits u32");
        field_children.push(source_id);
        field_children.push(destination_id);
        fields[root.0 as usize].children =
            IndexRange::new(children_start, 2).expect("network root child span is valid");
        root
    }

    fn add_transport_root(
        fields: &mut Vec<DecodedField>,
        field_children: &mut Vec<FieldId>,
        packet_range: ByteRange,
        protocol: StringId,
        ids: &StringIds,
        source_port: u16,
        destination_port: u16,
        tcp: Option<TcpPacketSpec>,
    ) -> FieldId {
        let root = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: protocol,
            value: FieldValue::None,
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let source = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.source_port,
            value: FieldValue::Unsigned(u64::from(source_port)),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let destination = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.destination_port,
            value: FieldValue::Unsigned(u64::from(destination_port)),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let mut child_ids = Vec::new();
        child_ids.push(source);
        child_ids.push(destination);
        if protocol == ids.tcp {
            if let Some(spec) = tcp {
                if let Some(sequence_number) = spec.sequence_number {
                    let sequence_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.sequence_number,
                        value: FieldValue::Unsigned(u64::from(sequence_number)),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(sequence_field);
                }

                if let Some(acknowledgment_number) = spec.acknowledgment_number {
                    let ack_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.acknowledgment_number,
                        value: FieldValue::Unsigned(u64::from(acknowledgment_number)),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(ack_field);
                }

                if spec.syn {
                    let syn_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.syn,
                        value: FieldValue::Boolean(true),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(syn_field);
                }
                if spec.ack {
                    let ack_flag_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.ack,
                        value: FieldValue::Boolean(true),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(ack_flag_field);
                }
                if spec.fin {
                    let fin_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.fin,
                        value: FieldValue::Boolean(true),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(fin_field);
                }
                if spec.rst {
                    let rst_field =
                        FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
                    fields.push(DecodedField {
                        name: ids.rst,
                        value: FieldValue::Boolean(true),
                        byte_range: packet_range,
                        children: IndexRange::default(),
                    });
                    child_ids.push(rst_field);
                }
            }
        }
        let children_start = u32::try_from(field_children.len()).expect("children index fits u32");
        for child_id in child_ids {
            field_children.push(child_id);
        }
        fields[root.0 as usize].children = IndexRange::new(
            children_start,
            u32::try_from(field_children.len() - children_start as usize)
                .expect("child range length fits u32"),
        )
        .expect("transport root child span is valid");
        root
    }

    #[derive(Clone, Copy)]
    struct DnsStringIds {
        ipv4: StringId,
        ipv6: StringId,
        tcp: StringId,
        udp: StringId,
        source_address: StringId,
        destination_address: StringId,
        source_port: StringId,
        destination_port: StringId,
        sequence_number: StringId,
        acknowledgment_number: StringId,
        syn: StringId,
        ack: StringId,
        fin: StringId,
        rst: StringId,
        dns: StringId,
        transaction_id: StringId,
        is_response: StringId,
        question_count: StringId,
        answer_count: StringId,
    }

    fn add_dns_root(
        fields: &mut Vec<DecodedField>,
        field_children: &mut Vec<FieldId>,
        packet_range: ByteRange,
        ids: &DnsStringIds,
        dns: DnsPacketSpec,
    ) -> FieldId {
        let root = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.dns,
            value: FieldValue::None,
            byte_range: packet_range,
            children: IndexRange::default(),
        });

        let transaction_id = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.transaction_id,
            value: FieldValue::Unsigned(u64::from(dns.transaction_id)),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let is_response = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.is_response,
            value: FieldValue::Boolean(dns.is_response),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let question_count = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.question_count,
            value: FieldValue::Unsigned(u64::from(dns.question_count)),
            byte_range: packet_range,
            children: IndexRange::default(),
        });
        let answer_count = FieldId(u32::try_from(fields.len()).expect("field id fits u32"));
        fields.push(DecodedField {
            name: ids.answer_count,
            value: FieldValue::Unsigned(u64::from(dns.answer_count)),
            byte_range: packet_range,
            children: IndexRange::default(),
        });

        let children_start = u32::try_from(field_children.len()).expect("children index fits u32");
        field_children.push(transaction_id);
        field_children.push(is_response);
        field_children.push(question_count);
        field_children.push(answer_count);
        fields[root.0 as usize].children = IndexRange::new(
            children_start,
            u32::try_from(field_children.len() - children_start as usize)
                .expect("child range length fits u32"),
        )
        .expect("dns root child span is valid");
        root
    }

    fn build_dataset(packets: &[PacketSpec]) -> CaptureDataset {
        let interface_count = packets
            .iter()
            .map(|packet| packet.interface_id.0)
            .max()
            .map_or(0, |id| id + 1);
        let strings = vec![
            "ipv4".into(),
            "ipv6".into(),
            "tcp".into(),
            "udp".into(),
            "source_address".into(),
            "destination_address".into(),
            "source_port".into(),
            "destination_port".into(),
            "sequence_number".into(),
            "acknowledgment_number".into(),
            "syn".into(),
            "ack".into(),
            "fin".into(),
            "rst".into(),
        ];
        let ids = StringIds {
            ipv4: StringId(0),
            ipv6: StringId(1),
            tcp: StringId(2),
            udp: StringId(3),
            source_address: StringId(4),
            destination_address: StringId(5),
            source_port: StringId(6),
            destination_port: StringId(7),
            sequence_number: StringId(8),
            acknowledgment_number: StringId(9),
            syn: StringId(10),
            ack: StringId(11),
            fin: StringId(12),
            rst: StringId(13),
        };
        let mut sections = vec![crate::model::SectionMetadata {
            id: crate::model::SectionId(0),
            byte_range: ByteRange::new(0, 0).expect("placeholder section range"),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, interface_count).expect("interface span is valid"),
        }];
        let mut interfaces = Vec::new();
        for index in 0..interface_count {
            interfaces.push(InterfaceMetadata {
                id: InterfaceId(index),
                section_id: crate::model::SectionId(0),
                byte_range: ByteRange::new(u64::from(index * 8), 8).expect("interface range valid"),
                section_index: index,
                link_type: LinkType(1),
                snap_length: 65_535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                name: None,
            });
        }

        let mut bytes = Vec::new();
        let mut packet_records = Vec::new();
        let mut layers = Vec::new();
        let mut fields = Vec::new();
        let mut field_children = Vec::new();
        let diagnostics = Vec::new();

        for (index, packet) in packets.iter().enumerate() {
            let payload_len = match packet.network {
                NetworkSpec::V4(_, _) => 32,
                NetworkSpec::V6(_, _) => 64,
            };
            let packet_start = u64::try_from(bytes.len()).expect("byte cursor fits");
            bytes.resize(bytes.len() + payload_len, 0);

            match packet.network {
                NetworkSpec::V4(source, destination) => {
                    bytes[packet_start as usize..packet_start as usize + 4]
                        .copy_from_slice(&source);
                    bytes[packet_start as usize + 4..packet_start as usize + 8]
                        .copy_from_slice(&destination);
                }
                NetworkSpec::V6(source, destination) => {
                    bytes[packet_start as usize..packet_start as usize + 16]
                        .copy_from_slice(&source);
                    bytes[packet_start as usize + 16..packet_start as usize + 32]
                        .copy_from_slice(&destination);
                }
            }

            let packet_range =
                ByteRange::new(packet_start, payload_len as u32).expect("packet range valid");
            let layer_start = u32::try_from(layers.len()).expect("layer span fits u32");
            match packet.network {
                NetworkSpec::V4(..) => {
                    let root = add_network_root(
                        &mut fields,
                        &mut field_children,
                        packet_start,
                        packet_range,
                        packet.network,
                        &ids,
                        ids.ipv4,
                    );
                    layers.push(LayerFact {
                        protocol: ids.ipv4,
                        byte_range: packet_range,
                        root_field: Some(root),
                    });
                }
                NetworkSpec::V6(..) => {
                    let root = add_network_root(
                        &mut fields,
                        &mut field_children,
                        packet_start,
                        packet_range,
                        packet.network,
                        &ids,
                        ids.ipv6,
                    );
                    layers.push(LayerFact {
                        protocol: ids.ipv6,
                        byte_range: packet_range,
                        root_field: Some(root),
                    });
                }
            }

            if let Some(transport) = packet.transport {
                let (protocol, source_port, destination_port) = match transport {
                    TransportSpec::Tcp(source_port, destination_port) => {
                        (ids.tcp, source_port, destination_port)
                    }
                    TransportSpec::Udp(source_port, destination_port) => {
                        (ids.udp, source_port, destination_port)
                    }
                };
                let root = add_transport_root(
                    &mut fields,
                    &mut field_children,
                    packet_range,
                    protocol,
                    &ids,
                    source_port,
                    destination_port,
                    packet.tcp,
                );
                layers.push(LayerFact {
                    protocol,
                    byte_range: packet_range,
                    root_field: Some(root),
                });
            }

            let layer_end = u32::try_from(layers.len()).expect("layer span fits u32");
            packet_records.push(PacketRecord {
                id: PacketId(u32::try_from(index).expect("packet id fits")),
                section_id: crate::model::SectionId(0),
                interface_id: packet.interface_id,
                timestamp: packet.timestamp,
                captured_length: payload_len as u32,
                original_length: payload_len as u32,
                data: packet_range,
                layers: IndexRange::new(layer_start, layer_end - layer_start)
                    .expect("packet layer span valid"),
                diagnostics: IndexRange::default(),
            });
        }

        let (started_at, ended_at) = timestamps_bounds(packets);
        if let Some(section) = sections.get_mut(0) {
            section.byte_range = ByteRange::new(
                0,
                u32::try_from(bytes.len()).expect("section byte length fits u32"),
            )
            .expect("section range valid");
        }
        let byte_length = u64::try_from(bytes.len()).expect("byte length fits");
        CaptureDataset::from_parts(CaptureDatasetParts {
            metadata: CaptureMetadata {
                format: CaptureFormat::Pcap,
                byte_length,
                packet_count: u64::try_from(packet_records.len()).expect("packet count fits"),
                started_at,
                ended_at,
            },
            bytes: bytes.into_boxed_slice(),
            sections: sections.into_boxed_slice(),
            interfaces: interfaces.into_boxed_slice(),
            packets: packet_records.into_boxed_slice(),
            layers: layers.into_boxed_slice(),
            fields: fields.into_boxed_slice(),
            field_children: field_children.into_boxed_slice(),
            diagnostics: diagnostics.into_boxed_slice(),
            strings: strings.into_boxed_slice(),
        })
        .expect("test dataset is valid")
    }

    fn build_dataset_with_dns(packets: &[PacketSpecWithDns]) -> CaptureDataset {
        let interface_count = packets
            .iter()
            .map(|packet| packet.interface_id.0)
            .max()
            .map_or(0, |id| id + 1);
        let strings = vec![
            "ipv4".into(),
            "ipv6".into(),
            "tcp".into(),
            "udp".into(),
            "source_address".into(),
            "destination_address".into(),
            "source_port".into(),
            "destination_port".into(),
            "sequence_number".into(),
            "acknowledgment_number".into(),
            "syn".into(),
            "ack".into(),
            "fin".into(),
            "rst".into(),
            "dns".into(),
            "transaction_id".into(),
            "is_response".into(),
            "question_count".into(),
            "answer_count".into(),
        ];
        let ids = DnsStringIds {
            ipv4: StringId(0),
            ipv6: StringId(1),
            tcp: StringId(2),
            udp: StringId(3),
            source_address: StringId(4),
            destination_address: StringId(5),
            source_port: StringId(6),
            destination_port: StringId(7),
            sequence_number: StringId(8),
            acknowledgment_number: StringId(9),
            syn: StringId(10),
            ack: StringId(11),
            fin: StringId(12),
            rst: StringId(13),
            dns: StringId(14),
            transaction_id: StringId(15),
            is_response: StringId(16),
            question_count: StringId(17),
            answer_count: StringId(18),
        };
        let legacy_ids = StringIds {
            ipv4: ids.ipv4,
            ipv6: ids.ipv6,
            tcp: ids.tcp,
            udp: ids.udp,
            source_address: ids.source_address,
            destination_address: ids.destination_address,
            source_port: ids.source_port,
            destination_port: ids.destination_port,
            sequence_number: ids.sequence_number,
            acknowledgment_number: ids.acknowledgment_number,
            syn: ids.syn,
            ack: ids.ack,
            fin: ids.fin,
            rst: ids.rst,
        };
        let mut sections = vec![crate::model::SectionMetadata {
            id: crate::model::SectionId(0),
            byte_range: ByteRange::new(0, 0).expect("placeholder section range"),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, interface_count).expect("interface span is valid"),
        }];
        let mut interfaces = Vec::new();
        for index in 0..interface_count {
            interfaces.push(InterfaceMetadata {
                id: InterfaceId(index),
                section_id: crate::model::SectionId(0),
                byte_range: ByteRange::new(u64::from(index * 8), 8).expect("interface range valid"),
                section_index: index,
                link_type: LinkType(1),
                snap_length: 65_535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                name: None,
            });
        }

        let mut bytes = Vec::new();
        let mut packet_records = Vec::new();
        let mut layers = Vec::new();
        let mut fields = Vec::new();
        let mut field_children = Vec::new();
        let diagnostics = Vec::new();

        for (index, packet) in packets.iter().enumerate() {
            let payload_len = packet.captured_length.max(match packet.network {
                NetworkSpec::V4(_, _) => 32,
                NetworkSpec::V6(_, _) => 64,
            });
            let packet_start = u64::try_from(bytes.len()).expect("byte cursor fits");
            bytes.resize(
                bytes.len() + usize::try_from(payload_len).expect("payload len fits usize"),
                0,
            );

            match packet.network {
                NetworkSpec::V4(source, destination) => {
                    let start = usize::try_from(packet_start).expect("start index fits");
                    bytes[start..start + 4].copy_from_slice(&source);
                    bytes[start + 4..start + 8].copy_from_slice(&destination);
                }
                NetworkSpec::V6(source, destination) => {
                    let start = usize::try_from(packet_start).expect("start index fits");
                    bytes[start..start + 16].copy_from_slice(&source);
                    bytes[start + 16..start + 32].copy_from_slice(&destination);
                }
            }

            let packet_range =
                ByteRange::new(packet_start, payload_len).expect("packet range valid");
            let layer_start = u32::try_from(layers.len()).expect("layer span fits u32");
            match packet.network {
                NetworkSpec::V4(..) => {
                    let root = add_network_root(
                        &mut fields,
                        &mut field_children,
                        packet_start,
                        packet_range,
                        packet.network,
                        &legacy_ids,
                        ids.ipv4,
                    );
                    layers.push(LayerFact {
                        protocol: ids.ipv4,
                        byte_range: packet_range,
                        root_field: Some(root),
                    });
                }
                NetworkSpec::V6(..) => {
                    let root = add_network_root(
                        &mut fields,
                        &mut field_children,
                        packet_start,
                        packet_range,
                        packet.network,
                        &legacy_ids,
                        ids.ipv6,
                    );
                    layers.push(LayerFact {
                        protocol: ids.ipv6,
                        byte_range: packet_range,
                        root_field: Some(root),
                    });
                }
            }

            if let Some(transport) = packet.transport {
                let (protocol, source_port, destination_port) = match transport {
                    TransportSpec::Tcp(source_port, destination_port) => {
                        (ids.tcp, source_port, destination_port)
                    }
                    TransportSpec::Udp(source_port, destination_port) => {
                        (ids.udp, source_port, destination_port)
                    }
                };
                let root = add_transport_root(
                    &mut fields,
                    &mut field_children,
                    packet_range,
                    protocol,
                    &legacy_ids,
                    source_port,
                    destination_port,
                    packet.tcp,
                );
                layers.push(LayerFact {
                    protocol,
                    byte_range: packet_range,
                    root_field: Some(root),
                });
            }

            if let Some(dns) = packet.dns {
                let root = add_dns_root(&mut fields, &mut field_children, packet_range, &ids, dns);
                layers.push(LayerFact {
                    protocol: ids.dns,
                    byte_range: packet_range,
                    root_field: Some(root),
                });
            }

            let layer_end = u32::try_from(layers.len()).expect("layer span fits u32");
            packet_records.push(PacketRecord {
                id: PacketId(u32::try_from(index).expect("packet id fits")),
                section_id: crate::model::SectionId(0),
                interface_id: packet.interface_id,
                timestamp: packet.timestamp,
                captured_length: payload_len,
                original_length: payload_len,
                data: packet_range,
                layers: IndexRange::new(layer_start, layer_end - layer_start)
                    .expect("packet layer span valid"),
                diagnostics: IndexRange::default(),
            });
        }

        let (started_at, ended_at) = timestamps_bounds_with_dns(packets);
        if let Some(section) = sections.get_mut(0) {
            section.byte_range = ByteRange::new(
                0,
                u32::try_from(bytes.len()).expect("section byte length fits u32"),
            )
            .expect("section range valid");
        }
        let byte_length = u64::try_from(bytes.len()).expect("byte length fits");
        CaptureDataset::from_parts(CaptureDatasetParts {
            metadata: CaptureMetadata {
                format: CaptureFormat::Pcap,
                byte_length,
                packet_count: u64::try_from(packet_records.len()).expect("packet count fits"),
                started_at,
                ended_at,
            },
            bytes: bytes.into_boxed_slice(),
            sections: sections.into_boxed_slice(),
            interfaces: interfaces.into_boxed_slice(),
            packets: packet_records.into_boxed_slice(),
            layers: layers.into_boxed_slice(),
            fields: fields.into_boxed_slice(),
            field_children: field_children.into_boxed_slice(),
            diagnostics: diagnostics.into_boxed_slice(),
            strings: strings.into_boxed_slice(),
        })
        .expect("test dataset is valid")
    }

    #[test]
    fn reconstruct_bidirectional_flows_are_canonical_and_directional() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(10, 200)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(443, 443)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(8, 900)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(443, 443)),
                tcp: None,
            },
        ]);
        let first = dataset
            .reconstruct_bidirectional_flows()
            .expect("flow reconstruction succeeds");
        let second = dataset
            .reconstruct_bidirectional_flows()
            .expect("flow reconstruction succeeds");
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);

        let flow = &first[0];
        assert_eq!(flow.packets_a_to_b, 1);
        assert_eq!(flow.packets_b_to_a, 1);
        assert_eq!(flow.bytes_a_to_b, 32);
        assert_eq!(flow.bytes_b_to_a, 32);
        assert_eq!(flow.first_timestamp, Some(timestamp(8, 900)));
        assert_eq!(flow.last_timestamp, Some(timestamp(10, 200)));
    }

    #[test]
    fn reconstruct_bidirectional_flows_distinguish_tcp_udp_and_interface() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: None,
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(443, 53)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(1),
                timestamp: None,
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(443, 53)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: None,
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Udp(443, 53)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: None,
                network: NetworkSpec::V6([0_u8; 16], [1_u8; 16]),
                transport: Some(TransportSpec::Udp(53, 443)),
                tcp: None,
            },
        ]);
        let flows = dataset
            .reconstruct_bidirectional_flows()
            .expect("flow reconstruction succeeds");
        let tcp_flows: Vec<_> = flows
            .iter()
            .filter(|flow| flow.protocol == TransportProtocol::Tcp)
            .collect();
        let udp_flows: Vec<_> = flows
            .iter()
            .filter(|flow| flow.protocol == TransportProtocol::Udp)
            .collect();
        assert_eq!(tcp_flows.len(), 2);
        assert_eq!(udp_flows.len(), 2);
        assert_eq!(tcp_flows[0].interface_id, InterfaceId(0));
        assert_eq!(tcp_flows[1].interface_id, InterfaceId(1));
        assert_eq!(udp_flows[1].endpoint_a.address, IpAddress::V6([0_u8; 16]));
    }

    #[test]
    fn reconstruct_bidirectional_flows_skip_partial_captures() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(443, 443)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(3, 0)),
                network: NetworkSpec::V4([10, 0, 0, 3], [10, 0, 0, 4]),
                transport: None,
                tcp: None,
            },
        ]);
        let flows = dataset
            .reconstruct_bidirectional_flows()
            .expect("flow reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packets_total(), 1);
        assert_eq!(flows[0].bytes_total(), 32);
    }

    #[test]
    fn reconstruct_bidirectional_flows_handle_timestamp_ties() {
        let shared = timestamp(100, 10);
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(shared),
                network: NetworkSpec::V6([0_u8; 16], [1_u8; 16]),
                transport: Some(TransportSpec::Tcp(22, 22)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(shared),
                network: NetworkSpec::V6([1_u8; 16], [0_u8; 16]),
                transport: Some(TransportSpec::Tcp(22, 22)),
                tcp: None,
            },
        ]);
        let flows = dataset
            .reconstruct_bidirectional_flows()
            .expect("flow reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].first_timestamp, Some(shared));
        assert_eq!(flows[0].last_timestamp, Some(shared));
        assert_eq!(flows[0].packets_total(), 2);
        assert_eq!(flows[0].bytes_total(), 128);
    }

    #[test]
    fn reconstruct_tcp_connection_states_detects_three_way_handshake() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_000),
                    acknowledgment_number: None,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(2_000),
                    acknowledgment_number: Some(1_001),
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(3, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_001),
                    acknowledgment_number: Some(2_001),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
        ]);
        let flows = dataset
            .reconstruct_tcp_connection_states()
            .expect("tcp state reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(
            flow.establishment,
            TcpConnectionEstablishment::Established {
                syn: PacketEvidence {
                    packet_id: PacketId(0)
                },
                syn_ack: PacketEvidence {
                    packet_id: PacketId(1)
                },
                final_ack: PacketEvidence {
                    packet_id: PacketId(2)
                },
                confidence: TcpHeuristicConfidence::Certain,
            }
        );
        assert_eq!(flow.termination, TcpConnectionTermination::NotObserved);
        assert!(flow.partial_capture);
        assert!(flow.retransmission.is_none());
    }

    #[test]
    fn reconstruct_tcp_connection_states_marks_failed_with_reset() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(100),
                    acknowledgment_number: None,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(200),
                    acknowledgment_number: Some(101),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: true,
                }),
            },
        ]);
        let flows = dataset
            .reconstruct_tcp_connection_states()
            .expect("tcp state reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(
            flow.establishment,
            TcpConnectionEstablishment::Failed {
                syn: PacketEvidence {
                    packet_id: PacketId(0)
                },
                evidence: PacketPairEvidence {
                    first: PacketEvidence {
                        packet_id: PacketId(0)
                    },
                    second: Some(PacketEvidence {
                        packet_id: PacketId(1)
                    }),
                },
                cause: TcpConnectionFailureCause::Reset,
                confidence: TcpHeuristicConfidence::Certain,
            }
        );
        assert_eq!(
            flow.termination,
            TcpConnectionTermination::Reset {
                packet: PacketEvidence {
                    packet_id: PacketId(1)
                },
                confidence: TcpHeuristicConfidence::Certain,
            }
        );
    }

    #[test]
    fn reconstruct_tcp_connection_states_flags_retransmission_duplicate_ack_and_out_of_order() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(10),
                    acknowledgment_number: None,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(20),
                    acknowledgment_number: Some(11),
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(3, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(11),
                    acknowledgment_number: Some(21),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(4, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(22),
                    acknowledgment_number: Some(12),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(5, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(23),
                    acknowledgment_number: Some(12),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(6, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(11),
                    acknowledgment_number: Some(22),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(7, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(5),
                    acknowledgment_number: Some(22),
                    syn: false,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
        ]);
        let flows = dataset
            .reconstruct_tcp_connection_states()
            .expect("tcp state reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(
            flow.retransmission,
            Some(TcpDirectionalIndicator {
                direction: FlowDirection::AToB,
                packets: PacketPairEvidence {
                    first: PacketEvidence {
                        packet_id: PacketId(2)
                    },
                    second: Some(PacketEvidence {
                        packet_id: PacketId(5)
                    }),
                },
                confidence: TcpHeuristicConfidence::Inferred,
            })
        );
        assert_eq!(
            flow.duplicate_ack,
            Some(TcpDirectionalIndicator {
                direction: FlowDirection::BToA,
                packets: PacketPairEvidence {
                    first: PacketEvidence {
                        packet_id: PacketId(3)
                    },
                    second: Some(PacketEvidence {
                        packet_id: PacketId(4)
                    }),
                },
                confidence: TcpHeuristicConfidence::Inferred,
            })
        );
        assert_eq!(
            flow.out_of_order,
            Some(TcpDirectionalIndicator {
                direction: FlowDirection::AToB,
                packets: PacketPairEvidence {
                    first: PacketEvidence {
                        packet_id: PacketId(5)
                    },
                    second: Some(PacketEvidence {
                        packet_id: PacketId(6)
                    }),
                },
                confidence: TcpHeuristicConfidence::Inferred,
            })
        );
        assert_eq!(flow.partial_capture, true);
    }

    #[test]
    fn reconstruct_tcp_connection_states_tracks_fin_termination() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(9_999, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(500),
                    acknowledgment_number: None,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 9_999)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(600),
                    acknowledgment_number: Some(501),
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(3, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(9_999, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(501),
                    acknowledgment_number: Some(601),
                    syn: false,
                    ack: true,
                    fin: true,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(4, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 9_999)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(601),
                    acknowledgment_number: Some(502),
                    syn: false,
                    ack: true,
                    fin: true,
                    rst: false,
                }),
            },
        ]);
        let flows = dataset
            .reconstruct_tcp_connection_states()
            .expect("tcp state reconstruction succeeds");
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(
            flow.termination,
            TcpConnectionTermination::Fin {
                first_fin: PacketEvidence {
                    packet_id: PacketId(2)
                },
                second_fin: Some(PacketEvidence {
                    packet_id: PacketId(3)
                }),
                confidence: TcpHeuristicConfidence::Certain,
            }
        );
    }

    #[test]
    fn reconstruct_flow_metrics_computes_directional_totals_and_duration() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(53, 53)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 250_000)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(53, 53)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(53, 53)),
                tcp: None,
            },
        ]);
        let metrics = dataset
            .reconstruct_flow_metrics()
            .expect("flow metrics reconstruction succeeds");
        assert_eq!(metrics.len(), 1);
        let flow = &metrics[0];
        assert_eq!(flow.packets_total, 3);
        assert_eq!(flow.bytes_total, 96);
        assert_eq!(flow.packets_a_to_b, 2);
        assert_eq!(flow.packets_b_to_a, 1);
        assert_eq!(flow.bytes_a_to_b, 64);
        assert_eq!(flow.bytes_b_to_a, 32);
        assert_eq!(
            flow.duration,
            Some(TcpFlowDuration {
                ticks: 1_000_000,
                resolution: TimestampResolution::Decimal(6),
            })
        );
        assert_eq!(flow.packet_size_distribution.min_size_bytes, Some(32));
        assert_eq!(flow.packet_size_distribution.max_size_bytes, Some(32));
        assert_eq!(flow.packet_size_distribution.total_size_bytes, 96);
        assert_eq!(
            flow.packet_size_distribution.buckets,
            [3, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn reconstruct_flow_metrics_estimates_handshake_and_first_data_timing() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_000),
                    acknowledgment_number: None,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(2, 0)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 12_345)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(2_000),
                    acknowledgment_number: Some(1_001),
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(3, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_001),
                    acknowledgment_number: Some(2_001),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(4, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(12_345, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_002),
                    acknowledgment_number: Some(2_001),
                    syn: false,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
        ]);
        let metrics = dataset
            .reconstruct_flow_metrics()
            .expect("flow metrics reconstruction succeeds");
        let flow = &metrics[0];
        assert_eq!(
            flow.handshake_latency,
            Some(TcpFlowDuration {
                ticks: 2_000_000,
                resolution: TimestampResolution::Decimal(6),
            })
        );
        assert_eq!(
            flow.time_to_first_data,
            Some(TcpFlowDuration {
                ticks: 1_000_000,
                resolution: TimestampResolution::Decimal(6),
            })
        );
    }

    #[test]
    fn reconstruct_flow_metrics_reports_dns_response_latency() {
        let dataset = build_dataset_with_dns(&[
            PacketSpecWithDns {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 53]),
                transport: Some(TransportSpec::Udp(53_001, 53)),
                tcp: None,
                dns: Some(DnsPacketSpec {
                    transaction_id: 0x1234,
                    is_response: false,
                    question_count: 1,
                    answer_count: 0,
                }),
                captured_length: 32,
            },
            PacketSpecWithDns {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 250_000)),
                network: NetworkSpec::V4([10, 0, 0, 53], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Udp(53, 53_001)),
                tcp: None,
                dns: Some(DnsPacketSpec {
                    transaction_id: 0x1234,
                    is_response: true,
                    question_count: 0,
                    answer_count: 1,
                }),
                captured_length: 32,
            },
        ]);
        let metrics = dataset
            .reconstruct_flow_metrics()
            .expect("flow metrics reconstruction succeeds");
        let flow = &metrics[0];
        assert_eq!(
            flow.dns_response_latency,
            Some(TcpFlowDuration {
                ticks: 250_000,
                resolution: TimestampResolution::Decimal(6),
            })
        );
    }

    #[test]
    fn reconstruct_packet_sequence_timelines_builds_directional_messages_and_lanes() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 0)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(55_001, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_000),
                    acknowledgment_number: Some(0),
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 250_000)),
                network: NetworkSpec::V4([10, 0, 0, 2], [10, 0, 0, 1]),
                transport: Some(TransportSpec::Tcp(80, 55_001)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(2_000),
                    acknowledgment_number: Some(1_001),
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                }),
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(1, 500_000)),
                network: NetworkSpec::V4([10, 0, 0, 1], [10, 0, 0, 2]),
                transport: Some(TransportSpec::Tcp(55_001, 80)),
                tcp: Some(TcpPacketSpec {
                    sequence_number: Some(1_001),
                    acknowledgment_number: Some(2_001),
                    syn: false,
                    ack: true,
                    fin: true,
                    rst: false,
                }),
            },
        ]);
        let timelines = dataset
            .reconstruct_packet_sequence_timelines()
            .expect("timeline reconstruction succeeds");
        assert_eq!(timelines.len(), 1);
        let timeline = &timelines[0];

        assert_eq!(timeline.protocol, TransportProtocol::Tcp);
        assert_eq!(timeline.messages.len(), 3);
        assert_eq!(
            timeline.lane_a.message_indices,
            vec![0, 2].into_boxed_slice()
        );
        assert_eq!(timeline.lane_b.message_indices, vec![1].into_boxed_slice());

        assert_eq!(timeline.messages[0].packet_id, PacketId(0));
        assert_eq!(
            timeline.messages[0].relative_offset,
            Some(TcpFlowDuration {
                ticks: 0,
                resolution: TimestampResolution::Decimal(6)
            })
        );
        assert_eq!(
            timeline.messages[0].tcp_flags,
            Some(PacketSequenceFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false
            })
        );
        assert_eq!(
            timeline.messages[1].tcp_flags,
            Some(PacketSequenceFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false
            })
        );
        assert_eq!(
            timeline.messages[2].tcp_flags,
            Some(PacketSequenceFlags {
                syn: false,
                ack: true,
                fin: true,
                rst: false
            })
        );
    }

    #[test]
    fn reconstruct_packet_sequence_timelines_zoom_aggregates_long_flow() {
        let mut packets = Vec::new();
        for index in 0..6 {
            packets.push(PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(index, 0)),
                network: NetworkSpec::V4([10, 0, 0, 3], [10, 0, 0, 4]),
                transport: Some(TransportSpec::Udp(53, 53)),
                tcp: None,
            });
        }
        let dataset = build_dataset(&packets);
        let timelines = dataset
            .reconstruct_packet_sequence_timelines()
            .expect("timeline reconstruction succeeds");
        assert_eq!(timelines.len(), 1);
        let timeline = &timelines[0];
        let entries = timeline.zoom(None, None, Some(2));
        assert_eq!(entries.len(), 2);
        match &entries[0] {
            PacketSequenceTimelineEntry::Aggregate(aggregate) => {
                assert_eq!(aggregate.packet_count, 3);
                assert_eq!(aggregate.first_packet, PacketId(0));
                assert_eq!(aggregate.last_packet, PacketId(2));
                assert_eq!(aggregate.first_packet_size_bytes, 32);
                assert_eq!(aggregate.total_packet_bytes, 96);
                assert_eq!(
                    aggregate.first_offset,
                    Some(TcpFlowDuration {
                        ticks: 0,
                        resolution: TimestampResolution::Decimal(6),
                    })
                );
                assert_eq!(
                    aggregate.last_offset,
                    Some(TcpFlowDuration {
                        ticks: 2_000_000,
                        resolution: TimestampResolution::Decimal(6),
                    })
                );
            }
            _ => panic!("expected aggregate"),
        }
        match &entries[1] {
            PacketSequenceTimelineEntry::Aggregate(aggregate) => {
                assert_eq!(aggregate.packet_count, 3);
                assert_eq!(aggregate.first_packet, PacketId(3));
                assert_eq!(aggregate.last_packet, PacketId(5));
                assert_eq!(aggregate.total_packet_bytes, 96);
            }
            _ => panic!("expected aggregate"),
        }
    }

    #[test]
    fn reconstruct_packet_sequence_timelines_handles_missing_packet_timestamps() {
        let dataset = build_dataset(&[
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: None,
                network: NetworkSpec::V4([10, 0, 0, 5], [10, 0, 0, 6]),
                transport: Some(TransportSpec::Udp(1000, 2000)),
                tcp: None,
            },
            PacketSpec {
                interface_id: InterfaceId(0),
                timestamp: Some(timestamp(10, 0)),
                network: NetworkSpec::V4([10, 0, 0, 5], [10, 0, 0, 6]),
                transport: Some(TransportSpec::Udp(1000, 2000)),
                tcp: None,
            },
        ]);
        let timelines = dataset
            .reconstruct_packet_sequence_timelines()
            .expect("timeline reconstruction succeeds");
        assert_eq!(timelines.len(), 1);
        let timeline = &timelines[0];
        assert_eq!(timeline.messages[0].timestamp, None);
        assert_eq!(timeline.messages[0].relative_offset, None);
        assert_eq!(timeline.messages[1].timestamp, Some(timestamp(10, 0)));
        assert_eq!(
            timeline.messages[1].relative_offset,
            Some(TcpFlowDuration {
                ticks: 0,
                resolution: TimestampResolution::Decimal(6),
            })
        );
    }
}
