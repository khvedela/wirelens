//! Exact post-DNS decoder resource maxima on real synthetic packet paths.

use packet_core::{CaptureDataset, CaptureImporter, ImportLimits, ImportStep};
use protocol_decoders::{
    DECODER_MAX_FIELD_CHILDREN_PER_PACKET, DECODER_MAX_FIELDS_PER_PACKET,
    DECODER_MAX_LAYERS_PER_PACKET, LinkLayerDecoder,
};

const DNS_PORT: u16 = 53;

fn legacy_capture(packet: &[u8]) -> Vec<u8> {
    let packet_length = u32::try_from(packet.len()).expect("synthetic packet length fits u32");
    let mut bytes = Vec::with_capacity(40 + packet.len());
    bytes.extend([0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend(2_u16.to_le_bytes());
    bytes.extend(4_u16.to_le_bytes());
    bytes.extend(0_i32.to_le_bytes());
    bytes.extend(0_u32.to_le_bytes());
    bytes.extend(65_535_u32.to_le_bytes());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(2_u32.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet_length.to_le_bytes());
    bytes.extend(packet);
    bytes
}

fn decode(packet: &[u8]) -> CaptureDataset {
    let mut importer = CaptureImporter::new_with_decoder(
        legacy_capture(packet).into_boxed_slice(),
        ImportLimits::default(),
        Box::new(LinkLayerDecoder::new()),
    )
    .expect("synthetic capture is valid");
    loop {
        match importer
            .step(64, 1024 * 1024)
            .expect("bounded synthetic import succeeds")
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
    importer.finish().expect("decoded dataset validates")
}

fn vlan_header(inner_ether_type: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(18);
    frame.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend(0x8100_u16.to_be_bytes());
    frame.extend(100_u16.to_be_bytes());
    frame.extend(inner_ether_type.to_be_bytes());
    frame
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for bytes in parts {
        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(last) << 8;
        }
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

fn maximum_dns_message() -> Vec<u8> {
    let mut message = Vec::new();
    message.extend(0x1234_u16.to_be_bytes());
    message.extend(0x8180_u16.to_be_bytes());
    message.extend(16_u16.to_be_bytes());
    message.extend(16_u16.to_be_bytes());
    message.extend(0_u16.to_be_bytes());
    message.extend(0_u16.to_be_bytes());

    for _ in 0..16 {
        // A direct root name still consumes one bounded name occurrence.
        message.push(0);
        message.extend(1_u16.to_be_bytes());
        message.extend(1_u16.to_be_bytes());
    }

    for _ in 0..15 {
        message.push(0);
        message.extend(6_u16.to_be_bytes());
        message.extend(1_u16.to_be_bytes());
        message.extend(300_u32.to_be_bytes());
        message.extend(22_u16.to_be_bytes());
        // SOA has the largest per-record tree: two names and five integers.
        message.extend([0, 0]);
        for value in [1_u32, 2, 3, 4, 5] {
            message.extend(value.to_be_bytes());
        }
    }

    message.push(0);
    message.extend(16_u16.to_be_bytes());
    message.extend(1_u16.to_be_bytes());
    message.extend(300_u32.to_be_bytes());
    message.extend(16_u16.to_be_bytes());
    // The global TXT cap contributes 16 leaf fields to this final record.
    message.extend([0_u8; 16]);
    message
}

fn maximal_ipv4_tcp_dns_decode() -> Vec<u8> {
    const IPV4_HEADER_LENGTH: usize = 60;
    const TCP_HEADER_LENGTH: usize = 60;

    let dns = maximum_dns_message();
    let mut tcp_payload = Vec::with_capacity(2 + dns.len());
    tcp_payload.extend(
        u16::try_from(dns.len())
            .expect("DNS message length fits u16")
            .to_be_bytes(),
    );
    tcp_payload.extend(dns);

    let tcp_length = TCP_HEADER_LENGTH + tcp_payload.len();
    let ipv4_length = IPV4_HEADER_LENGTH + tcp_length;
    let mut frame = vlan_header(0x0800);
    let ipv4_start = frame.len();
    frame.extend([0x4f, 0]);
    frame.extend(
        u16::try_from(ipv4_length)
            .expect("IPv4 packet length fits u16")
            .to_be_bytes(),
    );
    frame.extend(0x1234_u16.to_be_bytes());
    frame.extend(0_u16.to_be_bytes());
    frame.extend([64, 6]);
    frame.extend(0_u16.to_be_bytes());
    frame.extend([192, 0, 2, 1]);
    frame.extend([198, 51, 100, 2]);
    for _ in 0..20 {
        frame.extend([0x1e, 2]);
    }
    let ipv4_checksum = checksum(&[&frame[ipv4_start..ipv4_start + IPV4_HEADER_LENGTH]]);
    frame[ipv4_start + 10..ipv4_start + 12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    let tcp_start = frame.len();
    frame.extend(12_345_u16.to_be_bytes());
    frame.extend(DNS_PORT.to_be_bytes());
    frame.extend(0x0102_0304_u32.to_be_bytes());
    frame.extend(0x0506_0708_u32.to_be_bytes());
    frame.extend([0xf0, 0xff]);
    frame.extend(4_096_u16.to_be_bytes());
    frame.extend(0_u16.to_be_bytes());
    frame.extend(0_u16.to_be_bytes());
    for _ in 0..20 {
        frame.extend([0x1e, 2]);
    }
    frame.extend(tcp_payload);

    let tcp_length_bytes = u16::try_from(tcp_length)
        .expect("TCP segment length fits u16")
        .to_be_bytes();
    let protocol = [0_u8, 6];
    let tcp_checksum = checksum(&[
        &frame[ipv4_start + 12..ipv4_start + 16],
        &frame[ipv4_start + 16..ipv4_start + 20],
        &protocol,
        &tcp_length_bytes,
        &frame[tcp_start..],
    ]);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    frame
}

fn maximal_ipv6_dns_layer_decode() -> Vec<u8> {
    const EXTENSION_BYTES: usize = 8 * 8;
    const UDP_HEADER_LENGTH: usize = 8;
    let dns = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
    let udp_length = UDP_HEADER_LENGTH + dns.len();
    let payload_length = EXTENSION_BYTES + udp_length;
    let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let mut frame = vlan_header(0x86dd);
    frame.extend(0x6000_0000_u32.to_be_bytes());
    frame.extend(
        u16::try_from(payload_length)
            .expect("IPv6 payload length fits u16")
            .to_be_bytes(),
    );
    frame.extend([60, 64]);
    frame.extend(source);
    frame.extend(destination);
    for index in 0..8 {
        frame.extend([if index == 7 { 17 } else { 60 }, 0, 0, 0, 0, 0, 0, 0]);
    }

    let udp_start = frame.len();
    frame.extend(12_345_u16.to_be_bytes());
    frame.extend(DNS_PORT.to_be_bytes());
    frame.extend(
        u16::try_from(udp_length)
            .expect("UDP datagram length fits u16")
            .to_be_bytes(),
    );
    frame.extend(0_u16.to_be_bytes());
    frame.extend(dns);

    let udp_length_bytes = u32::try_from(udp_length)
        .expect("UDP length fits u32")
        .to_be_bytes();
    let next_header = [0_u8, 0, 0, 17];
    let udp_checksum = checksum(&[
        &source,
        &destination,
        &udp_length_bytes,
        &next_header,
        &frame[udp_start..],
    ]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    frame
}

fn layer_names(dataset: &CaptureDataset) -> Vec<&str> {
    dataset
        .layers()
        .iter()
        .map(|layer| {
            dataset
                .string(layer.protocol)
                .expect("protocol string exists")
        })
        .collect()
}

#[test]
fn maximum_ipv4_tcp_dns_tree_matches_exact_field_and_child_ceilings() {
    let dataset = decode(&maximal_ipv4_tcp_dns_decode());

    assert_eq!(
        layer_names(&dataset),
        ["ethernet", "vlan", "ipv4", "tcp", "dns"]
    );
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(dataset.fields().len(), 487);
    assert_eq!(dataset.field_children().len(), 482);
    assert_eq!(
        dataset.fields().len(),
        DECODER_MAX_FIELDS_PER_PACKET as usize
    );
    assert_eq!(
        dataset.field_children().len(),
        DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize
    );
}

#[test]
fn maximum_ipv6_extension_path_reaches_exact_layer_ceiling_with_dns() {
    let dataset = decode(&maximal_ipv6_dns_layer_decode());
    let names = layer_names(&dataset);

    assert_eq!(names.first(), Some(&"ethernet"));
    assert_eq!(names.get(1), Some(&"vlan"));
    assert_eq!(names.get(2), Some(&"ipv6"));
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "ipv6_destination_options")
            .count(),
        8
    );
    assert_eq!(&names[11..], ["udp", "dns"]);
    assert!(dataset.diagnostics().is_empty());
    assert_eq!(dataset.layers().len(), 13);
    assert_eq!(
        dataset.layers().len(),
        DECODER_MAX_LAYERS_PER_PACKET as usize
    );
    assert!(dataset.fields().len() <= DECODER_MAX_FIELDS_PER_PACKET as usize);
    assert!(dataset.field_children().len() <= DECODER_MAX_FIELD_CHILDREN_PER_PACKET as usize);
}
