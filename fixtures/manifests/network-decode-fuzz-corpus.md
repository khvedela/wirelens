# Network and transport decoder fuzz corpus provenance

- **Created:** 2026-07-26
- **Source:** WireLens-authored, deterministic synthetic byte sequences. No observed, captured,
  user-provided, private, or proprietary network traffic was used.
- **Redistribution:** Every byte is generated synthetic data and is redistributable under the
  WireLens repository license (MIT).
- **Encoding:** Each `.hex` file contains a literal `hex:` prefix followed by a one-byte selector
  and at most 4 KiB of network-layer bytes. ASCII whitespace after the prefix is ignored.
- **Regeneration:** The committed text is the canonical deterministic source. Copying a file
  byte-for-byte reproduces its fuzz input. The target deterministically adds capture-container and
  Ethernet framing at runtime; no binary capture is stored.
- **Synthetic identities:** The runtime Ethernet wrapper uses locally administered
  `02:00:00:00:00:01` and `02:00:00:00:00:02` addresses. IPv4 seeds use documentation-only
  TEST-NET-1 addresses `192.0.2.1` and `192.0.2.2`. IPv6 seeds use documentation-only
  `2001:db8::1` and `2001:db8::2` addresses.

The selector's low three bits choose the deterministic framing. Higher bits are ignored during
mutation:

| Selector | Container | Ethernet path |
| ---: | --- | --- |
| `0` | Legacy PCAP | Untagged IPv4 |
| `1` | Legacy PCAP | Untagged IPv6 |
| `2` | Legacy PCAP | VLAN 100, IPv4 |
| `3` | Legacy PCAP | VLAN 100, IPv6 |
| `4` | PCAPNG enhanced packet | Untagged IPv4 |
| `5` | PCAPNG enhanced packet | Untagged IPv6 |
| `6` | PCAPNG enhanced packet | VLAN 100, IPv4 |
| `7` | PCAPNG enhanced packet | VLAN 100, IPv6 |

| Seed | Protocol intent | Expected bounded behavior | SHA-256 of committed text file |
| --- | --- | --- | --- |
| `fuzz/corpus/network_decode/ipv4-options-valid.hex` | Complete IPv4 header with NOP, a length-two experimental option, EOL, a valid checksum, and four authored payload bytes. | Decode the IHL-bounded options, retain the protocol selector, and leave the authored payload bytes uninterpreted in canonical packet data. | `7586ac72781d26d140416f2ba025e7bb380158c9a771a3e3484ffacb0344ed57` |
| `fuzz/corpus/network_decode/ipv4-options-malformed.hex` | Complete IPv4 header whose experimental option declares invalid length one. | Stop option traversal with structured malformed evidence and no out-of-bounds read. | `21f9c18af3104a9126ffe2a507a580d12b19abc5d0548800f7cea7af0e0c191c` |
| `fuzz/corpus/network_decode/ipv4-options-truncated.hex` | IPv4 declares a 28-byte header but ends after two option bytes. | Retain only complete fields and diagnose the missing declared header bytes. | `db215c74cb71d87573c282a80bc8a04d4b3255970208faf08654f102a762f3cf` |
| `fuzz/corpus/network_decode/ipv4-fragment.hex` | IPv4 first fragment with More Fragments set and eight authored payload bytes. | Expose fragment metadata without synthesizing or reassembling another packet. | `be79e93967529495911148f58a0b2d667657fa88654f7dae709212f4b98738c6` |
| `fuzz/corpus/network_decode/ipv4-checksum-invalid.hex` | Complete IPv4 header whose checksum differs by one bit from the authored valid value. | Emit bounded checksum validation metadata while preserving the packet. | `0635aa5333f1c603008da75e06999b44122745c83da0210d10dcbcb6793e9078` |
| `fuzz/corpus/network_decode/ipv6-extension-valid.hex` | IPv6 packet with one eight-byte Hop-by-Hop extension and four authored payload bytes. | Traverse the declared extension and expose the terminal experimental next-header value. | `6da1c02e23ad190f5e84ab806e8c268049e64d48f2fa6eb7a09271cc177dfe43` |
| `fuzz/corpus/network_decode/ipv6-extension-malformed.hex` | Destination Options header claims 16 bytes inside an eight-byte IPv6 payload. | Diagnose contradictory extension length without leaving the declared payload. | `353798da1a66fa838c37990bd44d4f35600e1e1340503bb4e4ba2c611fe51b8f` |
| `fuzz/corpus/network_decode/ipv6-extension-truncated.hex` | IPv6 declares an eight-byte Routing header but only four bytes were captured. | Diagnose truncation and stop traversal at the captured boundary. | `4fbcf2eb07415cbf448244e0c3c444202e52f63b58928e94e3830947a0af5bf1` |
| `fuzz/corpus/network_decode/ipv6-fragment.hex` | IPv6 non-initial fragment with offset one, More Fragments set, and an authored identifier. | Expose fragment metadata, stop further next-header traversal, and perform no reassembly. | `79e7a40c8fcdb58a89cf2f24910609f21e33e5318bc275f3965755dbe0731460` |
| `fuzz/corpus/network_decode/ipv6-extension-depth-limit.hex` | IPv6 contains nine chained Destination Options headers. | Decode eight headers, then emit the bounded unsupported-chain marker and `RESOURCE_LIMIT` warning at the ninth selector. | `3253e141e9d9f2e21218cc72878f212f02c43812bce71779d618a35513ff80f5` |
| `fuzz/corpus/network_decode/tcp-options-valid.hex` | IPv4/TCP header with valid checksums and a 20-byte sequence of MSS, NOP, Window Scale, SACK Permitted, and Timestamp options. | Traverse only the data-offset-bounded option area and retain each common option without allocating from attacker-controlled lengths. | `e4fb67471217177f5a88617b7eb1f34c26a09fc28ec0df14f67956fa1c7b97d1` |
| `fuzz/corpus/network_decode/tcp-options-malformed.hex` | IPv4/TCP header whose MSS option declares the invalid length three. | Retain bounded option evidence, emit one structured malformed finding, continue only within the data-offset-bounded header, and suppress checksum/application handoff. | `0c307512d94b0043c907b9721699189a9173176a885779ae46e627cbc48d5935` |
| `fuzz/corpus/network_decode/udp-length-invalid.hex` | IPv4/UDP header whose UDP length is 65,535 inside an eight-byte network payload. | Reject the enclosing-length contradiction without using bytes outside the IP payload or allocating from the declared UDP length. | `f2753efd23150a1bc7e8cb971b5652232abc7aa1f6bee70e6e5f96b14b847f45` |

The target constructs one valid Ethernet packet inside either legacy PCAP or PCAPNG, exercises an
early cancellation, and separately drives the same bounded packet to a terminal result. Valid IP
seeds reach TCP, UDP, ICMP, and ICMPv6 through the same production handoff, so mutations exercise
transport lengths and option traversal without a second parser implementation. Successful imports
must validate the canonical dataset, keep every layer, field, byte value, and diagnostic range
within the packet, and stay within the decoder-wide layer, field, child-reference, vocabulary,
diagnostic, string, capture, and block ceilings. Corpus replay is per-PR smoke protection; scheduled
mutation campaigns provide the deeper hostile-input search.
