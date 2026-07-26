# Protocol decoder fuzz corpus provenance

- **Created:** 2026-07-26
- **Source:** WireLens-authored, deterministic synthetic byte sequences. No observed, captured, user-provided, private, or proprietary network traffic was used.
- **Redistribution:** Every byte is generated synthetic data and is redistributable under the WireLens repository license (MIT).
- **Encoding:** Each `.hex` file contains a literal `hex:` prefix followed by hexadecimal bytes. The `protocol_decode` fuzz target decodes this representation before import; ASCII whitespace after the prefix is ignored.
- **Regeneration:** The committed text is the canonical deterministic source. Copying a file byte-for-byte reproduces its fuzz input.
- **Synthetic identities:** Ethernet addresses use the locally administered `02:00:00:00:00:01` and `02:00:00:00:00:02` values. IPv4 addresses use documentation-only TEST-NET-1 values `192.0.2.1` and `192.0.2.2`.

| Seed | Protocol intent | Expected bounded behavior | SHA-256 of committed text file |
| --- | --- | --- | --- |
| `fuzz/corpus/protocol_decode/legacy-ethernet-arp-request.hex` | Little-endian PCAP containing one Ethernet II ARP request. | Decode destination/source MAC, EtherType, ARP header, sender, and target fields with exact source ranges. | `12af703512e92ec6c4263601d2010978a8f7f1f1449b15c8efef71aca671483f` |
| `fuzz/corpus/protocol_decode/pcapng-vlan-arp-reply.hex` | Little-endian PCAPNG containing one Ethernet II frame with a single 802.1Q VLAN tag (VID 100) and an ARP reply. | Decode Ethernet, one VLAN tag, inner EtherType, and ARP without copying packet bytes. | `46e9078ad8efa00d554dfe56e7491fbb922b4a808c58b1d5a7074213582dd759` |
| `fuzz/corpus/protocol_decode/legacy-ethernet-truncated.hex` | Complete PCAP record containing only ten Ethernet bytes. | Emit a structured truncation diagnostic without panic or out-of-bounds access. | `18e97c8c20db24867e30ac30c769a0d5c37242a142981d07cf4fa1a4ed4f7e90` |
| `fuzz/corpus/protocol_decode/legacy-vlan-truncated.hex` | Complete PCAP record ending after the 802.1Q tag control field. | Preserve the bounded Ethernet/VLAN evidence and diagnose the missing encapsulated EtherType. | `eeea0fe86f3036d8ba3e153a8626e1354d9ee0b89b5ff4b5ce53c4a55d0c46d1` |
| `fuzz/corpus/protocol_decode/pcapng-ethernet-arp-truncated.hex` | Complete PCAPNG record containing Ethernet plus only six ARP header bytes. | Diagnose the truncated ARP operation/address portion and remain deterministic. | `c8670eee52ea943cde08ce71ac457a5c2d26460bbe3813d575a46dbe71e250b8` |
| `fuzz/corpus/protocol_decode/legacy-arp-malformed-lengths.hex` | Ethernet ARP frame declaring hardware and protocol address lengths of 255. | Reject impossible address extents through checked arithmetic and bounded diagnostics. | `cfa84b7b4f0d651214cc72d27c77c0e82b2ef584267cbada01c35e18e3df681a` |
| `fuzz/corpus/protocol_decode/legacy-unsupported-ethertype.hex` | Ethernet II frame with authored unknown EtherType `0x88b5`. | Preserve the exact numeric EtherType and leave its payload uninterpreted without guessing a decoder. | `6259da221f4fe9a6ca637229b71b4a0b19123138bc833716fc2abd2cf05c590e` |
| `fuzz/corpus/protocol_decode/legacy-unsupported-stacked-vlan.hex` | Ethernet II frame whose single supported 802.1Q tag encapsulates another VLAN tag. | Stop at the documented single-tag boundary and report stacked VLAN as unsupported. | `3db3934cb261db63bf07a0cd33be8d77b70d01ab86cca884d07c812fcb471d31` |
| `fuzz/corpus/protocol_decode/legacy-unsupported-ieee8023.hex` | Ethernet header using an IEEE 802.3 length value instead of an Ethernet II EtherType. | Report unsupported encapsulation without interpreting the payload as Ethernet II. | `24bb9e0bfb3f5e700686570285f246f2a8e67e21daeb0bb668d3996f8b2c0bd3` |

The target applies strict capture, block, decoded-item, diagnostic, and string limits; exercises cancellation; drives each accepted input to a terminal result; and re-validates the canonical dataset. Corpus replay is intended for per-PR smoke protection, while mutation-based campaigns remain bounded scheduled work. The corpus contains no real identities, names, credentials, content, or user packet data.
