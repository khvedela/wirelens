# Protocol decoding support

WireLens decodes packet bytes locally from the one immutable capture allocation. Decoders receive
borrowed, packet-bounded slices and emit checked absolute byte ranges into the canonical layer and
field arenas. They do not depend on WebAssembly, browser, or UI types.

## Implemented link and neighbor protocols

| Input | Decoded facts | Current boundary |
| --- | --- | --- |
| `LINKTYPE_ETHERNET` (`1`) | Ethernet II destination/source MAC addresses and EtherType | Header must be complete before scalar fields are emitted |
| IEEE 802.1Q (`0x8100`) | One VLAN tag: TPID, PCP, DEI, VID, and encapsulated EtherType | Exactly one customer tag; stacked and provider tags are not interpreted |
| ARP (`0x0806`) over Ethernet/IPv4 | Hardware/protocol types and lengths, request/reply operation, sender and target hardware/protocol addresses | Ethernet hardware type, IPv4 protocol type, lengths 6/4, and operations 1/2 |

IPv4, IPv6, transport protocols, and DNS are intentionally handled by later Epic 3 issues. Their
EtherType remains visible without claiming that their payload was decoded.

## Evidence and recovery rules

- Every layer and decoded field refers to a checked half-open range in the original capture.
- Address values retain byte references; packet bytes are not copied into strings or secondary
  payload buffers.
- Truncated or contradictory headers produce structured packet diagnostics and stop only the
  affected protocol path. Capture framing remains available.
- Unsupported link types remain visible in interface metadata without invented packet-byte evidence.
  Unknown EtherTypes remain visible in the exact Ethernet type field and their payload is left
  uninterpreted. IEEE 802.3 length framing, provider tags, and stacked VLAN tags produce bounded
  unsupported encapsulation facts. WireLens does not guess a protocol from payload shape or ports.
- Arena growth is limited both per packet and per dataset. The browser/Wasm caps and their admission
  accounting are recorded in [ADR-0007](architecture/adr-0007-wasm-boundary-contract.md). The
  fixed small-capture allowance covers 1,024 copies of the current decoder's largest structured
  result. Exhausting a decoded arena above that baseline is transactional and fatal: WireLens
  publishes no partially decoded dataset because the canonical model has no decode-coverage marker.
  A coverage-aware or lazy strategy is tracked separately in
  [issue #57](https://github.com/khvedela/wirelens/issues/57).

## Verification and fixture provenance

Decoder changes require table tests, malformed and truncated cases, property tests over hostile
lengths and type values, synthetic PCAP/PCAPNG integration tests, fuzz-corpus replay, and a
directional benchmark. The committed protocol corpus is generated test data under the repository
license; its construction and hashes are documented in the
[protocol decoder fixture manifest](../fixtures/manifests/protocol-decode-fuzz-corpus.md).

No private, proprietary, or captured network traffic is accepted as a test fixture.
