# Protocol decoding support

WireLens decodes packet bytes locally from the one immutable capture allocation. Decoders receive
borrowed, packet-bounded slices and emit checked absolute byte ranges into the canonical layer and
field arenas. They do not depend on WebAssembly, browser, or UI types.

## Implemented protocols

### Link and neighbor layers

| Input | Decoded facts | Current boundary |
| --- | --- | --- |
| `LINKTYPE_ETHERNET` (`1`) | Ethernet II destination/source MAC addresses and EtherType | Header must be complete before scalar fields are emitted |
| IEEE 802.1Q (`0x8100`) | One VLAN tag: TPID, PCP, DEI, VID, and encapsulated EtherType | Exactly one customer tag; stacked and provider tags are not interpreted |
| ARP (`0x0806`) over Ethernet/IPv4 | Hardware/protocol types and lengths, request/reply operation, sender and target hardware/protocol addresses | Ethernet hardware type, IPv4 protocol type, lengths 6/4, and operations 1/2 |

### Network layers

| Input | Decoded facts | Current boundary |
| --- | --- | --- |
| IPv4 (`0x0800`) | Fixed header, DSCP/ECN, lengths, identification, flags and fragment offset, TTL, Protocol, checksum field and validity, addresses | IHL 5–15; at most 40 option bytes; EOL, NOP, and generic type/length/data options only |
| IPv6 (`0x86dd`) | Fixed header, traffic class, flow label, payload length, Next Header, hop limit, addresses | The complete 40-byte fixed header is required before extension traversal |
| IPv6 Hop-by-Hop, Routing, Fragment, AH, and Destination Options | Ordered extension facts, terminal Next Header, fragment offset/more-fragments/identifier, visible AH fields | At most eight extension headers and 512 cumulative extension bytes |
| IPv6 ESP | Visible SPI, sequence number, and opaque protected remainder | Terminal structured unsupported result; security-association-dependent remainder, trailer, and Next Header semantics are not inferred |

IPv4 options are not given semantics beyond safe generic traversal. Non-initial IPv6 fragments stop
next-header traversal after their Fragment header; first and atomic fragments may continue. IPv4
and IPv6 fragment metadata is retained, but packets are never reassembled.
IPv6 jumbograms stop at a visible structured unsupported marker. Recursive IP-in-IP decoding,
routing-header final-destination semantics, and IPsec processing are deferred rather than guessed.

Numeric IPv4 Protocol and terminal IPv6 Next Header selectors reach a single bounded handoff with
exact captured payload evidence, declared length, and fragment position. TCP, UDP, ICMP, ICMPv6,
and DNS are intentionally left uninterpreted until their later Epic 3 issues; no transport layer is
claimed merely from an IP selector or port-shaped bytes.

## Evidence and recovery rules

- Every layer and decoded field refers to a checked half-open range in the original capture.
- Address values retain byte references; packet bytes are not copied into strings or secondary
  payload buffers.
- Truncated or contradictory headers produce structured packet diagnostics and stop only the
  affected protocol path. Capture framing remains available.
- A network path emits at most one prioritized diagnostic. Actionable length, structure, and
  truncation conditions outrank checksum caveats so hostile packets cannot exhaust the diagnostic
  arena with one warning per failed check.
- IPv4 header checksum validity is evidence metadata, not a certainty claim. An invalid value emits
  a warning that explicitly notes capture offload as a possible explanation.
- Reaching an IPv6 traversal cap emits a visible unsupported-chain marker and a resource-limit
  warning. ESP is visible but terminal because its protected remainder, trailer, and Next Header
  semantics depend on security-association state that is outside the decoder.
- Unsupported link types remain visible in interface metadata without invented packet-byte evidence.
  Unknown EtherTypes remain visible in the exact Ethernet type field and their payload is left
  uninterpreted. IEEE 802.3 length framing, provider tags, and stacked VLAN tags produce bounded
  unsupported encapsulation facts. WireLens does not guess a protocol from payload shape or ports.
- Arena growth is limited both per packet and per dataset. The browser/Wasm caps and their admission
  accounting are recorded in [ADR-0007](architecture/adr-0007-wasm-boundary-contract.md). The
  fixed small-capture allowance covers 1,024 copies of each current decoder-wide componentwise
  maximum. Exhausting a decoded arena above that baseline is transactional and fatal: WireLens
  publishes no partially decoded dataset because the canonical model has no decode-coverage marker.
  A coverage-aware or lazy strategy is tracked separately in
  [issue #57](https://github.com/khvedela/wirelens/issues/57).

## Verification and fixture provenance

Decoder changes require table tests, malformed and truncated cases, property tests over hostile
lengths and type values, synthetic PCAP/PCAPNG integration tests, fuzz-corpus replay, and a
directional benchmark. The committed corpora are generated test data under the repository license;
their construction and hashes are documented in the
[link decoder fixture manifest](../fixtures/manifests/protocol-decode-fuzz-corpus.md) and focused
[network decoder fixture manifest](../fixtures/manifests/network-decode-fuzz-corpus.md).

No private, proprietary, or captured network traffic is accepted as a test fixture.
