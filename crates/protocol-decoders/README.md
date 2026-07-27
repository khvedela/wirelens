# Protocol decoders

This platform-neutral crate turns borrowed packet slices into bounded canonical
facts owned by `packet-core`. It has no browser, WebAssembly, networking, or UI
dependencies and never retains or copies packet payloads.

The v0.1 link scope is deliberately narrow: Ethernet II, one customer 802.1Q
tag (`0x8100`), and ARP request/reply for Ethernet plus IPv4 addresses. IEEE
802.3 length framing, provider or stacked VLAN tags, and unsupported ARP
variants remain structured and uninterpreted. Non-Ethernet link types remain
undecoded; their exact numeric value and evidence already live in
`InterfaceMetadata` rather than packet bytes. Unknown well-formed EtherTypes
remain visible in the exact enclosing type field without per-packet warnings.

The network scope covers IPv4 fixed headers, up to 40 IHL-bounded option bytes,
fragment metadata, and header-checksum validity. EOL, NOP, and generic
type/length/data options are retained without claiming option-specific
semantics. IPv6 fixed headers and common Hop-by-Hop, Routing, Fragment,
Authentication, and Destination Options headers are traversed up to eight
headers and 512 cumulative bytes. ESP exposes only its visible fixed fields and
opaque, security-association-dependent remainder as a terminal unsupported
result. IPv6 jumbograms stop at a visible structured unsupported marker rather
than applying ordinary 16-bit payload-length semantics.

Numeric IPv4 Protocol and terminal IPv6 Next Header selectors, exact captured
payload bounds, declared lengths, and fragment position reach one internal
bounded handoff. TCP decodes its fixed fields and data-offset-bounded common
options; UDP decodes its fixed header and length-bounded application payload;
ICMP and ICMPv6 decode their common header plus bounded fields for common
echo/error bodies. Complete, structurally sound checksum domains expose
validity metadata, including the IP pseudo-header for TCP, UDP, and ICMPv6.
Ambiguous routing destinations deliberately suppress checksum certainty.

Non-initial fragments never reach a transport-header decoder. First fragments
may expose a bounded transport header but never claim a complete checksum or
application payload; atomic IPv6 fragments are complete datagrams. The decoder
performs no fragment or TCP stream reassembly, congestion inference, recursive
ICMP quoted-packet decode, application decode, IPsec processing, or payload
copying. DNS remains a separate application-layer issue.

All test and benchmark packets in this crate are generated inline from protocol
constants and documentation-only address ranges. The focused network fuzz
corpus follows the same rule. These fixtures are synthetic, contain no captured
traffic, and may be redistributed under the repository license.
