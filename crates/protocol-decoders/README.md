# Protocol decoders

This platform-neutral crate turns borrowed packet slices into bounded canonical
facts owned by `packet-core`. It has no browser, WebAssembly, networking, or UI
dependencies and never retains or copies raw packet payloads. DNS names are the
deliberate exception for derived values: the decoder interns a bounded,
case-preserving escaped representation while every source field and raw RDATA
value continues to reference the immutable capture bytes.

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

Classic DNS dispatch is restricted to TCP or UDP packets whose source or
destination port is `53`. One complete UDP payload is one DNS message. TCP is
decoded only when one two-byte-length-prefixed DNS frame consumes the complete
captured TCP payload. Non-exact partial, trailing, and pipelined candidates
remain uninterpreted, and the resulting fact is segment-local rather than a
claim about TCP stream alignment because this crate performs no reassembly.
DNS exposes the header identifier, flags, query/response state, opcode,
four-bit header response code (base RCODE), section counts, questions, and
records from the answer, authority, and additional sections. Type-specific
RDATA is decoded for A, AAAA, NS, CNAME, SOA, PTR, MX, and TXT records; unknown
RDATA remains one borrowed byte range. OPT records are opaque in this version,
so EDNS extended response codes are not combined with the base RCODE. Those
v0.1 type-specific interpretations are restricted to the Internet class
(`IN`); records in other classes retain opaque RDATA because DNS record
semantics are selected by both type and class.

DNS work is bounded to 16 questions, 16 resource records total across all
three record sections, 64 decoded name occurrences, 16 compression-pointer
hops per name, and 16 TXT strings total per message. Labels and expanded names
also retain the DNS wire limits. Compression pointers must target a strictly
earlier, previously validated name boundary. Expanded names are interned in a
case-preserving escaped form under the capture-wide string budget; they are
never included in diagnostics or logs.

Non-initial fragments never reach a transport-header decoder. First fragments
may expose a bounded transport header but never claim a complete checksum or
application payload; atomic IPv6 fragments are complete datagrams. The decoder
performs no fragment or TCP stream reassembly, congestion inference, recursive
ICMP quoted-packet decode, IPsec processing, or unbounded payload copying.
Application protocols other than the explicitly bounded port-53 DNS path remain
uninterpreted.

All test and benchmark packets in this crate are generated inline from protocol
constants and documentation-only address ranges. The focused network fuzz
corpus and DNS message corpus follow the same rule. The directional DNS
benchmark also generates its messages in memory. These fixtures are synthetic,
contain no captured traffic, and may be redistributed under the repository
license.
