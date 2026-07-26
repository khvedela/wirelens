# Protocol decoders

This platform-neutral crate turns borrowed packet slices into bounded canonical
facts owned by `packet-core`. It has no browser, WebAssembly, networking, or UI
dependencies and never retains or copies packet payloads.

The v0.1 link-layer scope is deliberately narrow: Ethernet II, one customer
802.1Q tag (`0x8100`), and ARP request/reply for Ethernet plus IPv4 addresses.
IEEE 802.3 length framing, provider or stacked VLAN tags, and unsupported ARP
variants remain structured and uninterpreted. Non-Ethernet link types remain
undecoded; their exact numeric value and evidence already live in
`InterfaceMetadata` rather than packet bytes.
Unknown well-formed EtherTypes remain visible in the exact enclosing type field
without producing packet-by-packet diagnostics.

All test and benchmark packets in this crate are generated inline from protocol
constants and documentation-only address ranges. They are synthetic, contain no
captured traffic, and may be redistributed under the repository license.
