# DNS decoder fuzz corpus provenance

- **Created:** 2026-07-27
- **Source:** WireLens-authored, deterministic synthetic DNS byte sequences. No observed,
  captured, user-provided, private, or proprietary traffic was used.
- **Redistribution:** Every byte is generated synthetic data and is redistributable under the
  WireLens repository license (MIT).
- **Encoding:** Each `.hex` file contains a literal `hex:` prefix, a one-byte framing selector,
  and at most 4 KiB of DNS message bytes. ASCII whitespace after the prefix is ignored.
- **Regeneration:** The committed text is the canonical deterministic source. The `dns_decode`
  target adds transport, IPv4, Ethernet, and legacy-PCAP framing at runtime; no packet capture is
  stored in the corpus.
- **Synthetic identities:** Runtime Ethernet addresses are locally administered
  `02:00:00:00:00:01` and `02:00:00:00:00:02`. IPv4 addresses are documentation-only
  `192.0.2.1` and `198.51.100.2`. The source port is `53000` and the destination port is DNS `53`.
  Authored names use the reserved example domain `example.com`.

The selector's low two bits choose deterministic transport framing; higher bits are ignored during
mutation:

| Selector | Runtime framing |
| ---: | --- |
| `0` | One IPv4 UDP datagram whose length exactly bounds the supplied DNS bytes; the valid optional IPv4 UDP checksum value zero is used. |
| `1` | One IPv4 TCP segment containing a two-byte DNS length equal to the supplied message length. |
| `2` | One complete IPv4 TCP segment whose DNS length is one byte shorter than the supplied non-empty message, leaving trailing segment data. |
| `3` | One complete IPv4 TCP segment whose DNS length is one byte longer than the supplied message, modeling a frame split across segments. |

The target computes the IPv4 header checksum and the complete TCP pseudo-header checksum after
framing. It drives the production `LinkLayerDecoder` through `CaptureImporter`, including an early
cancellation path and a separate terminal import. A successful terminal dataset must validate the
canonical model, contain no more than the advertised decoder-wide layer/field/child ceilings, keep
every layer, field, byte value, and diagnostic range inside its packet, and retain at most one
prioritized packet diagnostic.

| Seed | DNS intent | Expected bounded behavior | SHA-256 of committed text file |
| --- | --- | --- | --- |
| `fuzz/corpus/dns_decode/valid-compressed-response.hex` | UDP response for `www.example.com` with a backward owner-name pointer and one synthetic `192.0.2.10` A record. | Decode one question and answer, expand the prior-name pointer, and retain exact evidence without copying raw RDATA. | `9845614b9ae70bbc4cd44554ca0415ed98f46fb575cc158a2317f99acb502861` |
| `fuzz/corpus/dns_decode/backward-pointer-chain.hex` | Three questions: literal `a.com`, a pointer to it, and a pointer to the prior pointer. | Traverse a finite, strictly backward compression chain and terminate within the configured hop/name budgets. | `2422baefc47c4e6ee299f4e6c01111c46577eaf76e5e7df50ffd043c1724dd39` |
| `fuzz/corpus/dns_decode/self-pointer.hex` | A question name at offset 12 points back to its own first byte. | Reject the compression cycle with one structured malformed finding and no loop. | `df87f890841b90e752b9cb71233aca0341bf05030048071ab7f3102b4752685e` |
| `fuzz/corpus/dns_decode/forward-pointer.hex` | A question name points forward to a later root octet. | Reject a non-prior compression target without following it or reading out of bounds. | `c7c71657e4a4c8f2af73fb7e65d1a100315189a6149ba38b060cdb2b2f076e51` |
| `fuzz/corpus/dns_decode/out-of-bounds-pointer.hex` | A question contains the maximum 14-bit compression offset in a much shorter message. | Reject the target before dereference and retain bounded diagnostic evidence. | `f77e20555bc1c726de15286325dfd5dee3402166561a82f9fa39d08efc4a5c61` |
| `fuzz/corpus/dns_decode/rdlength-overrun.hex` | An A record declares four RDATA bytes but carries only two. | Reject the message-length contradiction without allocating from or reading through `RDLENGTH`. | `040932ef425b95204692be7a56fe634efdf0144c954ee0c6b5e055d9034e9727` |
| `fuzz/corpus/dns_decode/excessive-counts.hex` | The header declares 17 questions and supplies no section data. | Apply the configured question/count ceiling before entering an attacker-controlled loop. | `43fd7bf731b2954cb8823360832e67c94c6aebdc512f5787f084ddd8e5f58ec7` |
| `fuzz/corpus/dns_decode/unknown-record.hex` | One unknown type `65400` record with three opaque RDATA bytes. | Preserve the unknown RDATA as one bounded byte reference without type-specific interpretation. | `e42ce019037fa3640822047d59f2fb16949260cebd8e63f1f81854df57a594a2` |
| `fuzz/corpus/dns_decode/exact-tcp-frame.hex` | A complete length-prefixed TCP query for `fuzz.example.com`. | Decode the single segment-local frame while keeping the compression base at the DNS header rather than the TCP prefix. | `fe5909bac0e6ee3e284256158619f52d8def305e3c61fb65a68f99af4c78e411` |
| `fuzz/corpus/dns_decode/partial-tcp-frame.hex` | The TCP DNS prefix declares one byte beyond the captured segment payload. | Leave the candidate uninterpreted without a false capture-truncation claim; stream reassembly is out of scope. | `edb825c3ddfa54ea001572f7e7c9e24049f56f9a53f892298a6e60ee15d9655d` |
| `fuzz/corpus/dns_decode/trailing-tcp-frame.hex` | The TCP DNS prefix declares one byte less than the supplied segment payload. | Leave non-exact single-frame payload uninterpreted rather than guessing at pipelined or mid-stream data. | `36bb5cd4741b1536fd3538ef41233bcd87c1fa104e4b33c6074d6130284bace3` |

Per-PR corpus replay is deterministic smoke protection. The scheduled bounded mutation campaign
uses the same target and corpus for deeper exploration of names, pointers, counts, record lengths,
transport selection, and TCP framing.
