# ADR-0004: capture-container framing library

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#7](https://github.com/khvedela/wirelens/issues/7)
- **Parent epic:** [#6](https://github.com/khvedela/wirelens/issues/6)

## Context

WireLens must frame legacy PCAP and PCAPNG capture containers locally in a platform-neutral Rust crate, then expose bounded results through a worker-centered Wasm boundary. Captures are hostile input. The selected library must preserve format metadata and byte references, support PCAPNG interfaces and sections, compile to `wasm32-unknown-unknown`, and avoid forcing packet payload copies before the explicit Rust-owned dataset allocation required by ADR-0001.

Container framing is deliberately separate from protocol decoding. This ADR does not choose Ethernet, IP, transport, or application protocol parsers.

## Candidates evaluated

| Candidate | PCAP / PCAPNG support | Ownership and streaming | Wasm probe | Decision |
| --- | --- | --- | --- | --- |
| `pcap-parser` 0.17.0 | Legacy PCAP plus PCAPNG blocks, sections, interfaces, and byte order | Borrowed block payloads; buffered readers support incremental consumption | `cargo check --target wasm32-unknown-unknown` passed | Chosen |
| `pcap-file` 2.0.0 | Legacy PCAP and PCAPNG read/parse APIs | Slice parser returns borrowed packets/blocks; reader API owns read buffers | `cargo check --target wasm32-unknown-unknown` passed | Viable alternative, not chosen |
| `pcap-file` 3.0.0-rc1 | Same stated format family | Pre-release at evaluation time | Not selected for a v0.1 dependency | Rejected |
| Project-owned framing | Could be constrained to v0.1 | Would add format, fuzzing, and compatibility ownership | Not justified while a maintained option satisfies requirements | Rejected |

Both selected candidates are permissively licensed: `pcap-parser` is MIT or Apache-2.0 and `pcap-file` 2.0.0 is MIT. `pcap-parser` declares Rust 1.65 minimum support; `pcap-file` did not declare an MSRV in its package metadata during this evaluation.

## Experiment and evidence

The reproducible, synthetic-only counting probe lives in [`benchmarks/parser/library-spike`](../../benchmarks/parser/library-spike). It creates small (100 packet), medium (50,000 packet), and truncated legacy-PCAP and PCAPNG fixtures, plus a big-endian legacy PCAP and PCAPNG fixture with two Ethernet interfaces. The PCAPNG fixture includes a section header, interface descriptions, and enhanced packet blocks. No packet capture is committed.

On the reference development machine (Apple Silicon macOS, Rust stable 1.97.1 for the Wasm probe), the release probe produced these directional results:

| Fixture | `pcap-file` | `pcap-parser` | Result |
| --- | ---: | ---: | --- |
| 50,000-packet PCAP (3.6 MiB) | 268 µs | 941 µs | Both counted 50,000 packets |
| 50,000-packet PCAPNG (4.4 MiB) | 795 µs | 1,065 µs | Both counted 50,001 post-section blocks |
| Truncated PCAP | `Need more bytes` | `Unexpected end of file` | Both returned an error without panic |
| Truncated PCAPNG | `Need more bytes` | `Unexpected end of file` | Both returned an error without panic |
| Big-endian PCAP | 1 packet | 1 packet | Both parsed the non-default byte order |
| Multi-interface PCAPNG | 3 post-section blocks | 3 post-section blocks | Both parsed two interface descriptions and a packet on interface 1 |

These results measure only in-memory framing/counting, not full WireLens ingest, allocations, browser transfer, or memory limits. They must not be used as product throughput claims. Both candidate dependencies and the probe compiled for `wasm32-unknown-unknown`.

## Decision

Use **`pcap-parser` 0.17.0** for capture-container framing in `packet-core`, pinned to an exact version when the workspace is initialized.

Adopt these integration rules:

1. Use its buffered reader APIs for incremental framing; do not require a whole capture to be parsed as one slice.
2. Treat emitted packet/block data as borrowed only for the reader callback/iteration step. `packet-core` copies capture bytes once into its Rust-owned dataset storage only when data must outlive that step, as required by ADR-0001.
3. Preserve PCAPNG section, interface identifier, link type, timestamp-resolution, and byte-range context in the canonical model. Do not infer a single capture-wide interface or timestamp resolution.
4. Convert library errors into WireLens structured diagnostics. A malformed or truncated record is a diagnostic and best-effort-continuation decision, never a panic.
5. Pin and periodically review the dependency; retain `pcap-file` 2.x as the evaluated fallback if an upstream compatibility or safety issue appears.

## Rationale

`pcap-parser` best matches the browser ownership plan: it explicitly supports zero-copy parsing, buffered incremental readers, and PCAPNG’s multiple sections/interfaces/endian variants. Its result was slower in the intentionally narrow in-memory probe, but the measured difference is not material evidence against the broader low-copy and streaming requirements. Selecting the pre-release `pcap-file` 3.x line would add avoidable version risk; selecting 2.x would be reasonable but offers less explicit fit to the required multi-section low-copy framing model.

## Consequences

- Issue #8 can model per-section and per-interface capture facts rather than assuming global link metadata.
- `packet-core` remains browser- and Wasm-independent; no parser result crosses directly into React.
- Initial implementation must add valid, malformed, truncated, mixed-endian, multi-interface, and multi-section synthetic fixtures with manifests before claiming full parser coverage.
- Issue #9 must document the one persistent Rust-owned capture allocation and bounded batch allocations; borrowed parser views must never escape into JavaScript.

## Follow-up risks

The initial probe does not yet cover mixed-endian **PCAPNG sections**, allocation profiling, or browser worker memory. Those are mandatory implementation verification cases for #8–#10 and must be added before their completion. This is an explicit evidence gap, not a claim of support without tests.
