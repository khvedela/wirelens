# WireLens

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Inspect PCAP files locally, reconstruct network flows, and understand protocol behavior through a modern interactive interface.**

> **Status:** the capture model, production Wasm boundary, and user-facing local PCAP/PCAPNG importer are implemented. Packet decoding and the investigation interface are still under construction, so WireLens is not yet a complete packet analyzer.

## The problem

Packet captures contain decisive evidence, but extracting an explanation often requires dense desktop tools, specialist syntax, and careful manual correlation. Learners and experienced engineers alike need a faster way to move from individual frames to a defensible account of what happened.

## Product vision

WireLens will be a privacy-first network investigation application for networking students, developers, network engineers, and security learners. It will combine serious protocol analysis with a modern, searchable, visual investigation experience. The initial product will open `.pcap` and `.pcapng` captures in the browser and analyze them locally.

## Why Rust and WebAssembly

Rust is a strong fit for parsing untrusted binary input because it supports explicit ownership, predictable resource use, and memory-safe abstractions without a garbage collector. WireLens compiles its platform-neutral capture core to WebAssembly and runs it in a module Web Worker. Accepted architecture decisions define crate ownership, browser boundaries, the capture-framing library, canonical model, and reproducible worker/Wasm build contract. The current boundary’s throughput, memory, cancellation, transfer, and cleanup measurements are recorded in the [Wasm boundary evidence](benchmarks/wasm/boundary-harness/EVIDENCE.md). Browser file acquisition, responsiveness, privacy, and cancellation results are recorded separately in the [browser-ingestion evidence](benchmarks/browser-ingestion/EVIDENCE.md).

## Privacy first

Packet data can contain credentials, identifiers, private conversations, and proprietary topology. WireLens therefore adopts a local-processing principle: offline capture analysis must not upload packet bytes to a server. Persistence will be opt-in, raw-data export will require an explicit warning, and future live capture will be an optional, authenticated local capability.

## Planned capabilities

- PCAP and PCAPNG import
- Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, TCP, UDP, and DNS decoding
- Searchable, virtualized packet table and structured header inspection
- Raw-byte and decoded-field correlation
- Five-tuple flow reconstruction and TCP connection-state analysis
- Retransmission, reset, handshake, latency, and failure indicators with supporting evidence
- Traffic metrics, conversation timelines, sequence diagrams, and topology visualization
- Privacy-preserving offline operation
- A later native Rust live-capture agent
- Optional future Aya/eBPF-based Linux observability, where justified

## Implemented foundations

- A platform-neutral, bounded PCAP/PCAPNG importer that treats captures as hostile input and preserves exact source evidence.
- An immutable canonical capture/packet model with exact timestamps, byte ranges, diagnostics, sections, and interfaces.
- A versioned, generational-handle Wasm API with cooperative cancellation, monotonic progress, deterministic cleanup, structured warnings/errors, and bounded binary packet batches.
- A production module-worker harness that blocks external traffic and verifies detached binary transfers in Chromium and Firefox CI.
- An accessible React file picker and drag-and-drop importer that validates capture magic, reads and parses only in a module worker, reports separate read/parse progress, cancels cooperatively, and retains no raw capture in browser storage.
- Platform-neutral, bounded [Ethernet II, single-tag IEEE 802.1Q, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and port-53 DNS decoding](docs/protocol-decoding.md) with exact field-to-byte evidence, bounded option, extension, DNS-record, and compressed-name traversal, fragment metadata, checksum caveats, and structured recovery.
- A focused [raw-byte and decoded-field inspector](docs/raw-byte-correlation.md) with bounded packet-relative evidence paging, deterministic nested/overlap resolution, zero-length and truncation markers, and virtualized accessible field/hex navigation.

## Accepted v0.1 architecture

The offline dependency direction and runtime responsibilities are governed by the [accepted architecture decisions](docs/architecture/README.md).

```mermaid
flowchart TB
    User["User selects PCAP or PCAPNG"] --> Browser["React and TypeScript browser application"]
    Browser --> Worker["Web Worker"]
    Worker --> Wasm["Rust analysis core compiled to WebAssembly"]
    Browser --> DB["Opt-in IndexedDB session persistence"]
    Agent["Optional future native Rust capture agent"] -. "authenticated local stream" .-> Browser

    subgraph RustWorkspace["Rust workspace"]
        PacketCore["packet-core"]
        Decoders["protocol-decoders"]
        Flow["flow-engine"]
        Analysis["analysis-engine"]
        Adapter["wasm-adapter"]
        Capture["capture-agent"]
        CLI["CLI"]
    end

    Wasm --> Adapter
    Adapter --> Analysis
    Analysis --> Flow
    Flow --> Decoders
    Decoders --> PacketCore
```

## Repository structure map

```text
wirelens/
├── crates/                  # Rust workspace crates, added incrementally per ADR-0002
├── apps/
│   └── web/                 # React application, module worker, and browser acceptance tests
├── fixtures/                # Synthetic or explicitly redistributable captures
├── benchmarks/              # Parser, flow, Wasm, and UI performance fixtures
├── docs/                    # Product, architecture, and roadmap documentation
└── .github/                 # Contribution and issue templates
```

This structure governs ongoing repository and workspace initialization. See [ADR-0002](docs/architecture/adr-0002-repository-workspace-structure.md) for crate responsibilities, dependency direction, naming conventions, and boundary guardrails.

## Roadmap

Delivery is tracked in the public [WireLens Roadmap](https://github.com/users/khvedela/projects/4).

- **M0 — Foundation:** validate architecture, tooling, repository boundaries, and testing strategy in [Foundation and architecture](https://github.com/khvedela/wirelens/issues/1).
- **v0.1 — Offline Packet Viewer:** build local ingestion in [Capture ingestion and Rust/Wasm pipeline](https://github.com/khvedela/wirelens/issues/6) and essential decoding in [Protocol decoding](https://github.com/khvedela/wirelens/issues/11).
- **v0.2 — Flow Analysis:** reconstruct conversations and explain TCP behavior in [Flow reconstruction and network analysis](https://github.com/khvedela/wirelens/issues/17).
- **v0.3 — Investigation Experience:** complete the investigation workflow in [Investigation user experience](https://github.com/khvedela/wirelens/issues/23), then make it releasable in [MVP hardening and release](https://github.com/khvedela/wirelens/issues/30).
- **v0.4 — Live Capture / v1.0 — eBPF Observability:** pursue the explicitly deferred [Live capture and eBPF observability](https://github.com/khvedela/wirelens/issues/36) epic only after the offline product is stable.

Dates remain evidence-driven rather than speculative. See [the detailed roadmap](docs/roadmap.md) for issue-level sequencing.

## Non-goals for the first release

- Server-side upload, storage, or processing of packet captures
- Live packet capture or privileged native installation
- eBPF telemetry or process/container attribution
- Full parity with Wireshark's protocol coverage or display-filter language
- IPv4/IPv6 fragment reassembly, TCP payload reassembly, or decryption
- Multi-user collaboration or cloud synchronization
- Claiming heuristic conclusions as certainty

## Run the browser importer locally

Use the pinned Node.js, pnpm, and Rust toolchains, then build the local Wasm asset before starting
Vite:

```sh
cd apps/web
corepack pnpm install --frozen-lockfile
corepack pnpm run build:wasm
corepack pnpm run dev
```

Run the complete frontend gate—including Biome formatting/linting, deterministic fixture tests,
privacy checks, the production build, and Chromium/Firefox acceptance tests—with
`corepack pnpm run verify`. Qualifying near-cap evidence is intentionally separate; its exact
reproduction command is documented in
[`benchmarks/browser-ingestion/EVIDENCE.md`](benchmarks/browser-ingestion/EVIDENCE.md).

## Contributing

WireLens accepts issue-scoped implementation, research, documentation, and verification contributions. Read [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), and the accepted decisions plus open architecture questions before proposing changes. Scope changes should be discussed in an issue first.

## Security and responsible capture handling

Treat every packet capture as potentially sensitive and every parser input as untrusted. Never attach private captures to public issues. Use synthetic or explicitly redistributable fixtures, remove identifying data, and follow [SECURITY.md](SECURITY.md) for confidential reports.

## License

WireLens is available under the [MIT License](LICENSE).
