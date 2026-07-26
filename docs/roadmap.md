# WireLens roadmap

WireLens is planned in evidence-driven phases. Dates are intentionally unset until the architecture spike establishes feasible boundaries and measurable performance targets.

## M0 — Foundation

Validate architecture, engineering constraints, toolchains, repository/workspace boundaries, and the testing, fixture, fuzzing, and benchmark strategy in [EPIC 1 — Foundation and architecture](https://github.com/khvedela/wirelens/issues/1).

## v0.1 — Offline Packet Viewer

Import PCAP/PCAPNG locally and define the canonical data model and Wasm boundary in [EPIC 2 — Capture ingestion and Rust/Wasm pipeline](https://github.com/khvedela/wirelens/issues/6). Decode essential protocols and preserve byte-level evidence in [EPIC 3 — Protocol decoding](https://github.com/khvedela/wirelens/issues/11).

## v0.2 — Flow Analysis

Reconstruct bidirectional flows, explain TCP connection state, compute timing and traffic metrics, and build evidence-linked conversation models in [EPIC 4 — Flow reconstruction and network analysis](https://github.com/khvedela/wirelens/issues/17).

## v0.3 — Investigation Experience

Complete filtering, visual investigation, persistence/export, and accessibility in [EPIC 5 — Investigation user experience](https://github.com/khvedela/wirelens/issues/23). Complete performance, parser hardening, threat modeling, documentation, and release automation in [EPIC 6 — MVP hardening and release](https://github.com/khvedela/wirelens/issues/30).

## v0.4 — Live Capture

After the offline product is stable, design a minimal native Rust agent, authenticated local stream protocol, and bounded live investigation mode in [EPIC 7 — Live capture and eBPF observability](https://github.com/khvedela/wirelens/issues/36).

## v1.0 — eBPF Observability

Continue [EPIC 7](https://github.com/khvedela/wirelens/issues/36) by evaluating Aya/eBPF for defensible Linux process/container network attribution. Proceed only if research demonstrates useful signal, acceptable compatibility, bounded overhead, and a sound privacy model.

## Dependency sequence

Architecture constraints → workspace boundaries → parser selection → packet model → Wasm boundary → browser ingestion → protocol decoders → flow analysis → investigation UX → hardening → optional live capture → optional eBPF.

Status, priority, size, risk, and target metadata are maintained in the public [WireLens Roadmap GitHub Project](https://github.com/users/khvedela/projects/4).
