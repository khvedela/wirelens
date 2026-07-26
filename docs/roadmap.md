# WireLens roadmap

WireLens is planned in evidence-driven phases. Dates are intentionally unset until the architecture spike establishes feasible boundaries and measurable performance targets.

## M0 — Foundation

Validate architecture, engineering constraints, toolchains, repository/workspace boundaries, and the testing, fixture, fuzzing, and benchmark strategy.

## v0.1 — Offline Packet Viewer

Import PCAP/PCAPNG locally, define the canonical data model and Wasm boundary, decode essential protocols, and inspect packets in a responsive browser interface.

## v0.2 — Flow Analysis

Reconstruct bidirectional flows, explain TCP connection state, compute timing and traffic metrics, and build evidence-linked conversation models.

## v0.3 — Investigation Experience

Complete filtering, visual investigation, persistence/export, accessibility, performance, parser hardening, threat modeling, documentation, and release automation.

## v0.4 — Live Capture

After the offline product is stable, design a minimal native Rust agent, authenticated local stream protocol, and bounded live investigation mode.

## v1.0 — eBPF Observability

Evaluate Aya/eBPF for defensible Linux process/container network attribution and proceed only if the research demonstrates useful signal, acceptable compatibility, bounded overhead, and a sound privacy model.

## Dependency sequence

Architecture constraints → workspace boundaries → parser selection → packet model → Wasm boundary → browser ingestion → protocol decoders → flow analysis → investigation UX → hardening → optional live capture → optional eBPF.

Links to the actual GitHub Project and epic issues will be added after issue creation.
