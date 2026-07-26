# Product vision

## Audience and primary job

WireLens is for networking students, developers, network engineers, and security learners who need to quickly understand what happened in a packet capture. Users should be able to progress from a capture overview to packet evidence, protocol fields, conversations, and explainable failure indicators without fighting a dated or opaque interface.

## Differentiator

The project aims to combine serious network analysis with modern frontend usability: fast search, clear hierarchy, cross-linked evidence, accessible visualizations, and explanations that distinguish observation from inference. It is not a simplified toy decoder; it should remain technically honest while lowering investigation friction.

## Privacy promise

Local analysis is the default and defining constraint. The offline application will not upload packet bytes. Persistence is explicit and local, derived-analysis export is preferred, and raw export requires a clear warning. Future live capture is optional, locally authenticated, and deferred until the offline model is stable.

## Educational value

WireLens should help learners connect raw bytes to headers, headers to flows, and flows to outcomes. Explanations will cite supporting packets, expose protocol state, communicate confidence, and avoid hiding important limitations behind a dashboard.

## Initial MVP

The first meaningful product imports PCAP and PCAPNG locally, decodes essential link/network/transport/DNS protocols, presents a responsive virtualized packet table, shows structured fields and corresponding bytes, supports practical search/filtering, and provides investigation summaries. Architecture, test strategy, safety, and performance budgets precede implementation.

## Long-term direction

After the offline product is reliable, WireLens may add a minimal native Rust capture agent that streams authenticated, bounded observations into the same investigation experience. Aya/eBPF research may later assess process and container attribution on Linux without making packet payload collection the default.

## Explicit non-goals

- Uploading captures for server-side processing or collaboration
- Full Wireshark protocol and filter-language parity in the initial releases
- Live capture, privileged installation, or eBPF in the offline MVP
- Decryption, intrusion-prevention actions, or automated incident-response claims
- Presenting heuristics as proven root causes
- Supporting every malformed, proprietary, or obscure encapsulation in v0.1
