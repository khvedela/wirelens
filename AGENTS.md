# Guidance for coding agents

These rules apply to automated and human-assisted coding work in this repository.

- Read accepted architecture decisions before changing package, crate, process, or data boundaries.
- Preserve privacy-first local processing. Offline packet data must never be uploaded.
- Keep packet parsing and analysis independent from UI code and browser frameworks.
- Keep `packet-core` platform-neutral and usable without WebAssembly or frontend dependencies.
- Avoid unnecessary copying of packet buffers; document ownership and lifetime decisions.
- Keep parsing, filtering, and other expensive browser work off the main thread.
- Never commit copyrighted, private, proprietary, or sensitive packet captures.
- Use synthetic or explicitly redistributable fixtures and document their provenance.
- Add tests for every protocol-parsing change, including malformed and truncated inputs.
- Benchmark changes affecting parser, Wasm-boundary, or flow-engine performance.
- Run formatting, linting, tests, and build checks before declaring work complete.
- Do not silently broaden the v0.1 scope. Propose scope changes through an issue or architecture decision.
- Treat captures as hostile input: avoid panics, out-of-bounds access, unbounded allocation, and misleading certainty.
- Keep documentation and acceptance criteria synchronized with behavior; never claim unimplemented features work.
