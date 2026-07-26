# Browser-ingestion evidence

Recorded 2026-07-26T20:33:13.962Z from the production bundle in full Chromium 150.0.7871.184. The fixture generator created only deterministic synthetic traffic in temporary storage; its runtime manifest SHA-256 was `54f305a78a624c1a373bc748be068b97b281560d05349fc847cafcecadbc8378`.

> This is the supported v1 path at exactly 250,613,512 bytes (239.00 MiB), below the accepted 256 MiB boundary. It does not satisfy or redefine ADR-0001's successful `>=500 MB` path. The separate sparse 500 MiB scenario proves pre-read rejection only.

## Reference profile

| Field | Value |
| --- | --- |
| Host | Apple M3 Pro; 11 logical CPUs; 18 GiB RAM |
| Platform | darwin / arm64 |
| Browser | Full Chromium 150.0.7871.184, cross-origin isolated |
| Fixture | 250,613,512 bytes, 1048576-byte synthetic payload records |
| Build | Pinned production Vite module-worker bundle; local Wasm asset |
| Source base revision | `0aee3332c3c24fd9883e175f4027de6aeb99329b` |
| Source-tree SHA-256 | `e79c71ce3d4b3af97d922cf0f02ce51ece0a16edad0a938440a87b6aebd05a96` |

## Quantitative supported-path result

| Measurement | Result | Gate | Status |
| --- | ---: | ---: | --- |
| Effective file-read + ingest + index throughput | 295.79 MiB/s | >=50 MiB/s | pass |
| Main-thread long tasks over 50 ms | 0 | 0 | pass |
| Main-thread heartbeat ticks during import | 205 | >0 | pass |
| Cancellation acknowledgement samples | 7.25, 6.70, 13.86, 6.70, 7.15, 6.26 ms | reading + parsing | pass |
| Cancellation acknowledgement median | 6.93 ms | <=200 ms | pass |
| Sampled attributable agent-cluster memory high-water | 1.02x input | <=2.5x | pass |
| Product-path source-modeled allocation envelope | 2.02x input | <=2.5x | pass |
| Worker-to-main binary response | 0 bytes | <=8 MiB | pass |

Chromium memory used `measureUserAgentSpecificMemory` across 31 agent-cluster samples. Idle baseline was 3,694,146 bytes; sampled absolute high-water was 258,989,042 bytes; attributable growth was 255,294,896 bytes. Because an asynchronous sampler cannot interrupt the worker's synchronous JavaScript-to-Wasm copy, the product-path model separately takes the maximum of: read assembly (254,807,816 bytes), the whole-input JavaScript-to-Rust overlap plus one admitted 4,194,304-byte slice (505,421,328 bytes), and the sampled parser logical upper bound (283,132,682 bytes). The resulting 505,421,328-byte envelope is 2.02x the exact input. The worker releases its chunk-assembled JavaScript input reference immediately after the admitted Wasm copy returns.

## Privacy and cleanup

| Check after worker readiness | Result | Gate |
| --- | ---: | ---: |
| HTTP(S) requests | 0 | 0 |
| Body-bearing requests | 0 | 0 |
| WebSocket channels | 0 | 0 |
| Page, worker, or console errors | 0 | 0 |
| Live imports after explicit reset | 0 | 0 |
| Live datasets after explicit reset | 0 | 0 |
| Live cursors after explicit reset | 0 | 0 |
| Retained logical bytes after explicit reset | 0 | 0 |
| Total logical upper bound after explicit reset | 0 | 0 |

The cross-browser production suite runs with service workers allowed and asserts zero registrations, IndexedDB databases, Cache Storage entries, local-storage entries, or session-storage entries. Static privacy checks also reject those APIs in product sources. The suite patches main-realm `File.prototype.arrayBuffer` to throw while a valid import succeeds, proving product code reads capture bytes only in the worker. Successful import retains exactly one dataset until the user resets; success, failure, reading cancellation, parsing cancellation, and reset return every live handle and retained/reserved logical-byte counter to baseline.

## Functional acceptance matrix

The pinned Playwright suite runs in Chromium and Firefox against the production bundle and covers:

- native picker and accessible drag/drop, including multiple-file rejection and same-file reselection;
- all four classic PCAP magics and both PCAPNG byte orders;
- misleading/missing extensions and MIME types, with magic authoritative;
- empty, short, random, truncated, malformed, declared-size, option-density, and packet-density hostile inputs;
- separate monotonic file-read and Rust-parse progress;
- cancellation during file acquisition and between bounded Wasm steps;
- exact logical cleanup after success, failure, cancellation, and reset;
- zero post-ready requests, WebSockets, raw-capture persistence, or service-worker control;
- keyboard semantics, live/alert regions, terminal focus, and 320 CSS-pixel reflow.

The sparse logical ADR-0001 guard is at least 500 MiB. Browser tests observe no `reading` or `parsing` state and zero Wasm import/dataset/cursor handles before the structured `resource_limit` result. That result is admission evidence, not successful-import performance evidence.

## Reproduction

```sh
cd apps/web
corepack pnpm install --frozen-lockfile
corepack pnpm run verify
WIRELENS_INGESTION_EVIDENCE_MIB=240 corepack pnpm run evidence
```

Generated captures remain in temporary or ignored test output. The compact qualifying JSON is committed beside this report so pull-request CI can reproduce the report, recheck every gate, and reject a stale source digest. Regenerate both artifacts after any file-ingestion, worker scheduling, Wasm-boundary, fixture, or measurement change.
