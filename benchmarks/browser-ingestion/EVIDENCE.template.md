# Browser-ingestion evidence — template, not a completed claim

> Replace every `TBD` and check every assertion from generated test output before publishing. A
> supported-path result below 256 MiB does not satisfy ADR-0001's successful `>=500 MB` criterion.

## Environment

| Field | Value |
| --- | --- |
| Recorded at | TBD |
| Commit | TBD |
| Reference machine / CI runner | TBD |
| Production bundle command | TBD |
| Chromium version | TBD |
| Firefox version | TBD |
| Fixture manifest path and digest | TBD |

## Acceptance mapping

| Issue #10 criterion | Chromium evidence | Firefox evidence | Result |
| --- | --- | --- | --- |
| Accessible file picker | TBD | TBD | TBD |
| Accessible drag-and-drop and keyboard equivalent | TBD | TBD | TBD |
| PCAP/PCAPNG magic validation independent of filename/MIME | TBD | TBD | TBD |
| Wasm runs only in a production module worker | TBD | TBD | TBD |
| Separate monotonic read and parse progress | TBD | TBD | TBD |
| Cancellation before read, during read, and during parse | TBD | TBD | TBD |
| Safe malformed, truncated, unsupported, and resource-limit states | TBD | TBD | TBD |
| Main thread remains responsive on the supported fixture | TBD | TBD | TBD |
| Capture data is never uploaded | TBD | TBD | TBD |
| Failure/cancellation/reset return logical resources to baseline | TBD | TBD | TBD |

## Fixture matrix

| Scenario | Exact bytes | Records/blocks | Expected result | Observed result |
| --- | ---: | ---: | --- | --- |
| Small PCAP, all four magics | TBD | TBD | Success | TBD |
| Small PCAPNG, both byte orders | TBD | TBD | Success | TBD |
| Medium PCAP | TBD | TBD | Success | TBD |
| Medium PCAPNG | TBD | TBD | Success | TBD |
| Supported near-cap PCAP | TBD | TBD | Success below 256 MiB | TBD |
| Empty/short/random | TBD | TBD | Structured rejection | TBD |
| Truncated record | TBD | TBD | Success with bounded warning | TBD |
| Malformed PCAPNG | TBD | TBD | Structured malformed outcome | TBD |
| Dense/options/declared-size hostile inputs | TBD | TBD | Resource limit | TBD |
| ADR-0001 oversize guard | `>=500 MiB` | TBD | Resource limit before full read | TBD |

## Quantitative supported-path measurements

| Measurement | Result | Gate |
| --- | ---: | ---: |
| Supported fixture size | TBD | `<256 MiB` |
| Effective file-read + ingest + index throughput | TBD | `>=50 MB/s` |
| Main-thread long tasks attributable to import | TBD | `0 tasks >50 ms` |
| Median cancellation acknowledgement | TBD | `<=200 ms` |
| Browser + worker + Wasm sampled/modelled peak | TBD | `<=2.5x input` |
| Largest worker-to-main binary response | TBD | `<=8 MiB` |
| Live imports/datasets/cursors after cancellation | TBD | Exact baseline |
| Live imports/datasets/cursors after failure | TBD | Exact baseline |
| Live resources after explicit reset/disposal | TBD | Exact baseline |

Chromium's qualifying memory result must use `measureUserAgentSpecificMemory` in a cross-origin-
isolated production page. Do not substitute a main-realm heap-only value. Report browser sampling,
Wasm high-water allocation, and source-inspected full-input copy accounting as separate measurements.
Firefox functional responsiveness may use a recorded animation-frame/timer heartbeat because it does
not expose Chromium's qualifying memory source or Long Tasks API.

## Oversize pre-read rejection

- Logical fixture size: TBD (`>=500 MiB` required)
- Bytes read before rejection: TBD
- Wasm import handles allocated: TBD (expected `0`)
- Main-thread tasks over 50 ms during rejection: TBD
- User-facing error category: TBD (expected resource limit)

This section proves size admission and safe UX only. It is not import throughput, successful-path
memory, or ADR-0001 L2/T1/M1 evidence.

## Privacy audit — both browsers required

| Audited channel after worker readiness | Chromium | Firefox | Gate |
| --- | ---: | ---: | ---: |
| HTTP(S) requests | TBD | TBD | `0` |
| External requests | TBD | TBD | `0` |
| Body-bearing requests | TBD | TBD | `0` |
| WebSocket channels | TBD | TBD | `0` |
| Raw-capture persistent-storage writes | TBD | TBD | `0` |
| Uncaught page/worker/console errors | TBD | TBD | `0` |

Record how service workers were blocked/absent and how post-ready requests were audited. Initial
same-origin production assets and the fingerprinted Wasm request must finish before the import audit
checkpoint.

## Claim boundary

- [ ] The report calls the successful fixture by its exact byte size.
- [ ] The report does not say that a sub-256 MiB fixture satisfies ADR-0001's `>=500 MB` path.
- [ ] The report describes the 500 MiB fixture as pre-read rejection only.
- [ ] Fixture provenance confirms no observed/private capture data.
- [ ] Chromium and Firefox production-bundle behavior passed.
- [ ] Any missed gate has a linked follow-up rather than a softened claim.
