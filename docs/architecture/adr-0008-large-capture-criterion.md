# ADR-0008: reconcile the large-capture criterion with the v1 Wasm boundary

- **Status:** proposed; open architecture decision
- **Date:** 2026-07-26
- **Decision follow-up:** [#55](https://github.com/khvedela/wirelens/issues/55)
- **Implementation evidence:** [#10](https://github.com/khvedela/wirelens/issues/10)
- **Related:** ADR-0001, ADR-0003, and ADR-0007
- **Supersedes:** nothing while proposed

## Context

ADR-0001 defines a large capture as at least 500 MB for its responsiveness, throughput, and memory
criteria. In particular, it requires zero main-thread parsing/filtering tasks over 50 ms on that
path. ADR-0003 adds a 50 MB/s ingest target, a 200 ms median cancellation target, and a 2.5-times
browser/worker/Wasm memory envelope.

The accepted ADR-0007 boundary has a hard v1 limit of 256 MiB for one capture. It accepts one complete
input, then Rust owns that allocation for the importer and resulting dataset. A capture at or above
ADR-0001's 500 MB criterion is therefore rejected before a v1 import can begin. Browser ingestion
work in issue #10 cannot demonstrate a successful 500 MB import without changing the accepted
ownership and resource contract.

Calling a smaller fixture "large" would hide the conflict. Treating fast size rejection as import
throughput or successful-path responsiveness would also be misleading.

## Proposed resolution

Keep two evidence scenarios distinct for issue #10:

1. A successful supported-path fixture below the 256 MiB boundary, with 240 MiB recommended for the
   qualifying reference run. Measure file acquisition, main-thread long tasks, cancellation, ingest
   throughput, cleanup, and browser/worker/Wasm memory on that path.
2. A synthetic logical file of at least 500 MiB used only to verify that the browser rejects the file
   from its size and negotiated capabilities before reading the full body or allocating Wasm import
   state. Measure safe error presentation and responsiveness, but do not report import throughput or
   successful-path memory from this scenario.

Under this proposal, issue #10 may complete its explicit picker, drag-and-drop, validation, progress,
cancellation, safe-error, supported-fixture responsiveness, and zero-upload criteria. Its evidence
must say that the supported-path measurements do **not** satisfy ADR-0001's L2 large-capture
criterion. ADR-0001's large-path L2/T1/M1 claims remain open.

Before WireLens v0.1 claims those criteria, a separately reviewed architecture change must choose one
of these directions:

- raise the boundary ceiling and revalidate complete-input ownership, allocation admission,
  cancellation, and retained-memory budgets on a successful capture of at least 500 MB; or
- introduce a bounded streaming/file-backed ingress and dataset-storage contract, then revalidate the
  Wasm API and parser lifetimes; or
- amend ADR-0001's product criterion to an explicitly supported maximum based on product requirements
  and measured evidence.

The follow-up must update the relevant accepted ADRs. This proposed record does not itself supersede
or weaken ADR-0001 or ADR-0007.

## Evidence rules if adopted

- Generate fixtures deterministically in temporary storage; commit recipes and provenance, never the
  large binary files.
- Run the successful supported-path evidence against a production module worker.
- Require zero main-thread long tasks over 50 ms during the measured Chromium import window.
- Require median cancellation acknowledgement at or below 200 ms.
- Require effective ingest and index throughput of at least 50 MB/s on the documented reference
  profile, while labelling the fixture size exactly.
- Require browser plus worker plus Wasm memory at or below 2.5 times the exact input size, with browser
  sampling and source-inspected allocation accounting reported separately.
- Require exact logical resource cleanup after cancellation, failure, and explicit dataset disposal.
- Run picker, drop, validation, error, cancellation, and zero-upload behavior in Chromium and Firefox.
- State explicitly that a pre-read 500 MiB rejection is not a successful import measurement.

## Consequences

- Issue #10 can test the full browser workflow within the accepted v1 resource contract without
  inventing support that the boundary does not provide.
- Oversized files fail before expensive reads or Wasm allocation.
- Product documentation cannot claim ADR-0001's 500 MB large-capture success criteria until the open
  architecture decision is resolved and evidence exists.
- A future streaming design remains intentional architecture work rather than an accidental extension
  of ADR-0007's bounded-step parser.

## Rejected shortcuts

- **Rename a sub-256 MiB fixture as the ADR-0001 large fixture:** rejected because it changes the
  criterion without an architecture decision.
- **Count 500 MiB size rejection as successful-path evidence:** rejected because parsing and indexing
  never occur.
- **Raise the constant only in browser code:** rejected because ownership, memory, parser admission,
  cancellation, and Wasm limits must move together.
- **Claim physical zero-copy File handling:** rejected because browser engines do not expose every
  implementation copy and the Rust boundary explicitly performs an admitted input copy.
