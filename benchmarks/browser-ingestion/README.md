# Browser-ingestion acceptance evidence

This directory owns issue #10 evidence for browser `File` acquisition, user-facing ingestion,
main-thread responsiveness, cancellation, cleanup, and zero-upload behavior. It is intentionally
separate from `benchmarks/wasm/boundary-harness`, which measures the lower-level Rust/Wasm contract
implemented by issue #9.

Use the deterministic fixture generator documented in
`apps/web/tests/support/FIXTURES.md`. Generated captures, traces, and intermediate browser output
belong in operating-system temporary storage or ignored test output and must never be committed.

[`EVIDENCE.md`](EVIDENCE.md) records the latest qualifying supported-path run. Its compact,
machine-readable measurements are committed as [`EVIDENCE.json`](EVIDENCE.json); pull-request CI
recomputes the runtime-source digest, revalidates every quantitative gate, and reproduces the Markdown
exactly from that JSON.
`EVIDENCE.template.md` remains a claim checklist for future runs. Preserve exact fixture sizes and
browser versions whenever the completed report is regenerated.

The proposed ADR-0008 records an unresolved conflict: ADR-0001 defines its large path at 500 MB or
more, while the accepted v1 boundary rejects captures above 256 MiB. A successful supported-path
measurement below 256 MiB and a responsive 500 MiB pre-read rejection are different results. Neither
may be presented as proof of a successful ADR-0001 large import.
