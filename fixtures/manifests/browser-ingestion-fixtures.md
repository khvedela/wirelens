# Browser-ingestion fixture provenance

- **Created:** 2026-07-26
- **Source:** WireLens-authored deterministic generators; no observed network traffic was used.
- **License:** WireLens repository license (MIT).
- **Sensitivity:** synthetic and non-sensitive.
- **Generator:** `apps/web/tests/support/capture-fixtures.mjs`
- **CLI:** `apps/web/tests/support/generate-capture-fixtures.mjs`
- **Detailed matrix:** `apps/web/tests/support/FIXTURES.md`

The generator covers all four classic PCAP magic values, both PCAPNG byte orders, bounded small and
medium success paths, a configurable near-cap success path, malformed/truncated/resource-exhaustion
inputs, and a sparse logical file used only for the `>=500 MiB` pre-read admission guard. Payloads
repeat the authored byte `0x42`; where room permits, frames begin with locally administered synthetic
Ethernet addresses and an IPv4 EtherType. No names, public addresses, credentials, or user-provided
capture content are present.

Generated binary captures are never committed. Output is restricted to an operating-system temporary
directory. Each run writes `fixture-manifest.json` containing every fixture's purpose, exact logical
size, expected outcome, deterministic recipe and recipe digest, plus a SHA-256 digest for each
materialized file. The sparse size guard records its recipe digest without reading its zero-filled
logical extent merely to hash it.

Smoke regeneration:

```sh
node apps/web/tests/support/generate-capture-fixtures.mjs
```

Qualifying supported-path regeneration:

```sh
node apps/web/tests/support/generate-capture-fixtures.mjs \
  --supported-large-target 240MiB
```

The default 8 MiB profile is functional smoke data, not qualifying performance evidence. The 240 MiB
requested profile materializes the largest whole-record fixture below the accepted 256 MiB boundary.
The sparse `>=500 MiB` file proves early rejection only and must never be described as a successful
large import.
