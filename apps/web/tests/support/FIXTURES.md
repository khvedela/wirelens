# Browser-ingestion synthetic fixture manifest

Repository-level provenance is recorded in
[`fixtures/manifests/browser-ingestion-fixtures.md`](../../../../fixtures/manifests/browser-ingestion-fixtures.md).

All fixtures produced by this support package are authored synthetic data. They contain no observed,
private, proprietary, or third-party network traffic. The only repeated payload content is the byte
`0x42`, preceded where space permits by two locally administered synthetic Ethernet addresses and an
intentionally unsupported authored EtherType `0x88b5`. Protocol correctness uses separate valid
frames. The fixtures are covered by the repository's MIT license.

- **Created:** 2026-07-26
- **Source:** WireLens-authored deterministic generator in this directory
- **License:** MIT (WireLens repository license)
- **Sensitivity:** synthetic/non-sensitive; no observed traffic
- **Regeneration:** run the pinned-Node command below into OS temporary storage

Binary fixtures are never committed. The generator only accepts an output directory below the
operating system's temporary directory and writes `fixture-manifest.json` alongside the generated
files. That runtime manifest records the exact recipe, logical size, expected outcome, recipe digest,
and a SHA-256 digest for every materialized file. The sparse 500 MiB size-guard fixture records a
recipe digest instead of reading its entire zero-filled logical extent solely to calculate a file
digest.

Run the smoke-sized set with the pinned Node.js runtime:

```sh
node apps/web/tests/support/generate-capture-fixtures.mjs
```

Generate the recommended near-cap supported fixture explicitly:

```sh
node apps/web/tests/support/generate-capture-fixtures.mjs \
  --supported-large-target 240MiB
```

The default supported-large target is deliberately only 8 MiB so local functional tests remain
cheap. It is not near-cap performance evidence. The 240 MiB setting remains below the v1 256 MiB
Wasm boundary limit. The sparse `adr-0001-oversize-guard.pcap` is at least 500 MiB and exists only to
prove pre-read resource-limit handling; it is not evidence of a successful 500 MiB import.

## Generated matrix

| Fixture | Intent | Expected outcome |
| --- | --- | --- |
| `small-pcap-little-microseconds.pcap` | Little-endian legacy microsecond magic | Success |
| `small-pcap-big-microseconds.pcap` | Big-endian legacy microsecond magic | Success |
| `small-pcap-little-nanoseconds.pcap` | Little-endian legacy nanosecond magic | Success |
| `small-pcap-big-nanoseconds.pcap` | Big-endian legacy nanosecond magic | Success |
| `small-pcapng-little.pcapng` | Little-endian PCAPNG section | Success |
| `small-pcapng-big.pcapng` | Big-endian PCAPNG section | Success |
| `medium.pcap` | Multi-step PCAP read and parse | Success |
| `medium.pcapng` | Multi-step PCAPNG read and parse | Success |
| `supported-large.pcap` | Successful path below 256 MiB | Success |
| `empty.capture` | Empty input | Structured rejection |
| `short-pcap-magic.pcap` | Three-byte legacy prefix | Truncated capture |
| `random-magic.capture` | Deterministic non-capture magic | Unsupported format |
| `truncated-pcap-header.pcap` | Partial legacy global header | Truncated capture |
| `truncated-pcap-record.pcap` | Valid header and incomplete record body | Success with warning |
| `truncated-pcapng-section.pcapng` | Incomplete section header | Truncated capture |
| `malformed-pcapng-bom.pcapng` | Invalid PCAPNG byte-order magic | Malformed capture |
| `malformed-pcapng-footer.pcapng` | Mismatched PCAPNG block lengths | Structured diagnostic |
| `oversized-declared-pcap-record.pcap` | Record above the 4 MiB ceiling | Resource limit |
| `oversized-declared-pcapng-block.pcapng` | Block above the 4 MiB ceiling | Resource limit |
| `option-dense-pcapng.pcapng` | 4,097 decoded option items in one block | Resource limit |
| `dense-packet-admission.pcap` | 4,096 zero-length records in about 64 KiB | Proportional resource limit |
| `adr-0001-oversize-guard.pcap` | Sparse logical file at least 500 MiB | Resource limit before read |

The generator source and runtime manifest are the canonical provenance. If a recipe changes, tests
and evidence must regenerate fixtures rather than checking in generated packet-capture files.
