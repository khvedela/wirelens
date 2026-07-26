# Capture framing-library spike

This reproducible, synthetic-only spike compares capture-container framing candidates for issue [#7](https://github.com/khvedela/wirelens/issues/7). It is not production ingestion code.

Generate fixtures outside the repository, then run the comparable packet/block-count probe:

```sh
node generate-fixtures.mjs /tmp/wirelens-library-spike
cargo run --release -- pcap /tmp/wirelens-library-spike/medium.pcap
cargo run --release -- pcapng /tmp/wirelens-library-spike/medium.pcapng
cargo run --release -- pcap /tmp/wirelens-library-spike/truncated.pcap
cargo run --release -- pcapng /tmp/wirelens-library-spike/truncated.pcapng
```

The fixtures contain repeated synthetic 60-byte payloads; no captured traffic is committed. The matrix includes small and medium inputs, truncated inputs, a big-endian legacy PCAP, and a PCAPNG input with two interfaces. The medium fixtures contain 50,000 packets and are intended only for relative candidate comparison. Run the Wasm compatibility check with the Rust toolchain that owns the installed target:

```sh
RUSTC="$(rustup which --toolchain stable rustc)" cargo check --target wasm32-unknown-unknown
```

Record machine details and output with any new result. The ADR records the initial decision evidence and explicitly treats timing as directional, not a product performance claim.
