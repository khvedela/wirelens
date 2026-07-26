# Capture importer fuzz corpus provenance

- **Created:** 2026-07-26
- **Source:** WireLens-authored synthetic byte sequences; no observed network traffic was used.
- **License:** WireLens repository license (MIT).
- **Encoding:** Files ending in `.hex` contain a literal `hex:` prefix followed by hexadecimal bytes. The fuzz target decodes this representation before import. The `.txt` seed is passed through as literal bytes.
- **Regeneration:** The committed text is the canonical deterministic source. Copying a file byte-for-byte reproduces its importer input; ASCII whitespace after `hex:` is ignored by the decoder.

| Seed | Intent | SHA-256 of committed text file |
| --- | --- | --- |
| `fuzz/corpus/capture_import/legacy-empty.hex` | Minimal little-endian PCAP global header with no records. | `8f630f27a297036063c11df937345b86c221e19934d5d23fcc3c37d5f0fdd3b6` |
| `fuzz/corpus/capture_import/legacy-one-packet.hex` | Minimal PCAP header plus one four-byte synthetic packet. | `1dd350b9ae795a9706ffdbb061e0de15a75413d90aced525fa59633dae4ef574` |
| `fuzz/corpus/capture_import/pcapng-empty.hex` | Minimal little-endian PCAPNG section header. | `48da3cc42e630a2c7097d7faca2c529ebecb5fe6e7d38b03fc91ddad44173f4d` |
| `fuzz/corpus/capture_import/pcapng-interface.hex` | Minimal PCAPNG section plus an Ethernet interface description. | `d7c59c2fe6ee52916188c6e07dde486d7140defb4ea5e7c302766168204f7981` |
| `fuzz/corpus/capture_import/pcapng-truncated.hex` | Deliberately truncated PCAPNG section header. | `5427187a509d19c798be4b95cb7da2472c891b8df0a1bca5a290335797d1c380` |
| `fuzz/corpus/capture_import/plain-invalid.txt` | Short non-capture input for header rejection. | `776929b32f5bc5a27e7e0fc809dc605d042186f1881ea03a979a5b31a2903708` |

The only packet payload is the four-byte sequence `00 01 02 03`. The corpus contains no names, addresses, credentials, or user-provided capture content.
