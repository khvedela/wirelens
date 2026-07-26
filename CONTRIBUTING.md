# Contributing to WireLens

Thank you for helping build a privacy-first network investigation tool. WireLens is currently in planning and architecture; application implementation should wait until the relevant architecture decisions and issues are ready.

## Before you start

1. Read the [product vision](docs/product/product-vision.md), [architecture questions](docs/architecture/README.md), [roadmap](docs/roadmap.md), and [agent guidance](AGENTS.md).
2. Search existing issues and discuss substantial scope or boundary changes before writing code.
3. Work from an issue with clear acceptance criteria. Keep pull requests focused and link the issue.

## Development principles

- Preserve local processing: offline captures must not be uploaded.
- Treat captures and decoded values as untrusted and potentially sensitive.
- Keep parsing and analysis independent of UI and browser frameworks.
- Prefer synthetic or explicitly redistributable packet fixtures with documented provenance.
- Add correctness tests for parsing changes and benchmarks for performance-sensitive changes.
- Keep browser analysis off the main thread and avoid unnecessary packet-buffer copies.

## Changes and review

Use Conventional Commit-style messages where practical. Before requesting review, run the formatting, linting, tests, security checks, and builds defined by the repository at that time. Explain performance and privacy/security impact in the pull-request template. Do not include credentials, private captures, or generated dependency directories.

## Reporting security issues

Do not open a public issue for a vulnerability or attach a sensitive capture. Follow [SECURITY.md](SECURITY.md).
