# Changelog

All notable changes to `dock-prune-daemon` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-23

### Security
- Pinned all GitHub Actions workflow dependencies across CI, Release, Release Drafter, and OpenSSF Scorecard to immutable 40-character commit SHAs.
- Enforced explicit top-level read-only `GITHUB_TOKEN` permissions in `.github/workflows/ci.yml`.

### Documentation
- Upgraded `README.md` with direct prebuilt binary download (`releases/latest`), `go install` quick start, `docker system prune` comparison matrix, and sample CLI output.
- Fixed table column wrapping on `verify-audit` and synchronized `CHANGELOG.md` release history.

## [0.1.0] - 2026-11-23

### Added
- **Zero-Dependency Core:** Pure Go 1.23 standard-library runtime (`CGO_ENABLED=0`, no `require` directives in `go.mod`, no `go.sum`).
- **Docker Engine Client:** HTTP-over-Unix/TCP transport with API version negotiation, 3-state circuit breaker, and resilient NDJSON `/events` streaming.
- **Predictive Disk Control:** Block & inode hysteresis watermarks paired with Holt-Winters double-exponential Time-To-Exhaustion (TTE) forecasting and Z-score anomaly detection.
- **Kernel-Aware Pacing:** Linux PSI I/O stall throttling and `/proc` phantom deleted-file descriptor scanning.
- **5-Stage Surgical Waterfall & OCI DAG Planner:** Forensic log truncation, stopped container cleanup, BuildKit retention floor, OCI layer DAG image reclamation, and opt-in anonymous volume pruning with immunity rules.
- **Tamper-Evident Audit & Telemetry:** Ed25519-signed SHA-256 Merkle JSONL ledger with `ChainAnchor` rotation, HMAC-SHA256 webhooks, OpenMetrics endpoint, embedded SSE dashboard, and FinOps ROI tracker.
- **8 CLI Subcommands & Production Manifests:** `daemon`, `once`, `explain`, `top`, `doctor`, `roi`, `verify-audit`, `version`, distroless `Dockerfile`, hardened `systemd` unit, and SLSA v1.0 multi-arch release pipeline.

[Unreleased]: https://github.com/PedroMartinezag/dock-prune-daemon/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/PedroMartinezag/dock-prune-daemon/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/PedroMartinezag/dock-prune-daemon/releases/tag/v0.1.0
