# Changelog

All notable changes to `dock-prune-daemon` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Zero-Dependency Core:** Pure Go 1.23 standard-library runtime (`CGO_ENABLED=0`, no external modules in `go.mod`, no `go.sum`).
- **Docker Engine Client:** HTTP-over-Unix/TCP transport with API version negotiation, 3-state circuit breaker, and resilient NDJSON `/events` streaming.
- **Predictive Disk Control:** Block & inode hysteresis watermarks (`preemptive`, `target`, `high`, `critical`, `panic`) combined with Holt-Winters double-exponential Time-To-Exhaustion (TTE) forecasting and Z-score anomaly detection.
- **Kernel-Aware Pacing:** Linux PSI I/O stall throttling and `/proc` phantom deleted-file descriptor scanning.
- **5-Stage Surgical Waterfall & OCI DAG Planner:** Forensic container log truncation (SHA-256 tail digests), stopped container cleanup, shared-layer OCI DAG image reclamation, build cache retention floor, and opt-in anonymous volume pruning with label/pattern/prefix immunity.
- **Tamper-Evident Audit & Telemetry:** Ed25519-signed SHA-256 Merkle JSONL ledger with `ChainAnchor` rotation, HMAC-SHA256 webhooks, OpenMetrics endpoint, embedded SSE dashboard, and FinOps ROI tracker.
- **8 CLI Subcommands:** `daemon`, `once`, `explain`, `top`, `doctor`, `roi`, `verify-audit`, and `version`.
- **Production Deployment & Supply Chain:** Multi-stage distroless `Dockerfile`, hardened `systemd` unit with `SIGHUP` hot-reload, Docker Compose manifest, GitHub Actions CI (`gofmt`, `go vet`, `-race`, fuzzing, `golangci-lint v2`), OpenSSF Scorecard, and SLSA v1.0 multi-arch release pipeline.
