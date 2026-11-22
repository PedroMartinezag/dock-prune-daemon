# dock-prune-daemon

[![CI](https://github.com/PedroMartinezag/dock-prune-daemon/actions/workflows/ci.yml/badge.svg)](https://github.com/PedroMartinezag/dock-prune-daemon/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/PedroMartinezag/dock-prune-daemon/badge)](https://scorecard.dev/viewer/?uri=github.com/PedroMartinezag/dock-prune-daemon)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat)](go.mod)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-2EA44F?style=flat)](go.mod)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat)](LICENSE)

Autonomous, zero-dependency Go daemon and CLI for surgical Docker disk reclamation. Replaces blind `docker system prune` cron jobs with OCI layer DAG math, Holt-Winters ENOSPC forecasting, Linux PSI I/O pacing, and tamper-evident Ed25519 audit ledgers.

## Core Capabilities

- **Zero External Dependencies:** Pure Go standard library (`CGO_ENABLED=0`, no `require` directives in `go.mod`, no `go.sum`).
- **Predictive Hysteresis Control:** Block and inode watermark bands paired with Holt-Winters double-exponential Time-To-Exhaustion (TTE) forecasting.
- **OCI Layer DAG Planner:** Calculates exclusive reclaimable bytes across shared image layers before deletion to preserve hot CI caches.
- **Kernel-Aware Safety:** Throttles reclamation under Linux PSI I/O pressure and detects phantom deleted-but-open file descriptors in `/proc`.
- **Cryptographic Compliance:** Every cycle is recorded in an Ed25519-signed SHA-256 Merkle JSONL ledger with offline verification (`verify-audit`) and HMAC-SHA256 webhooks.
- **Observability & FinOps:** Loopback OpenMetrics server (`127.0.0.1:9402`), embedded SSE dashboard, and storage/incident ROI tracking.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the control-loop diagram, watermark invariants, and 5-stage waterfall design.

## Quick Start

### Build from Source

```bash
git clone https://github.com/PedroMartinezag/dock-prune-daemon.git
cd dock-prune-daemon
make build
./bin/dock-prune-daemon version
```

### Dry-Run Inspection

```bash
# Inspect host readiness, Docker API negotiation, PSI availability, and phantom FDs
./bin/dock-prune-daemon doctor

# Simulate one reclamation cycle without deleting resources
./bin/dock-prune-daemon once --dry-run --force --json
```

## CLI Subcommands

| Subcommand | Purpose |
| :--- | :--- |
| `daemon` | Run the autonomous event-driven and periodic control plane with exclusive PID locking and `SIGHUP` hot-reload. |
| `once` | Execute a single reclamation evaluation (`--dry-run`, `--force`, `--json`). |
| `explain` | Evaluate active watermarks, Holt-Winters forecast, and protection rules without mutating state. |
| `top` | Rank Docker images and containers by exclusive reclaimable bytes via OCI DAG analysis. |
| `doctor` | Run host diagnostics across Docker Engine API, `statfs`, Linux PSI, and phantom FDs. |
| `roi` | Report reclaimed storage, averted ENOSPC incidents, and FinOps cost savings. |
| `verify-audit` | Cryptographically verify the SHA-256 Merkle chain and Ed25519 signatures of `audit.jsonl`. |
| `version` | Print immutable build provenance (`Version`, `Commit`, `BuildDate`, `zero_external_deps`). |

## Configuration & Deployment

Configuration merges in strict precedence order: **Defaults -> JSON file (`--config` / `DPD_CONFIG_FILE`) -> `DPD_*` Environment -> CLI Flags**.

Production templates are ready in [`deploy/`](deploy/):
- [`deploy/config.production.json`](deploy/config.production.json) — validated baseline policy with hysteresis watermarks and immunity labels.
- [`deploy/dock-prune-daemon.service`](deploy/dock-prune-daemon.service) — hardened Linux `systemd` unit supporting `systemctl reload` (`SIGHUP`).
- [`deploy/docker-compose.yml`](deploy/docker-compose.yml) & [`Dockerfile`](Dockerfile) — static distroless container deployment.

## Supply-Chain Verification

Official release archives include `SHA256SUMS` and **SLSA v1.0 Build Provenance** attestations:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify dock-prune-daemon_linux_amd64.tar.gz --owner PedroMartinezag
```

## Contributing & Security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests (all changes must keep zero external dependencies and pass `gofmt`, `go vet`, `go test -race`, fuzzing, and `golangci-lint v2`).
- Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Support

If `dock-prune-daemon` saves your team storage costs or prevents production ENOSPC outages, consider supporting ongoing maintenance via [GitHub Sponsors](https://github.com/sponsors/PedroMartinezag).

## License

Licensed under the [Apache License 2.0](LICENSE).
