# Security Policy

## Supported Versions

Security fixes and supply-chain advisories are provided for the latest minor release line of `dock-prune-daemon`.

| Version | Supported |
| :--- | :--- |
| `main` / latest `v0.x` | Yes |
| Older `v0.x` releases | No |

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities.

Report vulnerabilities privately through GitHub Security Advisories:

- **Private Advisory Portal:** `https://github.com/PedroMartinezag/dock-prune-daemon/security/advisories/new`

When reporting, include:
1. Affected version, OS/architecture, and deployment mode (`systemd`, container, or CLI).
2. Minimal reproduction steps or proof-of-concept configuration/input.
3. Observed impact (unauthorized deletion, ledger tampering bypass, credential leak, or denial of service).

You can expect an initial acknowledgement within **72 hours** and coordinated disclosure once a fix is verified.

## Security Architecture & Operational Hardening

### 1. Zero External Dependencies
- The repository enforces a strict zero-third-party-module contract (`go.mod` contains no `require` directives and no `go.sum` exists), verified on every CI run and release build.
- Release binaries are compiled statically (`CGO_ENABLED=0 -trimpath`) using only the Go standard library.

### 2. Docker Socket & Host Isolation
- Access to `/var/run/docker.sock` is effectively root-equivalent on the host. Run the daemon under the sandboxed `deploy/dock-prune-daemon.service` unit rather than an unrestricted root shell.
- Keep `prune.enable_volume_prune` set to `false` unless anonymous volume pruning is explicitly approved, and protect critical workloads with `prune.protected_labels`, `prune.protected_image_patterns`, and `prune.protected_container_prefixes`.

### 3. Telemetry Control Plane & Secret Redaction
- By default, the telemetry HTTP server binds strictly to loopback (`127.0.0.1:9402`).
- If exposing telemetry beyond localhost, place it behind TLS and configure a high-entropy `DPD_TELEMETRY_BEARER_TOKEN`.
- Secrets (`telemetry.bearer_token`, `audit.webhook_hmac_secret`) are masked with `[REDACTED]` in status APIs and config dumps.

### 4. Ed25519 Merkle Audit Ledger & Key Material
- Store `ed25519.key` inside a restricted `state_dir` (`0750` directory, `0600` private key).
- Copy `ed25519.pub` to an independent host or SIEM to run `dock-prune-daemon verify-audit` offline.
- Outbound audit webhooks support `HMAC-SHA256` signing via `DPD_WEBHOOK_HMAC_SECRET`.

## Verifying Release Artifacts

Every official release archive ships with `SHA256SUMS` and **SLSA v1.0 Build Provenance** attestations:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify dock-prune-daemon_linux_amd64.tar.gz --owner PedroMartinezag
```
