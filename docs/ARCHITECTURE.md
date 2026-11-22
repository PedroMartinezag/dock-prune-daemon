# Architecture

`dock-prune-daemon` replaces blind `docker system prune` cron jobs with a closed-loop, kernel-aware storage control plane written strictly in the Go standard library.

## High-Level Control Loop

```text
Docker /events (NDJSON) ──┐
                          ├──► Daemon Coordinator (PID lock + SIGHUP atomic config)
Periodic Statfs Probe ────┘           │
                                      ▼
                     Disk Pressure & Holt-Winters TTE
                   (Block + Inode Hysteresis Regimes)
                                      │
                                      ▼
                       Linux PSI I/O Stall Pacer
                 (Throttles stages; bypassed only in PANIC)
                                      │
                                      ▼
                        5-Stage Surgical Waterfall
                     (OCI Layer DAG + Immunity Filters)
                                      │
               ┌──────────────────────┼──────────────────────┐
               ▼                      ▼                      ▼
     Ed25519 Merkle Ledger    HMAC-SHA256 Webhook    OpenMetrics & SSE UI
```

## Pressure Regimes & Hysteresis

To prevent reclaim oscillation, `internal/config` enforces strict monotonic ordering:

- `preemptive_percent <= target_percent < high_percent < critical_percent < panic_percent`
- `panic_free_bytes <= min_free_bytes`
- `inode_target_percent < inode_high_percent < inode_critical_percent`

Reclamation stops as soon as disk utilization drops below `target_percent` and free space exceeds `min_free_bytes` (unless escalated by inode pressure or Holt-Winters TTE crossing the forecast horizon).

## 5-Stage Surgical Waterfall

Stages execute in ascending order of blast radius and halt immediately once the target watermark is satisfied:

1. **Container Log Truncation:** Truncates oversized JSON container logs above `max_container_log_bytes` while recording a forensic SHA-256 digest before truncation.
2. **Stopped Containers & Dangling Artifacts:** Removes eligible exited containers and untagged dangling images older than `min_resource_age`.
3. **Build Cache Retention Floor:** Trims BuildKit cache while preserving hot layers up to `build_cache_keep_bytes` to protect CI build latency.
4. **OCI Layer DAG Image Pruning:** Builds a directed acyclic graph of shared OCI layer `diff_ids` (`internal/graph`) to prioritize images with the highest *exclusive* reclaimable bytes per deletion.
5. **Anonymous Unreferenced Volumes (Opt-in):** Disabled by default (`enable_volume_prune: false`); only removes unreferenced anonymous volumes when explicitly enabled.

All stages strictly enforce `protected_labels`, `protected_image_patterns`, and `protected_container_prefixes`.

## Kernel Safety & Forensic Auditability

- **Linux PSI I/O Pacing (`internal/kernel/psi.go`):** Reads `/proc/pressure/io` and applies exponential stage backoff when host I/O stall exceeds `psi_io_budget_percent`.
- **Phantom FD Detection (`internal/kernel/phantom.go`):** Scans `/proc/*/fd` for large deleted-but-open files that hold disk blocks hostage after pruning.
- **Ed25519 Merkle Audit Ledger (`internal/audit/`):** Every cycle is canonicalized, SHA-256 hash-chained to `prev_hash`, domain-signed with Ed25519, and `fsync`-flushed to `audit.jsonl`. Rotated files begin with a signed `chain_anchor` so `verify-audit` detects silent head-truncation.
- **Lock-Free Hot Reload (`internal/config/config.go`):** Active configuration lives in an `atomic.Pointer[Config]`; `SIGHUP` validates the new profile before swapping, leaving the running state untouched on error.
