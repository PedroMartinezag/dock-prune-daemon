# Contributing to dock-prune-daemon

Thank you for contributing to `dock-prune-daemon`. Every change must preserve the core architectural contract of the project: **zero external Go dependencies**, deterministic safety under disk pressure, and clean static compilation.

## Core Engineering Contract

1. **Zero External Dependencies:** Never add `require` entries to `go.mod` or commit a `go.sum` file. All features must use the Go standard library only.
2. **Hysteresis & Safety Invariants:** Never bypass watermark ordering, resource protection filters (`protected_labels`, `protected_image_patterns`, `protected_container_prefixes`), or the `--dry-run` simulation boundary.
3. **Cross-Platform Static Builds:** Changes must compile cleanly with `CGO_ENABLED=0` across `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`.
4. **Conventional Commits:** Prefix commit messages with `feat:`, `fix:`, `perf:`, `security:`, `docs:`, `test:`, `ci:`, or `chore:` so Release Drafter categorizes changes accurately.

## Local Verification Checklist

Before opening a pull request, run the full verification pipeline locally:

```bash
# 1. Verify zero-dependency contract
make verify-zero-dep

# 2. Formatting and static analysis
test -z "$(gofmt -l .)"
go vet ./...
golangci-lint run ./...

# 3. Race-enabled tests and fuzz smoke suite
go test -race -count=1 ./...
make fuzz-smoke

# 4. Static binary build
make build
```

## Pull Request Process

- Keep pull requests focused on a single concern and include unit or race tests covering edge cases.
- Update documentation (`docs/ARCHITECTURE.md`, `README.md`, or `deploy/`) when adding flags, environment variables, or metrics.
- Ensure all 5 GitHub Actions CI gates pass before requesting review.
