## Summary

- What changed and why?

## Verification

- [ ] `make verify-zero-dep` passes (no third-party modules in `go.mod`, no `go.sum`)
- [ ] `gofmt -l .` returns empty and `go vet ./...` passes
- [ ] `go test -race -count=1 ./...` passes
- [ ] `golangci-lint run ./...` passes with zero issues
- [ ] Documentation or deployment manifests updated if flags/config changed

## Risk & Rollback

- Potential operational impact (watermarks, Docker API calls, audit ledger schema):
