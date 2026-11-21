// Package buildinfo exposes compile-time provenance and runtime platform metadata
// injected via Go linker flags (-ldflags) during reproducible release builds.
package buildinfo

import (
	"fmt"
	"runtime"
	"strings"
)

// Build-time variables overridden by -ldflags in Makefile and CI release pipelines.
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info represents immutable binary provenance and runtime architecture details.
type Info struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	BuildDate        string `json:"build_date"`
	GoVersion        string `json:"go_version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	Compiler         string `json:"compiler"`
	ZeroExternalDeps bool   `json:"zero_external_deps"`
}

// Get returns a snapshot of the binary's build and runtime metadata.
func Get() Info {
	return Info{
		Version:          cleanOrDefault(Version, "0.1.0-dev"),
		Commit:           cleanOrDefault(Commit, "unknown"),
		BuildDate:        cleanOrDefault(BuildDate, "unknown"),
		GoVersion:        runtime.Version(),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		Compiler:         runtime.Compiler,
		ZeroExternalDeps: true,
	}
}

// UserAgent returns a deterministic HTTP User-Agent header value used for
// Docker Engine API negotiation and outbound HMAC-signed audit webhooks.
func UserAgent() string {
	info := Get()
	return fmt.Sprintf("dock-prune-daemon/%s (%s/%s; zero-dep)", info.Version, info.OS, info.Arch)
}

// Summary formats build provenance as a concise single-line human-readable banner.
func Summary() string {
	info := Get()
	return fmt.Sprintf(
		"dock-prune-daemon v%s (commit=%s, built=%s, go=%s, platform=%s/%s, zero-dep=true)",
		info.Version,
		info.Commit,
		info.BuildDate,
		info.GoVersion,
		info.OS,
		info.Arch,
	)
}

func cleanOrDefault(raw, fallback string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}
