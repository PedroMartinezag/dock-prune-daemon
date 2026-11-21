// Package kernel provides zero-dependency Linux kernel introspection for
// Pressure Stall Information (/proc/pressure) adaptive I/O pacing and
// ProcFS (/proc/[pid]/fd) unlinked open file descriptor forensics.
package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

const maxPSIFileBytes = 16 << 10

// PressureLine represents a single 'some' or 'full' line from /proc/pressure/*.
type PressureLine struct {
	Avg10       float64 `json:"avg10"`
	Avg60       float64 `json:"avg60"`
	Avg300      float64 `json:"avg300"`
	TotalMicros uint64  `json:"total_micros"`
}

// PSISnapshot captures instantaneous Linux kernel I/O and memory stall percentages.
type PSISnapshot struct {
	Supported bool         `json:"supported"`
	SampledAt time.Time    `json:"sampled_at"`
	IOSome    PressureLine `json:"io_some"`
	IOFull    PressureLine `json:"io_full"`
	MemSome   PressureLine `json:"mem_some"`
	MemFull   PressureLine `json:"mem_full"`
}

// EffectiveIOStall returns the composite 10-second stall signal, weighting 'full'
// system stalls higher than 'some' task stalls because 'full' indicates zero non-idle
// CPU progress while waiting on block device queues.
func (s PSISnapshot) EffectiveIOStall() float64 {
	if !s.Supported {
		return 0
	}
	weightedFull := s.IOFull.Avg10 * 1.5
	eff := math.Max(s.IOSome.Avg10, weightedFull)
	// Factor in severe memory reclaim thrashing (swap/pagecache pressure).
	if s.MemFull.Avg10 > eff {
		eff = s.MemFull.Avg10
	}
	if eff > 100.0 {
		return 100.0
	}
	return eff
}

// ParsePSI parses the standard Linux kernel /proc/pressure/{io,memory} text format.
func ParsePSI(raw string) (some PressureLine, full PressureLine, err error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	var sawSome bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return PressureLine{}, PressureLine{}, fmt.Errorf("malformed PSI line %q: expected at least 5 fields", line)
		}

		kind := fields[0]
		parsed, parseErr := parsePressureFields(fields[1:])
		if parseErr != nil {
			return PressureLine{}, PressureLine{}, fmt.Errorf("parse %q PSI metrics: %w", kind, parseErr)
		}

		switch kind {
		case "some":
			some = parsed
			sawSome = true
		case "full":
			full = parsed
		default:
			return PressureLine{}, PressureLine{}, fmt.Errorf("unknown PSI stall kind %q", kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return PressureLine{}, PressureLine{}, fmt.Errorf("scan PSI payload: %w", err)
	}
	if !sawSome {
		return PressureLine{}, PressureLine{}, errors.New("missing required 'some' line in PSI payload")
	}
	return some, full, nil
}

func parsePressureFields(tokens []string) (PressureLine, error) {
	var out PressureLine
	var seenAvg10, seenAvg60, seenAvg300, seenTotal bool

	for _, tok := range tokens {
		eqIdx := strings.IndexByte(tok, '=')
		if eqIdx <= 0 || eqIdx == len(tok)-1 {
			return PressureLine{}, fmt.Errorf("invalid key=value token %q", tok)
		}
		key := tok[:eqIdx]
		val := tok[eqIdx+1:]

		switch key {
		case "avg10":
			f, err := parsePercent(val)
			if err != nil {
				return PressureLine{}, fmt.Errorf("avg10: %w", err)
			}
			out.Avg10 = f
			seenAvg10 = true
		case "avg60":
			f, err := parsePercent(val)
			if err != nil {
				return PressureLine{}, fmt.Errorf("avg60: %w", err)
			}
			out.Avg60 = f
			seenAvg60 = true
		case "avg300":
			f, err := parsePercent(val)
			if err != nil {
				return PressureLine{}, fmt.Errorf("avg300: %w", err)
			}
			out.Avg300 = f
			seenAvg300 = true
		case "total":
			u, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return PressureLine{}, fmt.Errorf("total: %w", err)
			}
			out.TotalMicros = u
			seenTotal = true
		}
	}

	if !seenAvg10 || !seenAvg60 || !seenAvg300 || !seenTotal {
		return PressureLine{}, errors.New("incomplete PSI fields (require avg10, avg60, avg300, total)")
	}
	return out, nil
}

func parsePercent(raw string) (float64, error) {
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0.0 || f > 100.0 {
		return 0, fmt.Errorf("invalid percentage %q", raw)
	}
	return f, nil
}

// Governor dynamically scales inter-stage pruning pauses using Linux PSI feedback
// so container layer deletions never starve latency-sensitive production workloads.
type Governor struct {
	enabled         bool
	procRoot        string
	ioBudgetPercent float64
	gamma           float64
	basePause       time.Duration
	maxPause        time.Duration
	nowFn           func() time.Time
}

// NewGovernor constructs an adaptive I/O pacing governor from KernelConfig.
func NewGovernor(cfg config.KernelConfig) *Governor {
	procRoot := strings.TrimSpace(cfg.ProcRoot)
	if procRoot == "" {
		procRoot = "/proc"
	}
	budget := cfg.PSIIOBudgetPercent
	if budget <= 0 || math.IsNaN(budget) {
		budget = 25.0
	}
	gamma := cfg.PSIGamma
	if gamma <= 0 || math.IsNaN(gamma) {
		gamma = 2.0
	}
	basePause := cfg.BaseStagePause.Std()
	if basePause < 0 {
		basePause = 0
	}
	maxPause := cfg.MaxStagePause.Std()
	if maxPause < basePause {
		maxPause = basePause
	}

	return &Governor{
		enabled:         cfg.PSIEnabled,
		procRoot:        procRoot,
		ioBudgetPercent: budget,
		gamma:           gamma,
		basePause:       basePause,
		maxPause:        maxPause,
		nowFn:           time.Now,
	}
}

// ReadSnapshot reads /proc/pressure/io and /proc/pressure/memory.
// On non-Linux systems or kernels without CONFIG_PSI, it returns Supported=false without error.
func (g *Governor) ReadSnapshot() (PSISnapshot, error) {
	now := g.nowFn().UTC()
	ioPath := filepath.Join(g.procRoot, "pressure", "io")

	ioRaw, err := readBoundedTextFile(ioPath, maxPSIFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return PSISnapshot{Supported: false, SampledAt: now}, nil
		}
		return PSISnapshot{}, fmt.Errorf("read %s: %w", ioPath, err)
	}

	ioSome, ioFull, err := ParsePSI(ioRaw)
	if err != nil {
		return PSISnapshot{}, fmt.Errorf("parse %s: %w", ioPath, err)
	}

	snap := PSISnapshot{
		Supported: true,
		SampledAt: now,
		IOSome:    ioSome,
		IOFull:    ioFull,
	}

	memPath := filepath.Join(g.procRoot, "pressure", "memory")
	if memRaw, memErr := readBoundedTextFile(memPath, maxPSIFileBytes); memErr == nil {
		if memSome, memFull, parseErr := ParsePSI(memRaw); parseErr == nil {
			snap.MemSome = memSome
			snap.MemFull = memFull
		}
	}

	return snap, nil
}

// ThrottleFactor computes the dimensionless quadratic backoff multiplier:
// factor = 1 + gamma * (psi_eff / psi_budget)^2.
func (g *Governor) ThrottleFactor(snap PSISnapshot) float64 {
	if !g.enabled || !snap.Supported || g.ioBudgetPercent <= 0 {
		return 1.0
	}
	eff := snap.EffectiveIOStall()
	if eff <= 0 {
		return 1.0
	}
	ratio := eff / g.ioBudgetPercent
	factor := 1.0 + g.gamma*(ratio*ratio)
	if math.IsNaN(factor) || math.IsInf(factor, 0) || factor < 1.0 {
		return 1.0
	}
	return factor
}

// RecommendedPause calculates the inter-stage sleep duration. When bypassForPanic
// is true (PANIC regime), I/O yielding is bypassed (0s) to prevent host ENOSPC crash.
func (g *Governor) RecommendedPause(snap PSISnapshot, bypassForPanic bool) time.Duration {
	if bypassForPanic {
		return 0
	}
	if !g.enabled || !snap.Supported || g.basePause <= 0 {
		return g.basePause
	}

	factor := g.ThrottleFactor(snap)
	scaledNs := float64(g.basePause.Nanoseconds()) * factor
	if math.IsNaN(scaledNs) || math.IsInf(scaledNs, 0) || scaledNs >= float64(g.maxPause.Nanoseconds()) {
		return g.maxPause
	}
	paused := time.Duration(int64(math.Round(scaledNs)))
	if paused < g.basePause {
		return g.basePause
	}
	if paused > g.maxPause {
		return g.maxPause
	}
	return paused
}

func readBoundedTextFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
