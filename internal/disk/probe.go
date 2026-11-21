// Package disk implements cross-platform Statfs block/inode sensing,
// 6-regime pressure evaluation, exact byte-deficit calculation, and
// Holt-Winters double-exponential time-to-exhaustion (TTE) forecasting.
package disk

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

// Regime represents one of the 6 autonomous operating states of the storage control plane.
type Regime string

const (
	RegimeNominal    Regime = "NOMINAL"
	RegimePreemptive Regime = "PREEMPTIVE"
	RegimeElevated   Regime = "ELEVATED"
	RegimeCritical   Regime = "CRITICAL"
	RegimePanic      Regime = "PANIC"
	RegimeDegraded   Regime = "DEGRADED"
)

// Severity returns a monotonic integer severity rank for metrics and comparisons.
func (r Regime) Severity() int {
	switch r {
	case RegimeNominal:
		return 0
	case RegimePreemptive:
		return 1
	case RegimeElevated:
		return 2
	case RegimeCritical:
		return 3
	case RegimePanic:
		return 4
	case RegimeDegraded:
		return 5
	default:
		return 0
	}
}

// Snapshot captures dual-metric block and inode capacity on a backing filesystem.
type Snapshot struct {
	Path             string    `json:"path"`
	SampledAt        time.Time `json:"sampled_at"`
	TotalBytes       uint64    `json:"total_bytes"`
	FreeBytes        uint64    `json:"free_bytes"`
	RawFreeBytes     uint64    `json:"raw_free_bytes"`
	UsedBytes        uint64    `json:"used_bytes"`
	UsedPercent      float64   `json:"used_percent"`
	TotalInodes      uint64    `json:"total_inodes"`
	FreeInodes       uint64    `json:"free_inodes"`
	UsedInodes       uint64    `json:"used_inodes"`
	InodeUsedPercent float64   `json:"inode_used_percent"`
}

// BytesNeededToReachTarget computes the exact minimum bytes that must be freed so
// BOTH UsedPercent <= targetPercent AND FreeBytes >= minFreeBytes hold simultaneously.
func (s Snapshot) BytesNeededToReachTarget(targetPercent float64, minFreeBytes uint64) uint64 {
	usablePool := s.UsedBytes + s.FreeBytes
	if usablePool == 0 {
		return 0
	}

	var neededForPct uint64
	if targetPercent > 0 && targetPercent < 100.0 {
		allowedUsed := uint64(math.Floor(float64(usablePool) * (targetPercent / 100.0)))
		if s.UsedBytes > allowedUsed {
			neededForPct = s.UsedBytes - allowedUsed
		}
	}

	var neededForFloor uint64
	if minFreeBytes > s.FreeBytes {
		neededForFloor = minFreeBytes - s.FreeBytes
	}

	needed := neededForPct
	if neededForFloor > needed {
		needed = neededForFloor
	}
	if needed > s.UsedBytes {
		return s.UsedBytes
	}
	return needed
}

// Probe measures filesystem capacity at a target directory path.
type Probe interface {
	Measure(path string) (Snapshot, error)
}

// OSProbe queries the host operating system kernel for filesystem block and inode metrics.
type OSProbe struct {
	nowFn func() time.Time
}

// NewOSProbe returns a production OS-backed filesystem probe.
func NewOSProbe() *OSProbe {
	return &OSProbe{nowFn: time.Now}
}

// Measure executes a kernel filesystem stat call on path and computes POSIX-aligned percentages.
func (p *OSProbe) Measure(path string) (Snapshot, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Snapshot{}, errors.New("filesystem probe path cannot be empty")
	}
	now := time.Now
	if p != nil && p.nowFn != nil {
		now = p.nowFn
	}
	raw, err := statFS(trimmed)
	if err != nil {
		return Snapshot{}, fmt.Errorf("statfs %q: %w", trimmed, err)
	}
	return buildSnapshot(trimmed, now().UTC(), raw), nil
}

type rawStatFS struct {
	totalBytes   uint64
	freeAvail    uint64
	rawFreeBytes uint64
	totalInodes  uint64
	freeInodes   uint64
}

func buildSnapshot(path string, sampledAt time.Time, raw rawStatFS) Snapshot {
	rawFree := raw.rawFreeBytes
	if rawFree > raw.totalBytes {
		rawFree = raw.totalBytes
	}
	avail := raw.freeAvail
	if avail > rawFree {
		avail = rawFree
	}

	usedBytes := raw.totalBytes - rawFree
	// POSIX df semantics: percentage is computed over non-root usable pool (used + b_avail)
	// so reported saturation matches the exact moment unprivileged containers hit ENOSPC.
	usablePool := usedBytes + avail
	var usedPct float64
	if usablePool > 0 {
		usedPct = (float64(usedBytes) / float64(usablePool)) * 100.0
	}

	freeInodes := raw.freeInodes
	if freeInodes > raw.totalInodes {
		freeInodes = raw.totalInodes
	}
	usedInodes := raw.totalInodes - freeInodes
	var inodePct float64
	if raw.totalInodes > 0 {
		inodePct = (float64(usedInodes) / float64(raw.totalInodes)) * 100.0
	}

	return Snapshot{
		Path:             path,
		SampledAt:        sampledAt,
		TotalBytes:       raw.totalBytes,
		FreeBytes:        avail,
		RawFreeBytes:     rawFree,
		UsedBytes:        usedBytes,
		UsedPercent:      clampPct(usedPct),
		TotalInodes:      raw.totalInodes,
		FreeInodes:       freeInodes,
		UsedInodes:       usedInodes,
		InodeUsedPercent: clampPct(inodePct),
	}
}

// Assessment encapsulates the regime classification and target reclamation budget for a cycle.
type Assessment struct {
	Regime             Regime   `json:"regime"`
	Reasons            []string `json:"reasons"`
	ReclaimTargetBytes uint64   `json:"reclaim_target_bytes"`
}

// ShouldPrune reports whether the operating regime warrants executing reclamation stages.
func (a Assessment) ShouldPrune() bool {
	switch a.Regime {
	case RegimePreemptive, RegimeElevated, RegimeCritical, RegimePanic:
		return true
	default:
		return false
	}
}

// AllowDeepDAGPrune reports whether Stage 4 OCI Layer DAG reclamation is authorized.
func (a Assessment) AllowDeepDAGPrune() bool {
	return a.Regime == RegimeCritical || a.Regime == RegimePanic
}

// IsEmergency reports whether the host is in PANIC regime and must bypass PSI I/O throttling.
func (a Assessment) IsEmergency() bool {
	return a.Regime == RegimePanic
}

// Evaluate classifies current filesystem metrics and kinematic forecasts into one of the regimes.
func Evaluate(
	snap Snapshot,
	fc ForecastResult,
	wm config.WatermarkConfig,
	fcCfg config.ForecastConfig,
) Assessment {
	minFree := uint64(maxInt64(0, wm.MinFreeBytes.Bytes()))
	panicFree := uint64(maxInt64(0, wm.PanicFreeBytes.Bytes()))
	reclaimTarget := snap.BytesNeededToReachTarget(wm.TargetPercent, minFree)

	var panicReasons []string
	if snap.UsedPercent >= wm.PanicPercent {
		panicReasons = append(panicReasons, fmt.Sprintf("block usage %.2f%% >= panic watermark %.2f%%", snap.UsedPercent, wm.PanicPercent))
	}
	if panicFree > 0 && snap.TotalBytes > 0 && snap.FreeBytes <= panicFree {
		panicReasons = append(panicReasons, fmt.Sprintf("free space %s <= panic floor %s", config.ByteSize(snap.FreeBytes), wm.PanicFreeBytes))
	}
	if snap.TotalInodes > 0 && snap.InodeUsedPercent >= 98.0 {
		panicReasons = append(panicReasons, fmt.Sprintf("inode usage %.2f%% >= emergency ceiling 98.00%%", snap.InodeUsedPercent))
	}
	if len(panicReasons) > 0 {
		return Assessment{Regime: RegimePanic, Reasons: panicReasons, ReclaimTargetBytes: reclaimTarget}
	}

	var critReasons []string
	if snap.UsedPercent >= wm.CriticalPercent {
		critReasons = append(critReasons, fmt.Sprintf("block usage %.2f%% >= critical watermark %.2f%%", snap.UsedPercent, wm.CriticalPercent))
	}
	if snap.TotalInodes > 0 && snap.InodeUsedPercent >= wm.InodeCriticalPercent {
		critReasons = append(critReasons, fmt.Sprintf("inode usage %.2f%% >= critical watermark %.2f%%", snap.InodeUsedPercent, wm.InodeCriticalPercent))
	}
	if len(critReasons) > 0 {
		return Assessment{Regime: RegimeCritical, Reasons: critReasons, ReclaimTargetBytes: reclaimTarget}
	}

	var elevReasons []string
	if snap.UsedPercent >= wm.HighPercent {
		elevReasons = append(elevReasons, fmt.Sprintf("block usage %.2f%% >= high watermark %.2f%%", snap.UsedPercent, wm.HighPercent))
	}
	if minFree > 0 && snap.TotalBytes > 0 && snap.FreeBytes < minFree {
		elevReasons = append(elevReasons, fmt.Sprintf("free space %s < minimum floor %s", config.ByteSize(snap.FreeBytes), wm.MinFreeBytes))
	}
	if snap.TotalInodes > 0 && snap.InodeUsedPercent >= wm.InodeHighPercent {
		elevReasons = append(elevReasons, fmt.Sprintf("inode usage %.2f%% >= high watermark %.2f%%", snap.InodeUsedPercent, wm.InodeHighPercent))
	}
	if len(elevReasons) > 0 {
		return Assessment{Regime: RegimeElevated, Reasons: elevReasons, ReclaimTargetBytes: reclaimTarget}
	}

	if fcCfg.Enabled && (snap.UsedPercent >= wm.PreemptivePercent || (snap.TotalInodes > 0 && snap.InodeUsedPercent >= wm.PreemptivePercent)) {
		horizonSec := fcCfg.Horizon.Std().Seconds()
		var preReasons []string
		if fc.BlockTTESeconds > 0 && fc.BlockTTESeconds <= horizonSec {
			preReasons = append(preReasons, fmt.Sprintf("predicted block exhaustion in %.0fs <= horizon %.0fs", fc.BlockTTESeconds, horizonSec))
		}
		if fc.InodeTTESeconds > 0 && fc.InodeTTESeconds <= horizonSec {
			preReasons = append(preReasons, fmt.Sprintf("predicted inode exhaustion in %.0fs <= horizon %.0fs", fc.InodeTTESeconds, horizonSec))
		}
		if fc.AnomalyTriggered {
			preReasons = append(preReasons, fmt.Sprintf("burn-rate anomaly z-score %.2f >= threshold %.2f", fc.BurnZScore, fcCfg.ZScoreThreshold))
		}
		if len(preReasons) > 0 {
			// Ensure preemptive pruning reclaims at least down to PreemptivePercent - 5% if already below TargetPercent.
			if reclaimTarget == 0 {
				bandTarget := math.Max(1.0, wm.PreemptivePercent-5.0)
				reclaimTarget = snap.BytesNeededToReachTarget(bandTarget, minFree)
			}
			return Assessment{Regime: RegimePreemptive, Reasons: preReasons, ReclaimTargetBytes: reclaimTarget}
		}
	}

	return Assessment{
		Regime:             RegimeNominal,
		Reasons:            nil,
		ReclaimTargetBytes: 0,
	}
}

// HasReachedTarget determines whether hysteresis recovery targets have been satisfied
// across both block space and inode utilization so the waterfall can stop early.
func HasReachedTarget(snap Snapshot, wm config.WatermarkConfig) bool {
	minFree := uint64(maxInt64(0, wm.MinFreeBytes.Bytes()))
	if snap.UsedPercent > wm.TargetPercent {
		return false
	}
	if minFree > 0 && snap.TotalBytes > 0 && snap.FreeBytes < minFree {
		return false
	}
	if snap.TotalInodes > 0 && snap.InodeUsedPercent > wm.InodeTargetPercent {
		return false
	}
	return true
}

func clampPct(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	if v > 100.0 {
		return 100.0
	}
	return v
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
