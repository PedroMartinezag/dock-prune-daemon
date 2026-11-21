// Package telemetry provides a zero-dependency OpenMetrics/Prometheus exporter,
// constant-time Bearer-authenticated HTTP control plane, live SSE event bus,
// and an embedded single-binary dark-mode observability dashboard.
package telemetry

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

var durationHistogramBounds = []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0}

var allRegimes = []disk.Regime{
	disk.RegimeNominal,
	disk.RegimePreemptive,
	disk.RegimeElevated,
	disk.RegimeCritical,
	disk.RegimePanic,
	disk.RegimeDegraded,
}

var allBreakerStates = []docker.BreakerState{
	docker.BreakerClosed,
	docker.BreakerOpen,
	docker.BreakerHalfOpen,
}

var allStages = []engine.StageID{
	engine.Stage0LogTruncate,
	engine.Stage1ContainersNetworks,
	engine.Stage2DanglingImages,
	engine.Stage3BuildCache,
	engine.Stage4DAGAndVolumes,
}

type cycleCounterKey struct {
	trigger string
	regime  string
	dryRun  string
}

// Registry stores point-in-time gauges, monotonic counters, and latency histograms
// rendered in Prometheus text exposition format (version 0.0.4) with zero allocations overhead.
type Registry struct {
	mu        sync.RWMutex
	startedAt time.Time
	nowFn     func() time.Time

	currentRegime disk.Regime
	diskSnap      disk.Snapshot
	forecast      disk.ForecastResult
	psi           kernel.PSISnapshot
	breaker       docker.BreakerStats
	finopsRep     finops.Report
	lastCycle     *engine.CycleReport

	phantomBytes int64
	phantomFDs   int

	cycleTotals       map[cycleCounterKey]uint64
	stageExecTotals   map[engine.StageID]uint64
	stageItemsDeleted map[engine.StageID]uint64
	stageBytesTotals  map[engine.StageID]uint64

	actualReclaimedTotal   uint64
	reportedReclaimedTotal uint64
	enospcAvertedTotal     uint64
	cachePreservedTotal    uint64

	durBucketCounts []uint64
	durCount        uint64
	durSumSeconds   float64
}

// NewRegistry creates an initialized Prometheus telemetry registry.
func NewRegistry() *Registry {
	now := time.Now().UTC()
	r := &Registry{
		startedAt:         now,
		nowFn:             time.Now,
		currentRegime:     disk.RegimeNominal,
		breaker:           docker.BreakerStats{State: docker.BreakerClosed},
		cycleTotals:       make(map[cycleCounterKey]uint64),
		stageExecTotals:   make(map[engine.StageID]uint64, len(allStages)),
		stageItemsDeleted: make(map[engine.StageID]uint64, len(allStages)),
		stageBytesTotals:  make(map[engine.StageID]uint64, len(allStages)),
		durBucketCounts:   make([]uint64, len(durationHistogramBounds)),
	}
	for _, st := range allStages {
		r.stageExecTotals[st] = 0
		r.stageItemsDeleted[st] = 0
		r.stageBytesTotals[st] = 0
	}
	return r
}

// UpdateSensors refreshes live disk, forecast, PSI, phantom FD, and breaker gauges.
func (r *Registry) UpdateSensors(
	regime disk.Regime,
	snap disk.Snapshot,
	fc disk.ForecastResult,
	psi kernel.PSISnapshot,
	breaker docker.BreakerStats,
	phantomBytes int64,
	phantomFDs int,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentRegime = regime
	r.diskSnap = snap
	r.forecast = fc
	r.psi = psi
	r.breaker = breaker
	r.phantomBytes = phantomBytes
	r.phantomFDs = phantomFDs
}

// ObserveCycle records a completed reclamation cycle across counters, histograms, and gauges.
func (r *Registry) ObserveCycle(rep engine.CycleReport, roi finops.Report) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := rep
	r.lastCycle = &cp
	r.currentRegime = rep.FinalRegime
	r.diskSnap = rep.AfterDisk
	r.forecast = rep.Forecast
	r.psi = rep.PSI
	r.finopsRep = roi
	if rep.PhantomLeakedBytes > 0 || rep.PhantomFindings > 0 {
		r.phantomBytes = rep.PhantomLeakedBytes
		r.phantomFDs = rep.PhantomFindings
	}

	key := cycleCounterKey{
		trigger: nonEmpty(rep.Trigger, "periodic"),
		regime:  nonEmpty(string(rep.InitialRegime), string(disk.RegimeNominal)),
		dryRun:  strconv.FormatBool(rep.DryRun),
	}
	r.cycleTotals[key]++

	durSec := rep.Duration.Seconds()
	if durSec < 0 || math.IsNaN(durSec) || math.IsInf(durSec, 0) {
		durSec = 0
	}
	r.durCount++
	r.durSumSeconds += durSec
	for idx, bound := range durationHistogramBounds {
		if durSec <= bound {
			r.durBucketCounts[idx]++
		}
	}

	if !rep.DryRun {
		r.actualReclaimedTotal += rep.ActualDiskReclaimedBytes
		r.reportedReclaimedTotal += rep.ReportedReclaimedBytes
		if rep.ENOSPCAverted {
			r.enospcAvertedTotal++
		}
		if len(rep.Stages) > 0 && rep.BuildCachePreserved && (rep.ActualDiskReclaimedBytes > 0 || rep.ReportedReclaimedBytes > 0) {
			r.cachePreservedTotal++
		}
		for _, st := range rep.Stages {
			if st.Executed {
				r.stageExecTotals[st.Stage]++
				if st.ItemsDeleted > 0 {
					r.stageItemsDeleted[st.Stage] += uint64(st.ItemsDeleted)
				}
				r.stageBytesTotals[st.Stage] += st.ReportedReclaimedBytes
			}
		}
	}
}

// UpdateFinOps refreshes the cached FinOps ROI valuation snapshot.
func (r *Registry) UpdateFinOps(roi finops.Report) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finopsRep = roi
}

// LastCycle returns a copy of the most recent CycleReport, or nil if none has run yet.
func (r *Registry) LastCycle() *engine.CycleReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastCycle == nil {
		return nil
	}
	cp := *r.lastCycle
	return &cp
}

// RenderPrometheus formats all metrics into canonical Prometheus 0.0.4 exposition text.
func (r *Registry) RenderPrometheus() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b strings.Builder
	b.Grow(8192)

	bInfo := buildinfo.Get()
	writeGauge(&b, "dockprune_build_info", "Static build and runtime provenance metadata.",
		fmt.Sprintf(`{version="%s",commit="%s",go_version="%s",arch="%s"}`,
			escLabel(bInfo.Version), escLabel(bInfo.Commit), escLabel(bInfo.GoVersion), escLabel(bInfo.Arch)), 1)

	uptime := r.nowFn().UTC().Sub(r.startedAt).Seconds()
	if uptime < 0 {
		uptime = 0
	}
	writeGauge(&b, "dockprune_up", "Whether the dock-prune-daemon control plane is running.", "", 1)
	writeGauge(&b, "dockprune_uptime_seconds", "Daemon process uptime in seconds.", "", uptime)

	writeGauge(&b, "dockprune_regime_severity", "Current operating pressure regime severity (0=NOMINAL..5=DEGRADED).", "", float64(r.currentRegime.Severity()))
	b.WriteString("# HELP dockprune_regime_active One-hot indicator of the active storage pressure regime.\n")
	b.WriteString("# TYPE dockprune_regime_active gauge\n")
	for _, reg := range allRegimes {
		val := 0.0
		if r.currentRegime == reg {
			val = 1.0
		}
		fmt.Fprintf(&b, "dockprune_regime_active{regime=\"%s\"} %s\n", escLabel(string(reg)), fmtFloat(val))
	}

	// Disk & Inode capacity gauges
	writeGauge(&b, "dockprune_disk_total_bytes", "Total capacity of the monitored container filesystem in bytes.", "", float64(r.diskSnap.TotalBytes))
	writeGauge(&b, "dockprune_disk_used_bytes", "Used space on the monitored container filesystem in bytes.", "", float64(r.diskSnap.UsedBytes))
	writeGauge(&b, "dockprune_disk_free_bytes", "Unprivileged available space on the monitored filesystem in bytes.", "", float64(r.diskSnap.FreeBytes))
	writeGauge(&b, "dockprune_disk_used_percent", "Block capacity utilization percentage.", "", r.diskSnap.UsedPercent)

	writeGauge(&b, "dockprune_inodes_total", "Total inodes on the monitored filesystem.", "", float64(r.diskSnap.TotalInodes))
	writeGauge(&b, "dockprune_inodes_used", "Used inodes on the monitored filesystem.", "", float64(r.diskSnap.UsedInodes))
	writeGauge(&b, "dockprune_inodes_free", "Free inodes on the monitored filesystem.", "", float64(r.diskSnap.FreeInodes))
	writeGauge(&b, "dockprune_inodes_used_percent", "Inode table utilization percentage.", "", r.diskSnap.InodeUsedPercent)

	// Kinematic Holt-Winters forecast gauges
	writeGauge(&b, "dockprune_forecast_velocity_bytes_per_second", "Smoothed Holt-Winters disk write velocity in bytes/sec.", "", r.forecast.BlockVelocityBps)
	writeGauge(&b, "dockprune_forecast_accel_bytes_per_second_squared", "Smoothed Holt-Winters disk write acceleration in bytes/sec^2.", "", r.forecast.BlockAccelBps2)
	writeGauge(&b, "dockprune_forecast_tte_seconds", "Predicted quadratic Time-To-Exhaustion in seconds (-1 when non-increasing).", "", r.forecast.BlockTTESeconds)
	writeGauge(&b, "dockprune_forecast_burn_zscore", "Rolling Z-score of instantaneous disk burn velocity.", "", r.forecast.BurnZScore)
	anom := 0.0
	if r.forecast.AnomalyTriggered {
		anom = 1.0
	}
	writeGauge(&b, "dockprune_forecast_anomaly_active", "Whether a Z-score log-storm burst anomaly is currently active.", "", anom)

	// Kernel PSI & Phantom FD gauges
	psiSup := 0.0
	if r.psi.Supported {
		psiSup = 1.0
	}
	writeGauge(&b, "dockprune_psi_supported", "Whether Linux /proc/pressure PSI metrics are available.", "", psiSup)
	writeGauge(&b, "dockprune_psi_io_some_avg10", "Linux PSI io some 10-second stall percentage.", "", r.psi.IOSome.Avg10)
	writeGauge(&b, "dockprune_psi_io_full_avg10", "Linux PSI io full 10-second stall percentage.", "", r.psi.IOFull.Avg10)
	writeGauge(&b, "dockprune_psi_mem_full_avg10", "Linux PSI memory full 10-second stall percentage.", "", r.psi.MemFull.Avg10)
	writeGauge(&b, "dockprune_psi_effective_stall_percent", "Composite kernel stall percentage driving adaptive I/O backoff.", "", r.psi.EffectiveIOStall())

	writeGauge(&b, "dockprune_phantom_leaked_bytes", "Bytes pinned open by deleted unlinked file descriptors across /proc.", "", float64(r.phantomBytes))
	writeGauge(&b, "dockprune_phantom_open_fds", "Count of deduplicated unlinked open file descriptors above threshold.", "", float64(r.phantomFDs))

	// Docker Circuit Breaker metrics
	b.WriteString("# HELP dockprune_docker_breaker_state One-hot indicator of the Docker socket circuit breaker state.\n")
	b.WriteString("# TYPE dockprune_docker_breaker_state gauge\n")
	for _, st := range allBreakerStates {
		val := 0.0
		if r.breaker.State == st {
			val = 1.0
		}
		fmt.Fprintf(&b, "dockprune_docker_breaker_state{state=\"%s\"} %s\n", escLabel(string(st)), fmtFloat(val))
	}
	writeCounter(&b, "dockprune_docker_breaker_trips_total", "Total number of times the Docker socket circuit breaker tripped OPEN.", "", r.breaker.TotalTrips)
	writeCounter(&b, "dockprune_docker_breaker_failures_total", "Total socket/5xx errors observed by the Docker circuit breaker.", "", r.breaker.TotalFailures)
	writeCounter(&b, "dockprune_docker_breaker_rejected_total", "Total requests fast-rejected while the circuit breaker was OPEN.", "", r.breaker.TotalRejected)

	// Cycle counters & duration histogram
	b.WriteString("# HELP dockprune_cycles_total Total reclamation evaluation cycles executed.\n")
	b.WriteString("# TYPE dockprune_cycles_total counter\n")
	keys := make([]cycleCounterKey, 0, len(r.cycleTotals))
	for k := range r.cycleTotals {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b cycleCounterKey) int {
		if a.trigger != b.trigger {
			return strings.Compare(a.trigger, b.trigger)
		}
		if a.regime != b.regime {
			return strings.Compare(a.regime, b.regime)
		}
		return strings.Compare(a.dryRun, b.dryRun)
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "dockprune_cycles_total{trigger=\"%s\",regime=\"%s\",dry_run=\"%s\"} %d\n",
			escLabel(k.trigger), escLabel(k.regime), escLabel(k.dryRun), r.cycleTotals[k])
	}

	var lastTs float64
	if r.lastCycle != nil && !r.lastCycle.CompletedAt.IsZero() {
		lastTs = float64(r.lastCycle.CompletedAt.Unix())
	}
	writeGauge(&b, "dockprune_cycle_last_timestamp_seconds", "Unix timestamp of the most recently completed evaluation cycle.", "", lastTs)

	b.WriteString("# HELP dockprune_cycle_duration_seconds Histogram of reclamation cycle execution latency in seconds.\n")
	b.WriteString("# TYPE dockprune_cycle_duration_seconds histogram\n")
	for idx, bound := range durationHistogramBounds {
		fmt.Fprintf(&b, "dockprune_cycle_duration_seconds_bucket{le=\"%s\"} %d\n", fmtFloat(bound), r.durBucketCounts[idx])
	}
	fmt.Fprintf(&b, "dockprune_cycle_duration_seconds_bucket{le=\"+Inf\"} %d\n", r.durCount)
	fmt.Fprintf(&b, "dockprune_cycle_duration_seconds_sum %s\n", fmtFloat(r.durSumSeconds))
	fmt.Fprintf(&b, "dockprune_cycle_duration_seconds_count %d\n", r.durCount)

	// Reclamation & FinOps totals
	writeCounter(&b, "dockprune_reclaimed_bytes_actual_total", "Cumulative actual filesystem bytes freed across live cycles.", "", r.actualReclaimedTotal)
	writeCounter(&b, "dockprune_reclaimed_bytes_reported_total", "Cumulative bytes reported reclaimed by stages across live cycles.", "", r.reportedReclaimedTotal)
	writeCounter(&b, "dockprune_enospc_averted_total", "Total critical/panic pressure emergencies successfully resolved.", "", r.enospcAvertedTotal)
	writeCounter(&b, "dockprune_build_cache_preserved_total", "Total active reclaim cycles that preserved warm BuildKit cache via early hysteresis exit.", "", r.cachePreservedTotal)

	b.WriteString("# HELP dockprune_stage_executions_total Total live executions per surgical waterfall stage.\n")
	b.WriteString("# TYPE dockprune_stage_executions_total counter\n")
	for _, st := range allStages {
		fmt.Fprintf(&b, "dockprune_stage_executions_total{stage=\"%s\"} %d\n", escLabel(string(st)), r.stageExecTotals[st])
	}

	b.WriteString("# HELP dockprune_stage_items_deleted_total Total items truncated or evicted per waterfall stage.\n")
	b.WriteString("# TYPE dockprune_stage_items_deleted_total counter\n")
	for _, st := range allStages {
		fmt.Fprintf(&b, "dockprune_stage_items_deleted_total{stage=\"%s\"} %d\n", escLabel(string(st)), r.stageItemsDeleted[st])
	}

	b.WriteString("# HELP dockprune_stage_reclaimed_bytes_total Total bytes reported reclaimed per waterfall stage.\n")
	b.WriteString("# TYPE dockprune_stage_reclaimed_bytes_total counter\n")
	for _, st := range allStages {
		fmt.Fprintf(&b, "dockprune_stage_reclaimed_bytes_total{stage=\"%s\"} %d\n", escLabel(string(st)), r.stageBytesTotals[st])
	}

	writeGauge(&b, "dockprune_finops_estimated_savings_usd", "Cumulative estimated infrastructure & reliability value saved in USD.", "", r.finopsRep.EstimatedTotalSavingsUSD)

	return b.String()
}

func writeGauge(b *strings.Builder, name, help, labels string, val float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s%s %s\n", name, help, name, name, labels, fmtFloat(val))
}

func writeCounter(b *strings.Builder, name, help, labels string, val uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s%s %d\n", name, help, name, name, labels, val)
}

func fmtFloat(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "0"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func escLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
