// Package finops quantifies cumulative reclaimed storage, prevented ENOSPC host
// outages, and preserved warm BuildKit cache value into auditable USD savings
// so engineering teams can justify B2B open-source sponsorships with real data.
package finops

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

const (
	stateFileName                  = "finops_state.json"
	stateSchemaVersion             = "dpd-finops-v1"
	estimatedWarmCacheSavedMinutes = 3.0
	referenceTeamSponsorMonthlyUSD = 150.0
)

// PersistedState stores cumulative operational counters across daemon restarts.
type PersistedState struct {
	Schema                      string    `json:"schema"`
	FirstRecordedAt             time.Time `json:"first_recorded_at"`
	LastUpdatedAt               time.Time `json:"last_updated_at"`
	TotalCycles                 uint64    `json:"total_cycles"`
	ActiveReclaimCycles         uint64    `json:"active_reclaim_cycles"`
	DryRunCycles                uint64    `json:"dry_run_cycles"`
	TotalActualReclaimedBytes   uint64    `json:"total_actual_reclaimed_bytes"`
	TotalReportedReclaimedBytes uint64    `json:"total_reported_reclaimed_bytes"`
	TotalLogTruncatedBytes      uint64    `json:"total_log_truncated_bytes"`
	PeakSingleReclaimBytes      uint64    `json:"peak_single_reclaim_bytes"`
	ENOSPCAvertedCount          uint64    `json:"enospc_averted_count"`
	BuildCachePreservedCycles   uint64    `json:"build_cache_preserved_cycles"`
}

// Report combines cumulative counters with live USD FinOps valuations.
type Report struct {
	State                    PersistedState `json:"state"`
	TotalActualReclaimedGiB  float64        `json:"total_actual_reclaimed_gib"`
	PeakSingleReclaimGiB     float64        `json:"peak_single_reclaim_gib"`
	CIMinutesSavedEstimate   float64        `json:"ci_minutes_saved_estimate"`
	StorageSavingsUSD        float64        `json:"storage_savings_usd"`
	IncidentAvoidanceUSD     float64        `json:"incident_avoidance_usd"`
	WarmCacheSavingsUSD      float64        `json:"warm_cache_savings_usd"`
	EstimatedTotalSavingsUSD float64        `json:"estimated_total_savings_usd"`
	TeamSponsorROIMultiple   float64        `json:"team_sponsor_roi_multiple"`
}

// Tracker maintains thread-safe FinOps telemetry backed by atomic JSON persistence.
type Tracker struct {
	mu        sync.Mutex
	statePath string
	nowFn     func() time.Time
	state     PersistedState
}

// LoadOrNew loads existing FinOps counters from stateDir/finops_state.json or
// initializes a fresh tracker when none exists yet.
func LoadOrNew(stateDir string) (*Tracker, error) {
	trimmedDir := strings.TrimSpace(stateDir)
	var statePath string
	if trimmedDir != "" {
		statePath = filepath.Join(trimmedDir, stateFileName)
	}

	t := &Tracker{
		statePath: statePath,
		nowFn:     time.Now,
		state: PersistedState{
			Schema: stateSchemaVersion,
		},
	}

	if statePath == "" {
		return t, nil
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return t, nil
		}
		return nil, fmt.Errorf("read finops state %q: %w", statePath, err)
	}

	var loaded PersistedState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, fmt.Errorf("parse finops state %q: %w", statePath, err)
	}
	if loaded.Schema == "" {
		loaded.Schema = stateSchemaVersion
	}
	t.state = loaded
	return t, nil
}

// RecordCycle updates cumulative operational and reliability counters from a completed cycle
// and persists the updated state atomically to disk when stateDir is configured.
func (t *Tracker) RecordCycle(cycle engine.CycleReport) error {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := cycle.CompletedAt.UTC()
	if now.IsZero() {
		now = t.nowFn().UTC()
	}
	if t.state.FirstRecordedAt.IsZero() {
		t.state.FirstRecordedAt = now
	}
	t.state.LastUpdatedAt = now
	t.state.TotalCycles++

	if cycle.DryRun {
		t.state.DryRunCycles++
		return t.persistLocked()
	}

	effectiveBytes := cycle.ActualDiskReclaimedBytes
	if effectiveBytes == 0 && cycle.ReportedReclaimedBytes > 0 {
		effectiveBytes = cycle.ReportedReclaimedBytes
	}

	if effectiveBytes > 0 || len(cycle.Stages) > 0 {
		t.state.ActiveReclaimCycles++
	}
	t.state.TotalActualReclaimedBytes += cycle.ActualDiskReclaimedBytes
	t.state.TotalReportedReclaimedBytes += cycle.ReportedReclaimedBytes

	if effectiveBytes > t.state.PeakSingleReclaimBytes {
		t.state.PeakSingleReclaimBytes = effectiveBytes
	}

	for _, entry := range cycle.LogEntries {
		if !entry.DryRun && entry.BytesReclaimed > 0 {
			t.state.TotalLogTruncatedBytes += uint64(entry.BytesReclaimed)
		}
	}

	if cycle.ENOSPCAverted {
		t.state.ENOSPCAvertedCount++
	}

	// Credit warm BuildKit cache preservation only on genuine reclamation cycles that
	// recovered space without wiping the warm builder cache budget.
	if len(cycle.Stages) > 0 && effectiveBytes > 0 && cycle.BuildCachePreserved {
		t.state.BuildCachePreservedCycles++
	}

	return t.persistLocked()
}

// Snapshot computes a full FinOps ROI valuation using the rates in TelemetryConfig.
func (t *Tracker) Snapshot(rates config.TelemetryConfig) Report {
	if t == nil {
		return Report{}
	}
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()

	return ComputeReport(st, rates)
}

// ComputeReport calculates deterministic USD valuations from a PersistedState snapshot.
func ComputeReport(st PersistedState, rates config.TelemetryConfig) Report {
	const gibFloat = float64(1024 * 1024 * 1024)

	creditedBytes := st.TotalActualReclaimedBytes
	if creditedBytes == 0 && st.TotalReportedReclaimedBytes > 0 {
		creditedBytes = st.TotalReportedReclaimedBytes
	}

	actualGiB := float64(creditedBytes) / gibFloat
	peakGiB := float64(st.PeakSingleReclaimBytes) / gibFloat
	ciMinutes := float64(st.BuildCachePreservedCycles) * estimatedWarmCacheSavedMinutes

	costPerGiB := sanitizeNonNegative(rates.FinOpsCostPerGiBMonthUSD)
	incidentCost := sanitizeNonNegative(rates.FinOpsIncidentCostUSD)
	ciMinCost := sanitizeNonNegative(rates.FinOpsCIMinuteCostUSD)

	storageUSD := roundCents(actualGiB * costPerGiB)
	incidentUSD := roundCents(float64(st.ENOSPCAvertedCount) * incidentCost)
	cacheUSD := roundCents(ciMinutes * ciMinCost)
	totalUSD := roundCents(storageUSD + incidentUSD + cacheUSD)

	roiMultiple := roundCents(totalUSD / referenceTeamSponsorMonthlyUSD)

	return Report{
		State:                    st,
		TotalActualReclaimedGiB:  roundCents(actualGiB),
		PeakSingleReclaimGiB:     roundCents(peakGiB),
		CIMinutesSavedEstimate:   roundCents(ciMinutes),
		StorageSavingsUSD:        storageUSD,
		IncidentAvoidanceUSD:     incidentUSD,
		WarmCacheSavingsUSD:      cacheUSD,
		EstimatedTotalSavingsUSD: totalUSD,
		TeamSponsorROIMultiple:   roiMultiple,
	}
}

// FormatMarkdown renders a copy-pasteable engineering ROI summary for Slack, PRs, or Jira.
func FormatMarkdown(rep Report) string {
	var b strings.Builder
	b.WriteString("## Infrastructure Reliability & FinOps ROI Report (`dock-prune-daemon`)\n\n")
	b.WriteString("| Metric | Observed Value | Estimated Value (USD) |\n")
	b.WriteString("| :--- | :--- | :--- |\n")
	fmt.Fprintf(&b, "| **Disk Space Reclaimed** | `%.2f GiB` (peak `%.2f GiB`) | `$%.2f` |\n",
		rep.TotalActualReclaimedGiB, rep.PeakSingleReclaimGiB, rep.StorageSavingsUSD)
	fmt.Fprintf(&b, "| **ENOSPC Outages Averted** | `%d` critical/panic rescues | `$%.2f` |\n",
		rep.State.ENOSPCAvertedCount, rep.IncidentAvoidanceUSD)
	fmt.Fprintf(&b, "| **Warm BuildKit Cache Kept** | `%d` cycles (~`%.0f` CI mins saved) | `$%.2f` |\n",
		rep.State.BuildCachePreservedCycles, rep.CIMinutesSavedEstimate, rep.WarmCacheSavingsUSD)
	fmt.Fprintf(&b, "| **Total Estimated Value** | `%d` active reclaim cycles | **`$%.2f`** (`%.2fx` Team Sponsor tier) |\n\n",
		rep.State.ActiveReclaimCycles, rep.EstimatedTotalSavingsUSD, rep.TeamSponsorROIMultiple)
	b.WriteString("> Sustained via [GitHub Sponsors (@PedroMartinezag)](https://github.com/sponsors/PedroMartinezag) — corporate tiers include 24h/48h SLAs & README placement.\n")
	return b.String()
}

func (t *Tracker) persistLocked() error {
	if t.statePath == "" {
		return nil
	}
	dir := filepath.Dir(t.statePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create finops state dir %q: %w", dir, err)
	}

	encoded, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal finops state: %w", err)
	}
	encoded = append(encoded, '\n')

	tmp, err := os.CreateTemp(dir, ".finops-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp finops file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	_ = tmp.Chmod(0o640)
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, t.statePath); err != nil {
		return fmt.Errorf("rename finops state: %w", err)
	}
	cleanup = false
	return nil
}

func sanitizeNonNegative(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}

func roundCents(v float64) float64 {
	return math.Round(v*100.0) / 100.0
}
