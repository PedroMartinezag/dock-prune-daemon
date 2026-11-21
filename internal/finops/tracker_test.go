package finops

import (
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

func TestTracker_Persistence_DryRunExemption_AndROIMath(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	tracker, err := LoadOrNew(stateDir)
	if err != nil {
		t.Fatalf("LoadOrNew initial error: %v", err)
	}

	const gib = uint64(1024 * 1024 * 1024)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// 1. Dry-run cycle must increment DryRunCycles without inflating USD savings!
	if err := tracker.RecordCycle(engine.CycleReport{
		CycleID:                  "dry-1",
		DryRun:                   true,
		CompletedAt:              now,
		ReportedReclaimedBytes:   50 * gib,
		ActualDiskReclaimedBytes: 50 * gib,
		ENOSPCAverted:            true,
	}); err != nil {
		t.Fatalf("RecordCycle(dry-run) error: %v", err)
	}

	// 2. Live CRITICAL rescue reclaiming 40 GiB, truncating 2 GiB logs, averting ENOSPC, keeping BuildKit cache!
	if err := tracker.RecordCycle(engine.CycleReport{
		CycleID:                  "live-1",
		DryRun:                   false,
		InitialRegime:            disk.RegimeCritical,
		FinalRegime:              disk.RegimeNominal,
		CompletedAt:              now.Add(5 * time.Minute),
		ReportedReclaimedBytes:   40 * gib,
		ActualDiskReclaimedBytes: 40 * gib,
		BuildCachePreserved:      true,
		ENOSPCAverted:            true,
		Stages: []engine.StageResult{
			{Stage: engine.Stage0LogTruncate, Executed: true, ItemsDeleted: 1},
		},
		LogEntries: []engine.LogTruncateEntry{
			{ContainerID: "c1", BytesReclaimed: int64(2 * gib)},
		},
	}); err != nil {
		t.Fatalf("RecordCycle(live-1) error: %v", err)
	}

	// Reload from disk to prove atomic JSON persistence across daemon restarts.
	reloaded, err := LoadOrNew(stateDir)
	if err != nil {
		t.Fatalf("LoadOrNew reload error: %v", err)
	}

	rates := config.TelemetryConfig{
		FinOpsCostPerGiBMonthUSD: 0.10,  // 40 GiB * $0.10 = $4.00
		FinOpsIncidentCostUSD:    250.0, // 1 incident * $250 = $250.00
		FinOpsCIMinuteCostUSD:    0.10,  // 3 mins * $0.10 = $0.30
	}
	rep := reloaded.Snapshot(rates)

	if rep.State.TotalCycles != 2 || rep.State.DryRunCycles != 1 || rep.State.ActiveReclaimCycles != 1 {
		t.Fatalf("unexpected cycle counts: %+v", rep.State)
	}
	if rep.TotalActualReclaimedGiB != 40.0 || rep.State.TotalLogTruncatedBytes != 2*gib {
		t.Fatalf("unexpected byte totals: %+v", rep)
	}
	if rep.StorageSavingsUSD != 4.00 || rep.IncidentAvoidanceUSD != 250.00 || rep.WarmCacheSavingsUSD != 0.30 {
		t.Fatalf("unexpected USD breakdown: %+v", rep)
	}
	if rep.EstimatedTotalSavingsUSD != 254.30 {
		t.Fatalf("EstimatedTotalSavingsUSD = %.2f, want 254.30", rep.EstimatedTotalSavingsUSD)
	}
	if rep.TeamSponsorROIMultiple <= 1.60 {
		t.Fatalf("expected ROI multiple > 1.60x against $150 tier, got %.2f", rep.TeamSponsorROIMultiple)
	}

	md := FormatMarkdown(rep)
	if !strings.Contains(md, "$254.30") || !strings.Contains(md, "GitHub Sponsors (@PedroMartinezag)") {
		t.Fatalf("FormatMarkdown missing expected valuation or sponsor link:\n%s", md)
	}
}
