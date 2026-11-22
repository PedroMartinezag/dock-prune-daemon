package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/graph"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

func TestRenderer_NoColorCompliance_AndAllDiagnosticViews(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	const gib = uint64(1024 * 1024 * 1024)
	const mib = int64(1024 * 1024)

	noColorEnv := func(k string) (string, bool) {
		if k == "NO_COLOR" {
			return "1", true
		}
		return "", false
	}
	plainR := AutoRenderer(noColorEnv)
	colorR := NewRenderer(false, 90)

	snap := disk.Snapshot{
		Path:             "/var/lib/docker",
		SampledAt:        now,
		TotalBytes:       100 * gib,
		UsedBytes:        88 * gib,
		FreeBytes:        12 * gib,
		UsedPercent:      88.0,
		TotalInodes:      1_000_000,
		UsedInodes:       350_000,
		FreeInodes:       650_000,
		InodeUsedPercent: 35.0,
	}

	// 1. RenderExplain with Orphan Clique & Shared-Layer Illusion
	expOut := plainR.RenderExplain(engine.ExplainReport{
		CapturedAt: now,
		Disk:       snap,
		Forecast:   disk.ForecastResult{BlockTTESeconds: 900},
		Assessment: disk.Assessment{Regime: disk.RegimeElevated, ReclaimTargetBytes: 18 * gib},
		Breaker:    docker.BreakerStats{State: docker.BreakerClosed},
		DAG: &graph.DAG{
			ImageOrder:            []string{"sha256:a", "sha256:b"},
			LayerOrder:            []string{"sha256:L1"},
			TotalUniqueLayerBytes: 2048 * mib,
			ReclaimableLayerBytes: 2048 * mib,
			SharedBloatRatio:      1.95,
		},
		Plan: graph.ReclamationPlan{
			OrphanCliques: []graph.OrphanClique{
				{
					ID:                "clique-01",
					ImageIDs:          []string{"sha256:a", "sha256:b"},
					RepoTags:          []string{"ml:v1", "ml:v2"},
					SharedUnlockBytes: 1800 * mib,
					TotalReclaimBytes: 2048 * mib,
				},
			},
			Explanations: []graph.ImageExplanation{
				{
					PrimaryTag:          "ml:v1",
					ReportedSize:        1924 * mib,
					ExclusiveBytes:      124 * mib,
					SharedIllusionBytes: 1800 * mib,
					Disposition:         graph.DispositionEligibleClique,
					CliqueID:            "clique-01",
				},
			},
			Steps: []graph.EvictionStep{
				{
					Step:            1,
					Kind:            graph.CandidateOrphanClique,
					RepoTags:        []string{"ml:v1", "ml:v2"},
					MarginalBytes:   2048 * mib,
					CumulativeBytes: 2048 * mib,
					UnlockedLayers:  3,
				},
			},
		},
	})
	if strings.Contains(expOut, "\x1b[") {
		t.Fatal("NO_COLOR renderer emitted ANSI escape codes in RenderExplain")
	}
	if !strings.Contains(expOut, "clique-01") || !strings.Contains(expOut, "1.95x") {
		t.Fatalf("RenderExplain missing clique or bloat ratio:\n%s", expOut)
	}

	// 2. RenderDoctor with Phantom FD Leak
	docOut := colorR.RenderDoctor(DoctorReport{
		CheckedAt: now,
		Healthy:   false,
		Checks: []DoctorCheck{
			{Name: "Docker Engine Socket", Status: CheckPass, Summary: "API v1.46 responsive"},
			{Name: "Phantom Open-FD Leaks", Status: CheckWarn, Summary: "4.00 GiB held by deleted log", Remediation: "Truncate or restart container"},
		},
		Phantom: kernel.PhantomReport{
			Supported:        true,
			TotalLeakedBytes: int64(4 * gib),
			Findings: []kernel.PhantomFD{
				{PID: 4120, FD: 1, Comm: "node", ContainerID: "abcdef1234567890", SizeBytes: int64(4 * gib), DeletedPath: "/var/lib/docker/containers/x/x-json.log"},
			},
		},
	})
	if !strings.Contains(docOut, "\x1b[") || !strings.Contains(docOut, "4120") {
		t.Fatalf("color RenderDoctor missing ANSI escapes or PID 4120:\n%s", docOut)
	}

	// 3. RenderTopFrame, RenderROI, RenderCycle, RenderVerifyAudit
	roiRep := finops.ComputeReport(finops.PersistedState{
		TotalCycles:               10,
		ActiveReclaimCycles:       4,
		TotalActualReclaimedBytes: 80 * gib,
		ENOSPCAvertedCount:        2,
		BuildCachePreservedCycles: 4,
	}, config.Default().Telemetry)

	cyc := engine.CycleReport{
		CycleID:                  "cyc-ui-1",
		Trigger:                  "manual",
		InitialRegime:            disk.RegimeCritical,
		FinalRegime:              disk.RegimeNominal,
		BeforeDisk:               snap,
		AfterDisk:                disk.Snapshot{UsedPercent: 68.0},
		ActualDiskReclaimedBytes: 20 * gib,
		TargetSatisfied:          true,
		BuildCachePreserved:      true,
		Duration:                 420 * time.Millisecond,
		Stages: []engine.StageResult{
			{Stage: engine.Stage1ContainersNetworks, Executed: true, ItemsDeleted: 3, StoppedEarlyAfter: true},
		},
	}

	topOut := plainR.RenderTopFrame(TopFrame{
		CapturedAt: now,
		Iteration:  1,
		Regime:     disk.RegimeNominal,
		Disk:       snap,
		Forecast:   disk.ForecastResult{BlockVelocityBps: 2 * float64(mib), BlockTTESeconds: 3600},
		PSI:        kernel.PSISnapshot{Supported: true, IOSome: kernel.PressureLine{Avg10: 4.5}},
		Breaker:    docker.BreakerStats{State: docker.BreakerClosed},
		FinOps:     roiRep,
		LastCycle:  &cyc,
	}, true)
	if strings.Contains(topOut, "\x1b[") || !strings.Contains(topOut, "dock-prune-daemon top") {
		t.Fatalf("unexpected plain RenderTopFrame output:\n%s", topOut)
	}

	roiOut := plainR.RenderROI(roiRep)
	if !strings.Contains(roiOut, "https://github.com/sponsors/PedroMartinezag") {
		t.Fatalf("RenderROI missing sponsor URL:\n%s", roiOut)
	}

	cycOut := plainR.RenderCycle(cyc)
	if !strings.Contains(cycOut, "early stop") {
		t.Fatalf("RenderCycle missing early stop marker:\n%s", cycOut)
	}

	verOut := plainR.RenderVerifyAudit(audit.VerifyResult{
		LedgerPath:    "/var/lib/dock-prune-daemon/audit.jsonl",
		KeyID:         "ed25519:1122334455667788",
		VerifiedCount: 12,
		FirstSequence: 1,
		LastSequence:  12,
		HeadHash:      strings.Repeat("a", 64),
	})
	if !strings.Contains(verOut, "VERIFICATION PASSED") {
		t.Fatalf("unexpected RenderVerifyAudit output:\n%s", verOut)
	}
}
