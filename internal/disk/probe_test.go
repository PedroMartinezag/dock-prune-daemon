package disk

import (
	"math"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

func TestOSProbe_MeasuresRealHostFilesystem(t *testing.T) {
	t.Parallel()

	probe := NewOSProbe()
	snap, err := probe.Measure(t.TempDir())
	if err != nil {
		t.Fatalf("OSProbe.Measure() unexpected error: %v", err)
	}
	if snap.TotalBytes == 0 {
		t.Fatal("expected TotalBytes > 0 on live filesystem")
	}
	if snap.UsedPercent < 0.0 || snap.UsedPercent > 100.0 {
		t.Fatalf("UsedPercent out of bounds: %.2f", snap.UsedPercent)
	}

	if _, err := probe.Measure("   "); err == nil {
		t.Fatal("expected error for empty probe path")
	}
}

func TestBytesNeededToReachTarget_ExactMath(t *testing.T) {
	t.Parallel()

	const gib = uint64(1024 * 1024 * 1024)

	// 100 GiB usable pool: 85 GiB used, 15 GiB free => 85% used.
	snap := Snapshot{
		TotalBytes:  100 * gib,
		UsedBytes:   85 * gib,
		FreeBytes:   15 * gib,
		UsedPercent: 85.0,
	}

	// Case 1: Target 70% requires bringing UsedBytes to 70 GiB => reclaim 15 GiB (free becomes 30 GiB >= 5 GiB floor).
	gotPctBound := snap.BytesNeededToReachTarget(70.0, 5*gib)
	if gotPctBound != 15*gib {
		t.Fatalf("percentage-bound deficit = %d, want %d", gotPctBound, 15*gib)
	}

	// Case 2: MinFreeBytes floor of 40 GiB requires freeing 25 GiB (strictly larger than 15 GiB percentage bound).
	gotFloorBound := snap.BytesNeededToReachTarget(70.0, 40*gib)
	if gotFloorBound != 25*gib {
		t.Fatalf("floor-bound deficit = %d, want %d", gotFloorBound, 25*gib)
	}
}

func TestEvaluate_AllSixPressureRegimesAndHysteresis(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	wm := cfg.Watermarks
	fcCfg := cfg.Forecast
	idleFC := ForecastResult{BlockTTESeconds: -1, InodeTTESeconds: -1}
	const gib = uint64(1024 * 1024 * 1024)

	// 1. NOMINAL
	nominalSnap := Snapshot{
		TotalBytes:       100 * gib,
		UsedBytes:        50 * gib,
		FreeBytes:        50 * gib,
		UsedPercent:      50.0,
		TotalInodes:      1_000_000,
		FreeInodes:       800_000,
		UsedInodes:       200_000,
		InodeUsedPercent: 20.0,
	}
	if a := Evaluate(nominalSnap, idleFC, wm, fcCfg); a.Regime != RegimeNominal || a.ShouldPrune() {
		t.Fatalf("expected NOMINAL, got %+v", a)
	}

	// 2. PREEMPTIVE (68% used >= 65% preemptive band, and TTE = 600s <= 1800s horizon)
	preSnap := nominalSnap
	preSnap.UsedBytes = 68 * gib
	preSnap.FreeBytes = 32 * gib
	preSnap.UsedPercent = 68.0
	soonFC := ForecastResult{Ready: true, BlockTTESeconds: 600}
	preAssess := Evaluate(preSnap, soonFC, wm, fcCfg)
	if preAssess.Regime != RegimePreemptive || !preAssess.ShouldPrune() || preAssess.AllowDeepDAGPrune() {
		t.Fatalf("expected PREEMPTIVE without Stage 4 DAG unlock, got %+v", preAssess)
	}

	// 3. ELEVATED via Inode pressure even when blocks are only 40% used
	inodeSnap := nominalSnap
	inodeSnap.UsedPercent = 40.0
	inodeSnap.InodeUsedPercent = 85.0
	elevAssess := Evaluate(inodeSnap, idleFC, wm, fcCfg)
	if elevAssess.Regime != RegimeElevated || !elevAssess.ShouldPrune() {
		t.Fatalf("expected ELEVATED on high inode usage, got %+v", elevAssess)
	}
	if HasReachedTarget(inodeSnap, wm) {
		t.Fatal("HasReachedTarget must return false while InodeUsedPercent > InodeTargetPercent")
	}

	// 4. CRITICAL unlocks deep OCI Layer DAG pruning
	critSnap := nominalSnap
	critSnap.UsedBytes = 92 * gib
	critSnap.FreeBytes = 8 * gib
	critSnap.UsedPercent = 92.0
	critAssess := Evaluate(critSnap, idleFC, wm, fcCfg)
	if critAssess.Regime != RegimeCritical || !critAssess.AllowDeepDAGPrune() || critAssess.IsEmergency() {
		t.Fatalf("expected CRITICAL with DAG unlock, got %+v", critAssess)
	}

	// 5. PANIC triggered by free space dropping below 2 GiB panic floor
	panicSnap := nominalSnap
	panicSnap.UsedBytes = 99 * gib
	panicSnap.FreeBytes = 1 * gib
	panicSnap.UsedPercent = 99.0
	panicAssess := Evaluate(panicSnap, idleFC, wm, fcCfg)
	if panicAssess.Regime != RegimePanic || !panicAssess.IsEmergency() {
		t.Fatalf("expected PANIC emergency regime, got %+v", panicAssess)
	}
}

func TestForecaster_LinearConvergence_QuadraticAcceleration_AndZScoreBurst(t *testing.T) {
	t.Parallel()

	fcCfg := config.Default().Forecast
	const mib = uint64(1024 * 1024)
	const gib = uint64(1024 * 1024 * 1024)

	// Part A: Steady 10 MiB/s linear write rate
	fcLinear := NewForecaster(fcCfg, 0)
	t0 := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	total := 100 * gib
	used := 50 * gib

	var resLinear ForecastResult
	for step := 0; step <= 12; step++ {
		curUsed := used + uint64(step)*100*mib // +100 MiB every 10s = 10 MiB/s
		resLinear = fcLinear.Observe(Snapshot{
			SampledAt:  t0.Add(time.Duration(step*10) * time.Second),
			TotalBytes: total,
			UsedBytes:  curUsed,
			FreeBytes:  total - curUsed,
		})
	}

	wantVel := float64(10 * mib)
	if math.Abs(resLinear.BlockVelocityBps-wantVel)/wantVel > 0.05 {
		t.Fatalf("linear velocity = %.2f B/s, want ~%.2f B/s", resLinear.BlockVelocityBps, wantVel)
	}

	// Part B: Accelerating runaway writer must predict strictly shorter TTE than linear velocity alone
	fcAccel := NewForecaster(fcCfg, 0)
	var resAccel ForecastResult
	for step := 0; step <= 10; step++ {
		// Quadratic growth: 0.5 * 2 MiB/s^2 * t^2
		elapsedSec := uint64(step * 10)
		curUsed := used + mib*elapsedSec*elapsedSec
		resAccel = fcAccel.Observe(Snapshot{
			SampledAt:  t0.Add(time.Duration(elapsedSec) * time.Second),
			TotalBytes: total,
			UsedBytes:  curUsed,
			FreeBytes:  total - curUsed,
		})
	}
	if resAccel.BlockAccelBps2 <= 0 {
		t.Fatalf("expected positive acceleration on quadratic growth, got %.2f", resAccel.BlockAccelBps2)
	}
	naiveLinearTTE := float64(total-(used+mib*100*100)) / resAccel.BlockVelocityBps
	if !(resAccel.BlockTTESeconds > 0 && resAccel.BlockTTESeconds < naiveLinearTTE) {
		t.Fatalf("expected quadratic TTE (%.2fs) < naive linear TTE (%.2fs)", resAccel.BlockTTESeconds, naiveLinearTTE)
	}

	// Part C: Sudden 80 MiB/s log storm after 6 calm samples triggers Z-score anomaly
	fcBurst := NewForecaster(fcCfg, 0)
	curUsed := 60 * gib
	for step := 0; step < 7; step++ {
		curUsed += 512 * 1024 // gentle 51.2 KiB/s trickle over 10s intervals
		fcBurst.Observe(Snapshot{
			SampledAt:  t0.Add(time.Duration(step*10) * time.Second),
			TotalBytes: total,
			UsedBytes:  curUsed,
			FreeBytes:  total - curUsed,
		})
	}
	// Step 7: sudden +800 MiB spike in 10 seconds (80 MiB/s)
	curUsed += 800 * mib
	burstRes := fcBurst.Observe(Snapshot{
		SampledAt:  t0.Add(70 * time.Second),
		TotalBytes: total,
		UsedBytes:  curUsed,
		FreeBytes:  total - curUsed,
	})
	if !burstRes.AnomalyTriggered || burstRes.BurnZScore < fcCfg.ZScoreThreshold {
		t.Fatalf("expected Z-score burst anomaly trigger, got %+v", burstRes)
	}

	// Part D: Large 10 GiB reclamation drop must not turn smoothed velocity deeply negative
	curUsed -= 10 * gib
	afterPrune := fcBurst.Observe(Snapshot{
		SampledAt:  t0.Add(80 * time.Second),
		TotalBytes: total,
		UsedBytes:  curUsed,
		FreeBytes:  total - curUsed,
	})
	if afterPrune.BlockVelocityBps < 0 {
		t.Fatalf("reclamation drop corrupted velocity into negative state: %.2f", afterPrune.BlockVelocityBps)
	}
}
