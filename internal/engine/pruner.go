package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/graph"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

// ErrCycleAlreadyRunning indicates another reclamation cycle holds the atomic execution lock.
var ErrCycleAlreadyRunning = errors.New("reclamation cycle is already running")

// StageID identifies each tier of the 5-stage surgical storage reclamation waterfall.
type StageID string

const (
	Stage0LogTruncate        StageID = "stage0_container_logs"
	Stage1ContainersNetworks StageID = "stage1_containers_networks"
	Stage2DanglingImages     StageID = "stage2_dangling_images"
	Stage3BuildCache         StageID = "stage3_buildkit_cache"
	Stage4DAGAndVolumes      StageID = "stage4_oci_dag_volumes"
)

// RunOptions controls per-cycle trigger attribution and manual override flags.
type RunOptions struct {
	Trigger        string
	Force          bool
	DryRunOverride *bool
}

// StageResult captures execution telemetry and byte accounting for a single waterfall tier.
type StageResult struct {
	Stage                  StageID       `json:"stage"`
	Executed               bool          `json:"executed"`
	DryRun                 bool          `json:"dry_run"`
	ItemsDeleted           int           `json:"items_deleted"`
	ReportedReclaimedBytes uint64        `json:"reported_reclaimed_bytes"`
	DiskDeltaBytes         uint64        `json:"disk_delta_bytes"`
	PSIPauseApplied        time.Duration `json:"psi_pause_applied"`
	Duration               time.Duration `json:"duration"`
	StoppedEarlyAfter      bool          `json:"stopped_early_after"`
	Details                []string      `json:"details,omitempty"`
}

// CycleReport is the canonical execution record consumed by the Ed25519 Merkle ledger,
// HMAC webhook notifier, FinOps ROI engine, OpenMetrics exporter, and ANSI CLI UI.
type CycleReport struct {
	CycleID                  string                 `json:"cycle_id"`
	Trigger                  string                 `json:"trigger"`
	StartedAt                time.Time              `json:"started_at"`
	CompletedAt              time.Time              `json:"completed_at"`
	Duration                 time.Duration          `json:"duration"`
	DryRun                   bool                   `json:"dry_run"`
	InitialRegime            disk.Regime            `json:"initial_regime"`
	FinalRegime              disk.Regime            `json:"final_regime"`
	Reasons                  []string               `json:"reasons,omitempty"`
	TargetReclaimBytes       uint64                 `json:"target_reclaim_bytes"`
	BeforeDisk               disk.Snapshot          `json:"before_disk"`
	AfterDisk                disk.Snapshot          `json:"after_disk"`
	Forecast                 disk.ForecastResult    `json:"forecast"`
	PSI                      kernel.PSISnapshot     `json:"psi"`
	PhantomLeakedBytes       int64                  `json:"phantom_leaked_bytes"`
	PhantomFindings          int                    `json:"phantom_findings"`
	Stages                   []StageResult          `json:"stages,omitempty"`
	LogEntries               []LogTruncateEntry     `json:"log_entries,omitempty"`
	DAGPlan                  *graph.ReclamationPlan `json:"dag_plan,omitempty"`
	ReportedReclaimedBytes   uint64                 `json:"reported_reclaimed_bytes"`
	ActualDiskReclaimedBytes uint64                 `json:"actual_disk_reclaimed_bytes"`
	TargetSatisfied          bool                   `json:"target_satisfied"`
	BuildCachePreserved      bool                   `json:"build_cache_preserved"`
	ENOSPCAverted            bool                   `json:"enospc_averted"`
	BreakerState             docker.BreakerState    `json:"breaker_state"`
	Warnings                 []string               `json:"warnings,omitempty"`
}

// ExplainReport holds a complete read-only diagnostic snapshot of disk state,
// Holt-Winters forecast, Linux PSI pressure, Phantom FDs, and OCI Layer DAG plans.
type ExplainReport struct {
	CapturedAt time.Time             `json:"captured_at"`
	Disk       disk.Snapshot         `json:"disk"`
	Forecast   disk.ForecastResult   `json:"forecast"`
	Assessment disk.Assessment       `json:"assessment"`
	PSI        kernel.PSISnapshot    `json:"psi"`
	Phantom    kernel.PhantomReport  `json:"phantom"`
	DAG        *graph.DAG            `json:"dag"`
	Plan       graph.ReclamationPlan `json:"plan"`
	Breaker    docker.BreakerStats   `json:"breaker"`
}

// Dependencies wires system interfaces into Pruner for production and deterministic testing.
type Dependencies struct {
	Engine     docker.Engine
	Probe      disk.Probe
	Forecaster *disk.Forecaster
	Governor   *kernel.Governor
	Phantom    *kernel.PhantomScanner
	NowFn      func() time.Time
	SleepFn    func(ctx context.Context, d time.Duration) error
}

// Pruner coordinates sensor evaluation, Linux PSI adaptive pacing, and the 5-stage
// surgical reclamation waterfall under an atomic single-flight lock.
type Pruner struct {
	eng        docker.Engine
	probe      disk.Probe
	forecaster *disk.Forecaster
	governor   *kernel.Governor
	phantom    *kernel.PhantomScanner
	nowFn      func() time.Time
	sleepFn    func(ctx context.Context, d time.Duration) error

	running   atomic.Bool
	cycleSeq  atomic.Uint64
	truncHook func(cleanPath string)
}

// NewPruner validates required subsystem interfaces and constructs a Pruner.
func NewPruner(deps Dependencies) (*Pruner, error) {
	if deps.Engine == nil {
		return nil, errors.New("engine dependency cannot be nil")
	}
	probe := deps.Probe
	if probe == nil {
		probe = disk.NewOSProbe()
	}
	nowFn := deps.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	sleepFn := deps.SleepFn
	if sleepFn == nil {
		sleepFn = sleepContext
	}
	fc := deps.Forecaster
	if fc == nil {
		def := config.Default()
		fc = disk.NewForecaster(def.Forecast, def.Watermarks.PanicFreeBytes)
	}

	return &Pruner{
		eng:        deps.Engine,
		probe:      probe,
		forecaster: fc,
		governor:   deps.Governor,
		phantom:    deps.Phantom,
		nowFn:      nowFn,
		sleepFn:    sleepFn,
	}, nil
}

// IsRunning reports whether a reclamation cycle currently holds the execution lock.
func (p *Pruner) IsRunning() bool {
	return p.running.Load()
}

// RunCycle executes one complete sense -> forecast -> waterfall -> verify control loop.
func (p *Pruner) RunCycle(ctx context.Context, cfg config.Config, opts RunOptions) (CycleReport, error) {
	if !p.running.CompareAndSwap(false, true) {
		return CycleReport{}, ErrCycleAlreadyRunning
	}
	defer p.running.Store(false)

	startedAt := p.nowFn().UTC()
	dryRun := cfg.DryRun
	if opts.DryRunOverride != nil {
		dryRun = *opts.DryRunOverride
	}
	trigger := opts.Trigger
	if trigger == "" {
		trigger = "periodic"
	}

	report := CycleReport{
		CycleID:             p.nextCycleID(startedAt),
		Trigger:             trigger,
		StartedAt:           startedAt,
		DryRun:              dryRun,
		BuildCachePreserved: true,
		BreakerState:        p.eng.BreakerStats().State,
	}

	beforeSnap, err := p.probe.Measure(cfg.Docker.ContainerRootDir)
	if err != nil {
		return report, fmt.Errorf("measure initial disk state: %w", err)
	}
	report.BeforeDisk = beforeSnap
	report.AfterDisk = beforeSnap

	fc := p.forecaster.Observe(beforeSnap)
	report.Forecast = fc

	gov := p.governor
	if gov == nil {
		gov = kernel.NewGovernor(cfg.Kernel)
	}
	if psiSnap, psiErr := gov.ReadSnapshot(); psiErr == nil {
		report.PSI = psiSnap
	} else {
		report.Warnings = append(report.Warnings, fmt.Sprintf("psi probe warning: %v", psiErr))
	}

	assessment := disk.Evaluate(beforeSnap, fc, cfg.Watermarks, cfg.Forecast)
	report.InitialRegime = assessment.Regime
	report.FinalRegime = assessment.Regime
	report.Reasons = assessment.Reasons
	report.TargetReclaimBytes = assessment.ReclaimTargetBytes

	// Check circuit breaker before attempting socket operations.
	if p.eng.BreakerStats().State == docker.BreakerOpen {
		return p.finalizeDegraded(report, "docker circuit breaker is OPEN; skipping cycle to protect daemon"), nil
	}

	shouldExecute := assessment.ShouldPrune()
	if !shouldExecute && opts.Force && !disk.HasReachedTarget(beforeSnap, cfg.Watermarks) {
		shouldExecute = true
		report.Reasons = append(report.Reasons, "manual force trigger above target watermark")
		minFree := uint64(maxInt64Zero(cfg.Watermarks.MinFreeBytes.Bytes()))
		report.TargetReclaimBytes = beforeSnap.BytesNeededToReachTarget(cfg.Watermarks.TargetPercent, minFree)
	}

	if !shouldExecute {
		report.TargetSatisfied = disk.HasReachedTarget(beforeSnap, cfg.Watermarks)
		report.CompletedAt = p.nowFn().UTC()
		report.Duration = report.CompletedAt.Sub(startedAt)
		report.BreakerState = p.eng.BreakerStats().State
		return report, nil
	}

	guard := NewGuard(cfg.Prune)
	curSnap := beforeSnap
	hadPriorExecutedStage := false

	applyInterStagePause := func() (time.Duration, error) {
		if !hadPriorExecutedStage {
			return 0, nil
		}
		if latestPSI, psiErr := gov.ReadSnapshot(); psiErr == nil {
			report.PSI = latestPSI
		}
		pause := gov.RecommendedPause(report.PSI, assessment.IsEmergency())
		if pause <= 0 {
			return 0, nil
		}
		if err := p.sleepFn(ctx, pause); err != nil {
			return 0, err
		}
		return pause, nil
	}

	reprobeAndCheckStop := func(prev disk.Snapshot) (next disk.Snapshot, delta uint64, stopEarly bool) {
		if dryRun {
			return prev, 0, false
		}
		measured, mErr := p.probe.Measure(cfg.Docker.ContainerRootDir)
		if mErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("re-probe statfs warning: %v", mErr))
			return prev, 0, false
		}
		var d uint64
		if prev.UsedBytes > measured.UsedBytes {
			d = prev.UsedBytes - measured.UsedBytes
		}
		return measured, d, disk.HasReachedTarget(measured, cfg.Watermarks)
	}

	// =========================================================================
	// STAGE 0: Forensic O_APPEND Container JSON Log Truncation (Zero-Disruption)
	// =========================================================================
	if cfg.Prune.EnableLogTruncate {
		stStart := p.nowFn()
		truncator := NewLogTruncator(cfg.Prune, cfg.Docker.ContainerRootDir)
		truncator.beforeTruncateHook = p.truncHook

		logRep, stErr := truncator.TruncateOversizedLogs(ctx, p.eng, guard, dryRun)
		if stErr != nil {
			if errors.Is(stErr, docker.ErrCircuitOpen) {
				return p.finalizeDegraded(report, stErr.Error()), nil
			}
			if errors.Is(stErr, context.Canceled) || errors.Is(stErr, context.DeadlineExceeded) {
				return report, stErr
			}
			report.Warnings = append(report.Warnings, fmt.Sprintf("stage0 warning: %v", stErr))
		} else {
			hadPriorExecutedStage = true
			report.LogEntries = logRep.Entries
			report.ReportedReclaimedBytes += logRep.BytesReclaimed

			nextSnap, delta, stop := reprobeAndCheckStop(curSnap)
			curSnap = nextSnap

			stRes := StageResult{
				Stage:                  Stage0LogTruncate,
				Executed:               true,
				DryRun:                 dryRun,
				ItemsDeleted:           logRep.TruncatedCount,
				ReportedReclaimedBytes: logRep.BytesReclaimed,
				DiskDeltaBytes:         delta,
				Duration:               p.nowFn().Sub(stStart),
				StoppedEarlyAfter:      stop,
			}
			if logRep.SkippedRotationRace > 0 {
				stRes.Details = append(stRes.Details, fmt.Sprintf("safely skipped %d concurrent log rotation(s)", logRep.SkippedRotationRace))
			}
			report.Stages = append(report.Stages, stRes)
			if stop {
				return p.finalizeCycle(report, curSnap, cfg), nil
			}
		}
	}

	// =========================================================================
	// STAGE 1: Stopped Containers & Unused Networks (PolicyGuard Enforced)
	// =========================================================================
	{
		pause, err := applyInterStagePause()
		if err != nil {
			return report, err
		}
		stStart := p.nowFn()
		stRes, abortDegraded, stErr := p.runStage1ContainersAndNetworks(ctx, guard, stStart, dryRun)
		if stErr != nil {
			return report, stErr
		}
		if abortDegraded != "" {
			return p.finalizeDegraded(report, abortDegraded), nil
		}

		hadPriorExecutedStage = true
		stRes.PSIPauseApplied = pause
		stRes.Duration = p.nowFn().Sub(stStart)
		report.ReportedReclaimedBytes += stRes.ReportedReclaimedBytes

		nextSnap, delta, stop := reprobeAndCheckStop(curSnap)
		curSnap = nextSnap
		stRes.DiskDeltaBytes = delta
		stRes.StoppedEarlyAfter = stop
		report.Stages = append(report.Stages, stRes)
		if stop {
			return p.finalizeCycle(report, curSnap, cfg), nil
		}
	}

	// =========================================================================
	// STAGE 2: Dangling OCI Images (<none>:<none>)
	// =========================================================================
	{
		pause, err := applyInterStagePause()
		if err != nil {
			return report, err
		}
		stStart := p.nowFn()
		stRes, abortDegraded, stErr := p.runStage2DanglingImages(ctx, guard, stStart, dryRun)
		if stErr != nil {
			return report, stErr
		}
		if abortDegraded != "" {
			return p.finalizeDegraded(report, abortDegraded), nil
		}

		hadPriorExecutedStage = true
		stRes.PSIPauseApplied = pause
		stRes.Duration = p.nowFn().Sub(stStart)
		report.ReportedReclaimedBytes += stRes.ReportedReclaimedBytes

		nextSnap, delta, stop := reprobeAndCheckStop(curSnap)
		curSnap = nextSnap
		stRes.DiskDeltaBytes = delta
		stRes.StoppedEarlyAfter = stop
		report.Stages = append(report.Stages, stRes)
		if stop {
			return p.finalizeCycle(report, curSnap, cfg), nil
		}
	}

	// =========================================================================
	// STAGE 3: BuildKit / Builder Cache (Warm Budget Preserved Unless PANIC)
	// =========================================================================
	{
		pause, err := applyInterStagePause()
		if err != nil {
			return report, err
		}
		stStart := p.nowFn()
		keepStorage := maxInt64Zero(cfg.Prune.BuildCacheKeepBytes.Bytes())
		pruneAllCache := false
		if assessment.IsEmergency() {
			keepStorage = 0
			pruneAllCache = true
		}

		stRes := StageResult{
			Stage:    Stage3BuildCache,
			Executed: true,
			DryRun:   dryRun,
		}
		if dryRun {
			stRes.Details = []string{fmt.Sprintf("simulated buildkit prune (keep_storage=%s)", config.ByteSize(keepStorage))}
		} else {
			bcFilters := docker.NewFilters()
			if !assessment.IsEmergency() && cfg.Prune.MinResourceAge.Std() > 0 {
				bcFilters.AddUntil(cfg.Prune.MinResourceAge.Std())
			}
			bcRep, bcErr := p.eng.PruneBuildCache(ctx, docker.BuildCachePruneOptions{
				All:         pruneAllCache,
				KeepStorage: keepStorage,
				Filters:     bcFilters,
			})
			if bcErr != nil {
				if errors.Is(bcErr, docker.ErrCircuitOpen) {
					return p.finalizeDegraded(report, bcErr.Error()), nil
				}
				var apiErr *docker.APIError
				if errors.As(bcErr, &apiErr) && (apiErr.IsNotImplemented() || apiErr.IsNotFound()) {
					stRes.Details = []string{"builder cache prune unsupported on daemon; skipped"}
				} else if errors.Is(bcErr, context.Canceled) || errors.Is(bcErr, context.DeadlineExceeded) {
					return report, bcErr
				} else {
					report.Warnings = append(report.Warnings, fmt.Sprintf("stage3 warning: %v", bcErr))
				}
			} else {
				stRes.ItemsDeleted = len(bcRep.CachesDeleted)
				stRes.ReportedReclaimedBytes = bcRep.SpaceReclaimed
				if pruneAllCache && len(bcRep.CachesDeleted) > 0 {
					report.BuildCachePreserved = false
				}
			}
		}

		hadPriorExecutedStage = true
		stRes.PSIPauseApplied = pause
		stRes.Duration = p.nowFn().Sub(stStart)
		report.ReportedReclaimedBytes += stRes.ReportedReclaimedBytes

		nextSnap, delta, stop := reprobeAndCheckStop(curSnap)
		curSnap = nextSnap
		stRes.DiskDeltaBytes = delta
		stRes.StoppedEarlyAfter = stop
		report.Stages = append(report.Stages, stRes)
		if stop {
			return p.finalizeCycle(report, curSnap, cfg), nil
		}
	}

	// =========================================================================
	// STAGE 4: Surgical OCI Layer DAG Eviction & Opt-In Anonymous Volumes
	// =========================================================================
	if (cfg.Prune.EnableStage4Images || cfg.Prune.EnableVolumePrune) && (assessment.AllowDeepDAGPrune() || opts.Force) {
		pause, err := applyInterStagePause()
		if err != nil {
			return report, err
		}
		stStart := p.nowFn()
		prevStageSnap := curSnap

		stRes, planPtr, updatedSnap, abortDegraded, stErr := p.runStage4DAGAndVolumes(
			ctx, cfg, guard, curSnap, stStart, dryRun,
		)
		if stErr != nil {
			return report, stErr
		}
		if abortDegraded != "" {
			return p.finalizeDegraded(report, abortDegraded), nil
		}

		curSnap = updatedSnap
		if planPtr != nil {
			report.DAGPlan = planPtr
		}
		stRes.PSIPauseApplied = pause
		stRes.Duration = p.nowFn().Sub(stStart)
		if !dryRun && prevStageSnap.UsedBytes > curSnap.UsedBytes {
			stRes.DiskDeltaBytes = prevStageSnap.UsedBytes - curSnap.UsedBytes
		}
		stRes.StoppedEarlyAfter = !dryRun && disk.HasReachedTarget(curSnap, cfg.Watermarks)
		report.ReportedReclaimedBytes += stRes.ReportedReclaimedBytes
		report.Stages = append(report.Stages, stRes)
	}

	return p.finalizeCycle(report, curSnap, cfg), nil
}

// Explain builds a non-destructive full diagnostic view of host pressure, PSI,
// Phantom open-FD leaks, and the OCI Layer Reference DAG eviction plan.
func (p *Pruner) Explain(ctx context.Context, cfg config.Config) (ExplainReport, error) {
	now := p.nowFn().UTC()

	snap, err := p.probe.Measure(cfg.Docker.ContainerRootDir)
	if err != nil {
		return ExplainReport{}, fmt.Errorf("measure filesystem: %w", err)
	}
	fc := p.forecaster.Last()
	if fc.Samples == 0 {
		fc = p.forecaster.Observe(snap)
	}
	assess := disk.Evaluate(snap, fc, cfg.Watermarks, cfg.Forecast)

	gov := p.governor
	if gov == nil {
		gov = kernel.NewGovernor(cfg.Kernel)
	}
	psiSnap, _ := gov.ReadSnapshot()

	scanner := p.phantom
	if scanner == nil {
		scanner = kernel.NewPhantomScanner(cfg.Kernel, cfg.Docker.ContainerRootDir)
	}
	phantomRep, _ := scanner.Scan()

	guard := NewGuard(cfg.Prune)
	dag, err := graph.BuildFromEngine(ctx, p.eng, graph.SnapshotOptions{
		Now:          now,
		ProtectCheck: guard.GraphProtectCheck(now),
	})
	if err != nil {
		return ExplainReport{}, fmt.Errorf("build OCI layer DAG: %w", err)
	}

	minFree := uint64(maxInt64Zero(cfg.Watermarks.MinFreeBytes.Bytes()))
	targetBytes := int64(snap.BytesNeededToReachTarget(cfg.Watermarks.TargetPercent, minFree))
	plan := graph.PlanReclamation(dag, graph.PlanOptions{
		TargetBytes: targetBytes,
	})

	return ExplainReport{
		CapturedAt: now,
		Disk:       snap,
		Forecast:   fc,
		Assessment: assess,
		PSI:        psiSnap,
		Phantom:    phantomRep,
		DAG:        dag,
		Plan:       plan,
		Breaker:    p.eng.BreakerStats(),
	}, nil
}

func (p *Pruner) runStage1ContainersAndNetworks(
	ctx context.Context,
	guard *Guard,
	now time.Time,
	dryRun bool,
) (StageResult, string, error) {
	res := StageResult{
		Stage:    Stage1ContainersNetworks,
		Executed: true,
		DryRun:   dryRun,
	}

	containers, err := p.eng.ListContainers(ctx, docker.ListContainersOptions{
		All:  true,
		Size: true,
	})
	if err != nil {
		if errors.Is(err, docker.ErrCircuitOpen) {
			return res, err.Error(), nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return res, "", err
		}
		res.Details = append(res.Details, fmt.Sprintf("list containers error: %v", err))
		return res, "", nil
	}

	for _, ctr := range containers {
		if err := ctx.Err(); err != nil {
			return res, "", err
		}
		if protected, _ := guard.CheckContainer(ctr, now); protected {
			continue
		}
		var rwBytes uint64
		if ctr.SizeRw > 0 {
			rwBytes = uint64(ctr.SizeRw)
		}
		if dryRun {
			res.ItemsDeleted++
			res.ReportedReclaimedBytes += rwBytes
			continue
		}
		rmErr := p.eng.RemoveContainer(ctx, ctr.ID, docker.RemoveContainerOptions{
			Force:         false,
			RemoveVolumes: false,
		})
		if rmErr != nil {
			if errors.Is(rmErr, docker.ErrCircuitOpen) {
				return res, rmErr.Error(), nil
			}
			var apiErr *docker.APIError
			if errors.As(rmErr, &apiErr) && (apiErr.IsNotFound() || apiErr.IsConflict()) {
				continue
			}
			continue
		}
		res.ItemsDeleted++
		res.ReportedReclaimedBytes += rwBytes
	}

	if !dryRun {
		netRep, netErr := p.eng.PruneNetworks(ctx, guard.BaseDockerFilters())
		if netErr != nil {
			if errors.Is(netErr, docker.ErrCircuitOpen) {
				return res, netErr.Error(), nil
			}
		} else if len(netRep.NetworksDeleted) > 0 {
			res.ItemsDeleted += len(netRep.NetworksDeleted)
			res.Details = append(res.Details, fmt.Sprintf("pruned %d unused network(s)", len(netRep.NetworksDeleted)))
		}
	}

	return res, "", nil
}

func (p *Pruner) runStage2DanglingImages(
	ctx context.Context,
	guard *Guard,
	now time.Time,
	dryRun bool,
) (StageResult, string, error) {
	res := StageResult{
		Stage:    Stage2DanglingImages,
		Executed: true,
		DryRun:   dryRun,
	}

	if dryRun {
		f := docker.NewFilters()
		f.AddDangling(true)
		imgs, err := p.eng.ListImages(ctx, docker.ListImagesOptions{Filters: f})
		if err != nil {
			if errors.Is(err, docker.ErrCircuitOpen) {
				return res, err.Error(), nil
			}
			return res, "", nil
		}
		for _, img := range imgs {
			if protected, _ := guard.CheckImageSummary(img, now); protected {
				continue
			}
			res.ItemsDeleted++
			if img.Size > 0 {
				res.ReportedReclaimedBytes += uint64(img.Size)
			}
		}
		return res, "", nil
	}

	rep, err := p.eng.PruneImages(ctx, true, guard.BaseDockerFilters())
	if err != nil {
		if errors.Is(err, docker.ErrCircuitOpen) {
			return res, err.Error(), nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return res, "", err
		}
		res.Details = append(res.Details, fmt.Sprintf("prune dangling images warning: %v", err))
		return res, "", nil
	}
	res.ItemsDeleted = len(rep.ImagesDeleted)
	res.ReportedReclaimedBytes = rep.SpaceReclaimed
	return res, "", nil
}

func (p *Pruner) runStage4DAGAndVolumes(
	ctx context.Context,
	cfg config.Config,
	guard *Guard,
	startSnap disk.Snapshot,
	now time.Time,
	dryRun bool,
) (StageResult, *graph.ReclamationPlan, disk.Snapshot, string, error) {
	res := StageResult{
		Stage:    Stage4DAGAndVolumes,
		Executed: true,
		DryRun:   dryRun,
	}
	curSnap := startSnap
	var planOut *graph.ReclamationPlan

	minFree := uint64(maxInt64Zero(cfg.Watermarks.MinFreeBytes.Bytes()))

	if cfg.Prune.EnableStage4Images {
		deficit := curSnap.BytesNeededToReachTarget(cfg.Watermarks.TargetPercent, minFree)
		dag, err := graph.BuildFromEngine(ctx, p.eng, graph.SnapshotOptions{
			Now:          now,
			ProtectCheck: guard.GraphProtectCheck(now),
		})
		if err != nil {
			if errors.Is(err, docker.ErrCircuitOpen) {
				return res, nil, curSnap, err.Error(), nil
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return res, nil, curSnap, "", err
			}
			res.Details = append(res.Details, fmt.Sprintf("build OCI DAG warning: %v", err))
		} else {
			plan := graph.PlanReclamation(dag, graph.PlanOptions{
				TargetBytes: int64(deficit),
			})
			planOut = &plan

			if dryRun {
				res.ItemsDeleted += plan.SelectedImageCount
				if plan.PlannedBytes > 0 {
					res.ReportedReclaimedBytes += uint64(plan.PlannedBytes)
				}
			} else {
				evictedSoFar := make(map[string]bool, plan.SelectedImageCount)
				for _, step := range plan.Steps {
					if err := ctx.Err(); err != nil {
						return res, planOut, curSnap, "", err
					}

					var removedInStep []string
					for _, imgID := range step.ImageIDs {
						_, rmErr := p.eng.RemoveImage(ctx, imgID, docker.RemoveImageOptions{
							Force:   false,
							NoPrune: false,
						})
						if rmErr != nil {
							if errors.Is(rmErr, docker.ErrCircuitOpen) {
								return res, planOut, curSnap, rmErr.Error(), nil
							}
							var apiErr *docker.APIError
							if errors.As(rmErr, &apiErr) && (apiErr.IsNotFound() || apiErr.IsConflict()) {
								continue
							}
							continue
						}
						removedInStep = append(removedInStep, imgID)
						res.ItemsDeleted++
					}

					if len(removedInStep) > 0 {
						actualMarginal, _ := dag.MarginalGain(removedInStep, evictedSoFar)
						if actualMarginal > 0 {
							res.ReportedReclaimedBytes += uint64(actualMarginal)
						}
						for _, id := range removedInStep {
							evictedSoFar[id] = true
						}
					}

					// Surgical step-level re-probe: halt mid-plan the instant disk reaches TargetPercent!
					if measured, mErr := p.probe.Measure(cfg.Docker.ContainerRootDir); mErr == nil {
						curSnap = measured
						if disk.HasReachedTarget(curSnap, cfg.Watermarks) {
							return res, planOut, curSnap, "", nil
						}
					}
				}
			}
		}
	}

	// Opt-in anonymous volume reclamation (named volumes are permanently immune in Guard.CheckVolume).
	if cfg.Prune.EnableVolumePrune && (dryRun || !disk.HasReachedTarget(curSnap, cfg.Watermarks)) {
		containers, cErr := p.eng.ListContainers(ctx, docker.ListContainersOptions{All: true})
		mounted := make(map[string]bool)
		if cErr == nil {
			for _, ctr := range containers {
				for _, m := range ctr.Mounts {
					if m.Name != "" {
						mounted[m.Name] = true
					}
				}
			}
		}

		volList, vErr := p.eng.ListVolumes(ctx, docker.NewFilters())
		if vErr != nil {
			if errors.Is(vErr, docker.ErrCircuitOpen) {
				return res, planOut, curSnap, vErr.Error(), nil
			}
		} else if cErr == nil {
			// Only remove volumes when container mount inventory succeeded cleanly.
			var prunedVols int
			for _, vol := range volList.Volumes {
				if protected, _ := guard.CheckVolume(vol, mounted, now); protected {
					continue
				}
				var volSize uint64
				if vol.UsageData != nil && vol.UsageData.Size > 0 {
					volSize = uint64(vol.UsageData.Size)
				}
				if dryRun {
					prunedVols++
					res.ItemsDeleted++
					res.ReportedReclaimedBytes += volSize
					continue
				}
				if rmErr := p.eng.RemoveVolume(ctx, vol.Name, false); rmErr == nil {
					prunedVols++
					res.ItemsDeleted++
					res.ReportedReclaimedBytes += volSize
				}
			}
			if prunedVols > 0 {
				res.Details = append(res.Details, fmt.Sprintf("reclaimed %d anonymous unmounted volume(s)", prunedVols))
			}
			if !dryRun {
				if measured, mErr := p.probe.Measure(cfg.Docker.ContainerRootDir); mErr == nil {
					curSnap = measured
				}
			}
		}
	}

	return res, planOut, curSnap, "", nil
}

func (p *Pruner) finalizeDegraded(report CycleReport, warning string) CycleReport {
	report.InitialRegime = disk.RegimeDegraded
	report.FinalRegime = disk.RegimeDegraded
	report.TargetSatisfied = false
	report.Warnings = append(report.Warnings, warning)
	report.BreakerState = p.eng.BreakerStats().State
	report.CompletedAt = p.nowFn().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)
	return report
}

func (p *Pruner) finalizeCycle(report CycleReport, latestSnap disk.Snapshot, cfg config.Config) CycleReport {
	if !report.DryRun {
		if measured, err := p.probe.Measure(cfg.Docker.ContainerRootDir); err == nil {
			latestSnap = measured
		}
	}
	report.AfterDisk = latestSnap

	if !report.DryRun && report.BeforeDisk.UsedBytes > latestSnap.UsedBytes {
		report.ActualDiskReclaimedBytes = report.BeforeDisk.UsedBytes - latestSnap.UsedBytes
		p.forecaster.ResetBaseline(latestSnap)
	}

	postAssess := disk.Evaluate(latestSnap, p.forecaster.Last(), cfg.Watermarks, cfg.Forecast)
	report.FinalRegime = postAssess.Regime
	report.TargetSatisfied = disk.HasReachedTarget(latestSnap, cfg.Watermarks)

	// Record ENOSPCAverted when a CRITICAL or PANIC host was successfully pulled back below CriticalPercent.
	if !report.DryRun &&
		(report.InitialRegime == disk.RegimeCritical || report.InitialRegime == disk.RegimePanic) &&
		latestSnap.UsedPercent < cfg.Watermarks.CriticalPercent {
		report.ENOSPCAverted = true
	}

	// Trigger ProcFS phantom open-FD forensics if disk pressure remains high after pruning.
	if !report.TargetSatisfied || latestSnap.UsedPercent >= cfg.Watermarks.HighPercent {
		scanner := p.phantom
		if scanner == nil {
			scanner = kernel.NewPhantomScanner(cfg.Kernel, cfg.Docker.ContainerRootDir)
		}
		if phRep, phErr := scanner.Scan(); phErr == nil && phRep.Supported {
			report.PhantomLeakedBytes = phRep.TotalLeakedBytes
			report.PhantomFindings = len(phRep.Findings)
		}
	}

	report.BreakerState = p.eng.BreakerStats().State
	report.CompletedAt = p.nowFn().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)
	return report
}

func (p *Pruner) nextCycleID(now time.Time) string {
	seq := p.cycleSeq.Add(1)
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err == nil {
		return fmt.Sprintf("cyc-%d-%s", now.Unix(), hex.EncodeToString(rnd[:]))
	}
	return fmt.Sprintf("cyc-%d-%04d", now.Unix(), seq)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func maxInt64Zero(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
