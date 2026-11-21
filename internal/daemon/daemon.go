package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/telemetry"
)

// Options configures all dependencies for the autonomous storage control plane Coordinator.
type Options struct {
	ConfigStore *config.Store
	Engine      docker.Engine
	Probe       disk.Probe
	Forecaster  *disk.Forecaster
	Governor    *kernel.Governor
	Phantom     *kernel.PhantomScanner
	Logger      *slog.Logger
	NowFn       func() time.Time
	SleepFn     func(ctx context.Context, d time.Duration) error
}

// Coordinator runs the unified periodic ticker, debounced Docker /events stream,
// SIGHUP atomic hot-reload, cooldown guard, Ed25519 Merkle ledger, HMAC webhooks,
// FinOps ROI persistence, and HTTP/SSE control plane server.
type Coordinator struct {
	cfgStore *config.Store
	eng      docker.Engine
	probe    disk.Probe
	forecast *disk.Forecaster
	pruner   *engine.Pruner
	ledger   *audit.Ledger
	notifier *audit.Notifier
	finops   *finops.Tracker
	registry *telemetry.Registry
	httpSrv  *telemetry.Server
	logger   *slog.Logger
	nowFn    func() time.Time

	reloadNotify chan time.Duration

	cooldownMu       sync.Mutex
	lastActivePrune  time.Time
}

// NewCoordinator wires and validates all control-plane subsystems prior to entering Run.
func NewCoordinator(opts Options) (*Coordinator, error) {
	if opts.ConfigStore == nil {
		return nil, errors.New("coordinator requires a non-nil config.Store")
	}
	if opts.Engine == nil {
		return nil, errors.New("coordinator requires a non-nil docker.Engine")
	}

	cfg := opts.ConfigStore.Current()
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	nowFn := opts.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	probe := opts.Probe
	if probe == nil {
		probe = disk.NewOSProbe()
	}
	fc := opts.Forecaster
	if fc == nil {
		fc = disk.NewForecaster(cfg.Forecast, cfg.Watermarks.PanicFreeBytes)
	}

	pruner, err := engine.NewPruner(engine.Dependencies{
		Engine:     opts.Engine,
		Probe:      probe,
		Forecaster: fc,
		Governor:   opts.Governor,
		Phantom:    opts.Phantom,
		NowFn:      nowFn,
		SleepFn:    opts.SleepFn,
	})
	if err != nil {
		return nil, fmt.Errorf("init pruner: %w", err)
	}

	ledger, err := audit.NewLedger(cfg.Audit)
	if err != nil {
		return nil, fmt.Errorf("init ed25519 audit ledger: %w", err)
	}
	notifier := audit.NewNotifier(cfg.Audit)

	roiTracker, err := finops.LoadOrNew(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("init finops tracker: %w", err)
	}

	registry := telemetry.NewRegistry()
	registry.UpdateFinOps(roiTracker.Snapshot(cfg.Telemetry))

	c := &Coordinator{
		cfgStore:     opts.ConfigStore,
		eng:          opts.Engine,
		probe:        probe,
		forecast:     fc,
		pruner:       pruner,
		ledger:       ledger,
		notifier:     notifier,
		finops:       roiTracker,
		registry:     registry,
		logger:       logger,
		nowFn:        nowFn,
		reloadNotify: make(chan time.Duration, 1),
	}

	if cfg.Telemetry.Enabled {
		srv, srvErr := telemetry.NewServer(telemetry.ServerOptions{
			ConfigStore: opts.ConfigStore,
			Registry:    registry,
			FinOps:      roiTracker,
			TriggerFn: func(ctx context.Context, dryRun bool, force bool) (engine.CycleReport, error) {
				return c.TriggerNow(ctx, "api-trigger", dryRun, force)
			},
			ExplainFn: func(ctx context.Context) (engine.ExplainReport, error) {
				return c.pruner.Explain(ctx, c.cfgStore.Current())
			},
		})
		if srvErr != nil {
			return nil, fmt.Errorf("init telemetry server: %w", srvErr)
		}
		c.httpSrv = srv
	}

	return c, nil
}

// Registry returns the live Prometheus/OpenMetrics telemetry registry.
func (c *Coordinator) Registry() *telemetry.Registry {
	return c.registry
}

// Reload hot-reloads configuration from disk/env on SIGHUP and adapts the poll ticker.
func (c *Coordinator) Reload() (config.Config, error) {
	updated, err := c.cfgStore.Reload()
	if err != nil {
		c.logger.Error("configuration hot-reload rejected; keeping active config", "error", err)
		return updated, err
	}

	select {
	case c.reloadNotify <- updated.Daemon.PollInterval.Std():
	default:
	}
	if c.httpSrv != nil {
		c.httpSrv.BroadcastSnapshot()
	}

	c.logger.Info("configuration hot-reloaded atomically",
		"poll_interval", updated.Daemon.PollInterval.String(),
		"target_percent", updated.Watermarks.TargetPercent,
		"high_percent", updated.Watermarks.HighPercent,
	)
	return updated, nil
}

// TriggerNow executes an immediate evaluation/reclamation cycle (used by SIGUSR1 and POST /v1/trigger),
// bypassing automatic cooldown pacing when force=true.
func (c *Coordinator) TriggerNow(
	ctx context.Context,
	trigger string,
	dryRun bool,
	force bool,
) (engine.CycleReport, error) {
	cfg := c.cfgStore.Current()
	opts := engine.RunOptions{
		Trigger:        trigger,
		Force:          force,
		DryRunOverride: &dryRun,
	}
	return c.executeAndRecord(ctx, cfg, opts)
}

// Run acquires the exclusive kernel PID lock, starts background telemetry & event
// watchers, executes an initial boot evaluation, and runs until ctx is canceled.
func (c *Coordinator) Run(ctx context.Context) error {
	cfg := c.cfgStore.Current()

	pidLock, err := AcquirePIDLock(cfg.Daemon.PIDFile)
	if err != nil {
		return err
	}
	defer func() {
		if relErr := pidLock.Release(); relErr != nil {
			c.logger.Warn("release pid lock warning", "error", relErr)
		}
	}()

	c.logger.Info("dock-prune-daemon autonomous control plane started",
		"pid_file", cfg.Daemon.PIDFile,
		"docker_host", cfg.Docker.Host,
		"docker_root", cfg.Docker.ContainerRootDir,
		"audit_key_id", c.ledger.KeyID(),
		"telemetry_enabled", cfg.Telemetry.Enabled,
		"listen_addr", cfg.Telemetry.ListenAddr,
	)

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var bgWG sync.WaitGroup
	errCh := make(chan error, 1)

	if c.httpSrv != nil {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			if srvErr := c.httpSrv.ListenAndServe(); srvErr != nil {
				select {
				case errCh <- fmt.Errorf("telemetry HTTP server failed: %w", srvErr):
				default:
				}
			}
		}()
	}

	debouncedEvents := make(chan string, 1)
	if cfg.Daemon.EventDriven {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			c.watchDockerEvents(runCtx, debouncedEvents)
		}()
	}

	// Execute immediate baseline sensing & safety check on boot.
	_, _ = c.runScheduledEvaluation(runCtx, "startup")

	pollDur := cfg.Daemon.PollInterval.Std()
	if pollDur < time.Second {
		pollDur = 30 * time.Second
	}
	ticker := time.NewTicker(pollDur)
	defer ticker.Stop()

	var loopErr error
loop:
	for {
		select {
		case <-runCtx.Done():
			break loop

		case fatalErr := <-errCh:
			loopErr = fatalErr
			cancelRun()
			break loop

		case newInterval := <-c.reloadNotify:
			if newInterval >= time.Second {
				ticker.Reset(newInterval)
			}

		case evReason := <-debouncedEvents:
			_, _ = c.runScheduledEvaluation(runCtx, evReason)

		case <-ticker.C:
			_, _ = c.runScheduledEvaluation(runCtx, "periodic")
		}
	}

	shutdownTimeout := c.cfgStore.Current().Daemon.ShutdownTimeout.Std()
	if shutdownTimeout < time.Second {
		shutdownTimeout = 15 * time.Second
	}
	shutCtx, cancelShut := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShut()

	if c.httpSrv != nil {
		if err := c.httpSrv.Shutdown(shutCtx); err != nil {
			c.logger.Warn("telemetry HTTP server shutdown warning", "error", err)
		}
	}
	if err := c.notifier.Close(shutCtx); err != nil {
		c.logger.Warn("webhook notifier drain warning", "error", err)
	}
	_ = c.eng.Close()

	bgWG.Wait()
	c.logger.Info("dock-prune-daemon shut down cleanly")
	return loopErr
}

func (c *Coordinator) runScheduledEvaluation(ctx context.Context, trigger string) (engine.CycleReport, error) {
	cfg := c.cfgStore.Current()

	// Pre-sense disk capacity so cooldown suppression keeps gauges fresh while still
	// allowing CRITICAL and PANIC emergencies to preempt cooldown immediately!
	if snap, err := c.probe.Measure(cfg.Docker.ContainerRootDir); err == nil {
		fc := c.forecast.Last()
		assess := disk.Evaluate(snap, fc, cfg.Watermarks, cfg.Forecast)
		if c.inCooldown(cfg.Daemon.Cooldown.Std()) &&
			assess.Regime != disk.RegimeCritical &&
			assess.Regime != disk.RegimePanic {
			gov := kernel.NewGovernor(cfg.Kernel)
			psiSnap, _ := gov.ReadSnapshot()
			c.registry.UpdateSensors(assess.Regime, snap, fc, psiSnap, c.eng.BreakerStats(), 0, 0)
			if c.httpSrv != nil {
				c.httpSrv.BroadcastSnapshot()
			}
			return engine.CycleReport{}, nil
		}
	}

	rep, err := c.executeAndRecord(ctx, cfg, engine.RunOptions{
		Trigger: trigger,
		Force:   false,
	})
	if err != nil {
		if !errors.Is(err, engine.ErrCycleAlreadyRunning) && !errors.Is(err, context.Canceled) {
			c.logger.Error("scheduled evaluation cycle failed", "trigger", trigger, "error", err)
		}
		return rep, err
	}
	return rep, nil
}

func (c *Coordinator) executeAndRecord(
	ctx context.Context,
	cfg config.Config,
	opts engine.RunOptions,
) (engine.CycleReport, error) {
	rep, err := c.pruner.RunCycle(ctx, cfg, opts)
	if err != nil {
		return rep, err
	}

	if !rep.DryRun && len(rep.Stages) > 0 {
		c.markActivePrune()
	}

	// Only append to the immutable Ed25519 Merkle ledger & fire webhooks when stages ran,
	// force/dry-run was requested, or the system entered a non-nominal regime.
	interestingCycle := len(rep.Stages) > 0 || opts.Force || rep.InitialRegime != disk.RegimeNominal || rep.FinalRegime != disk.RegimeNominal

	var auditRec audit.Record
	if interestingCycle {
		if err := c.finops.RecordCycle(rep); err != nil {
			c.logger.Warn("persist finops state warning", "error", err)
		}
		rec, lErr := c.ledger.Append(rep)
		if lErr != nil {
			c.logger.Error("append ed25519 audit ledger failed", "error", lErr)
		} else {
			auditRec = rec
		}
		if len(rep.Stages) > 0 || rep.InitialRegime == disk.RegimeDegraded {
			c.notifier.Enqueue(rep, auditRec)
		}
	}

	roiSnap := c.finops.Snapshot(cfg.Telemetry)
	c.registry.ObserveCycle(rep, roiSnap)
	if c.httpSrv != nil {
		c.httpSrv.BroadcastSnapshot()
	}

	if interestingCycle {
		c.logger.Info("reclamation cycle completed",
			"cycle_id", rep.CycleID,
			"trigger", rep.Trigger,
			"dry_run", rep.DryRun,
			"initial_regime", string(rep.InitialRegime),
			"final_regime", string(rep.FinalRegime),
			"before_pct", rep.BeforeDisk.UsedPercent,
			"after_pct", rep.AfterDisk.UsedPercent,
			"reclaimed_actual_bytes", rep.ActualDiskReclaimedBytes,
			"stages_executed", len(rep.Stages),
			"ledger_seq", auditRec.Sequence,
			"duration_ms", rep.Duration.Milliseconds(),
		)
	}

	return rep, nil
}

func (c *Coordinator) watchDockerEvents(ctx context.Context, out chan<- string) {
	filters := docker.NewFilters()
	filters.Add("type", "container").
		Add("type", "image").
		Add("type", "volume")

	rawEvents := make(chan docker.EventMessage, 32)

	var streamWG sync.WaitGroup
	streamWG.Add(1)
	go func() {
		defer streamWG.Done()
		_ = c.eng.StreamEvents(ctx, docker.EventsOptions{Filters: filters}, func(ev docker.EventMessage) {
			if !isStorageRelevantEvent(ev) {
				return
			}
			select {
			case rawEvents <- ev:
			default:
			}
		})
	}()

	var debounceTimer *time.Timer
	var timerCh <-chan time.Time
	var latestReason string

	stopTimer := func() {
		if debounceTimer != nil {
			if !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			timerCh = nil
		}
	}

	for {
		select {
		case <-ctx.Done():
			stopTimer()
			streamWG.Wait()
			return

		case ev := <-rawEvents:
			latestReason = fmt.Sprintf("docker-event:%s:%s", ev.Type, ev.Action)
			debounceDur := c.cfgStore.Current().Daemon.EventDebounce.Std()
			if debounceDur < 100*time.Millisecond {
				debounceDur = 5 * time.Second
			}
			if debounceTimer == nil {
				debounceTimer = time.NewTimer(debounceDur)
			} else {
				stopTimer()
				debounceTimer.Reset(debounceDur)
			}
			timerCh = debounceTimer.C

		case <-timerCh:
			timerCh = nil
			select {
			case out <- latestReason:
			default:
			}
		}
	}
}

func isStorageRelevantEvent(ev docker.EventMessage) bool {
	switch ev.Type {
	case "container":
		switch ev.Action {
		case "die", "oom", "stop", "destroy":
			return true
		}
	case "image":
		switch ev.Action {
		case "pull", "load", "import", "save", "tag", "build":
			return true
		}
	case "volume":
		if ev.Action == "create" {
			return true
		}
	}
	return false
}

func (c *Coordinator) markActivePrune() {
	c.cooldownMu.Lock()
	c.lastActivePrune = c.nowFn().UTC()
	c.cooldownMu.Unlock()
}

func (c *Coordinator) inCooldown(cooldown time.Duration) bool {
	if cooldown <= 0 {
		return false
	}
	c.cooldownMu.Lock()
	last := c.lastActivePrune
	c.cooldownMu.Unlock()
	if last.IsZero() {
		return false
	}
	return c.nowFn().UTC().Sub(last) < cooldown
}
