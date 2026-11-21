package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
)

func TestPIDLock_ExclusiveContention_AndReacquireAfterRelease(t *testing.T) {
	t.Parallel()

	pidPath := filepath.Join(t.TempDir(), "dock-prune.pid")

	lock1, err := AcquirePIDLock(pidPath)
	if err != nil {
		t.Fatalf("initial AcquirePIDLock failed: %v", err)
	}

	// Second concurrent lock on same path must fail immediately with ErrPIDLocked!
	if _, err := AcquirePIDLock(pidPath); !errors.Is(err, ErrPIDLocked) {
		t.Fatalf("expected ErrPIDLocked on duplicate acquire, got %v", err)
	}

	if err := lock1.Release(); err != nil {
		t.Fatalf("lock1.Release() error: %v", err)
	}

	// Re-acquisition after Release must succeed cleanly.
	lock2, err := AcquirePIDLock(pidPath)
	if err != nil {
		t.Fatalf("re-acquire after Release failed: %v", err)
	}
	if err := lock2.Release(); err != nil {
		t.Fatalf("lock2.Release() error: %v", err)
	}
}

type fakeDaemonEngine struct {
	docker.Engine
	mu        sync.Mutex
	total     uint64
	used      uint64
	eventCh   chan docker.EventMessage
	pruneRuns atomic.Int32
}

func (f *fakeDaemonEngine) Measure(path string) (disk.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	free := f.total - f.used
	pct := (float64(f.used) / float64(f.total)) * 100.0
	return disk.Snapshot{
		Path:             path,
		SampledAt:        time.Now().UTC(),
		TotalBytes:       f.total,
		UsedBytes:        f.used,
		FreeBytes:        free,
		RawFreeBytes:     free,
		UsedPercent:      pct,
		TotalInodes:      500_000,
		FreeInodes:       400_000,
		UsedInodes:       100_000,
		InodeUsedPercent: 20.0,
	}, nil
}

func (f *fakeDaemonEngine) setUsed(u uint64) {
	f.mu.Lock()
	f.used = u
	f.mu.Unlock()
}

func (f *fakeDaemonEngine) BreakerStats() docker.BreakerStats {
	return docker.BreakerStats{State: docker.BreakerClosed}
}

func (f *fakeDaemonEngine) ListContainers(context.Context, docker.ListContainersOptions) ([]docker.ContainerSummary, error) {
	return nil, nil
}

func (f *fakeDaemonEngine) PruneNetworks(context.Context, docker.Filters) (docker.NetworksPruneReport, error) {
	return docker.NetworksPruneReport{}, nil
}

func (f *fakeDaemonEngine) PruneImages(context.Context, bool, docker.Filters) (docker.ImagesPruneReport, error) {
	f.pruneRuns.Add(1)
	f.mu.Lock()
	const freed = 20 * 1024 * 1024 * 1024
	if f.used > freed {
		f.used -= freed
	}
	f.mu.Unlock()
	return docker.ImagesPruneReport{SpaceReclaimed: freed}, nil
}

func (f *fakeDaemonEngine) PruneBuildCache(context.Context, docker.BuildCachePruneOptions) (docker.BuildCachePruneReport, error) {
	return docker.BuildCachePruneReport{}, nil
}

func (f *fakeDaemonEngine) ListImages(context.Context, docker.ListImagesOptions) ([]docker.ImageSummary, error) {
	return nil, nil
}

func (f *fakeDaemonEngine) StreamEvents(ctx context.Context, _ docker.EventsOptions, onEvent func(docker.EventMessage)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-f.eventCh:
			onEvent(ev)
		}
	}
}

func (f *fakeDaemonEngine) Close() error { return nil }

func TestCoordinator_EventDebounce_HotReload_TriggerNow_AndEd25519Audit(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	cfgPath := filepath.Join(stateDir, "daemon.json")

	const gib = uint64(1024 * 1024 * 1024)
	if err := os.WriteFile(cfgPath, []byte(`{
		"log_level": "info",
		"daemon": {
			"poll_interval": "10s",
			"cooldown": "0s",
			"event_driven": true,
			"event_debounce": "100ms"
		},
		"prune": {
			"enable_log_truncate": false
		},
		"telemetry": {
			"enabled": true,
			"listen_addr": "127.0.0.1:0"
		}
	}`), 0o600); err != nil {
		t.Fatalf("write daemon.json: %v", err)
	}

	envLookup := func(k string) (string, bool) {
		if k == "DPD_STATE_DIR" {
			return stateDir, true
		}
		return "", false
	}

	initialCfg, err := config.Load(cfgPath, envLookup, nil)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	store, err := config.NewStore(initialCfg, cfgPath, envLookup)
	if err != nil {
		t.Fatalf("config.NewStore: %v", err)
	}

	mockEng := &fakeDaemonEngine{
		total:   100 * gib,
		used:    50 * gib, // Starts NOMINAL (50%)
		eventCh: make(chan docker.EventMessage, 16),
	}

	quietLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	coord, err := NewCoordinator(Options{
		ConfigStore: store,
		Engine:      mockEng,
		Probe:       mockEng,
		Logger:      quietLogger,
		SleepFn:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- coord.Run(runCtx)
	}()

	// Wait briefly for startup baseline cycle to complete.
	time.Sleep(80 * time.Millisecond)

	// 1. Push disk to 85% ELEVATED and emit a burst of 5 Docker events -> coalesces into 1 prune!
	mockEng.setUsed(85 * gib)
	for i := 0; i < 5; i++ {
		mockEng.eventCh <- docker.EventMessage{Type: "image", Action: "pull", Time: time.Now().Unix()}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mockEng.pruneRuns.Load() >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := mockEng.pruneRuns.Load(); got != 1 {
		t.Fatalf("expected 5-event burst to debounce into exactly 1 prune cycle, got %d", got)
	}

	// 2. Test SIGHUP atomic Reload()
	if err := os.WriteFile(cfgPath, []byte(`{
		"log_level": "debug",
		"daemon": {
			"poll_interval": "20s",
			"cooldown": "0s",
			"event_driven": true,
			"event_debounce": "100ms"
		},
		"prune": { "enable_log_truncate": false },
		"telemetry": { "enabled": true, "listen_addr": "127.0.0.1:0" }
	}`), 0o600); err != nil {
		t.Fatalf("update daemon.json: %v", err)
	}
	reloaded, err := coord.Reload()
	if err != nil || reloaded.LogLevel != "debug" {
		t.Fatalf("Reload() failed: cfg=%+v err=%v", reloaded, err)
	}

	// 3. Test TriggerNow(dryRun=true, force=true)
	trigRep, err := coord.TriggerNow(context.Background(), "sigusr1-test", true, true)
	if err != nil || !trigRep.DryRun {
		t.Fatalf("TriggerNow failed: rep=%+v err=%v", trigRep, err)
	}

	// 4. Cancel context and verify clean shutdown + valid Ed25519 Merkle ledger on disk!
	cancelRun()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Coordinator.Run returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Coordinator.Run hung during shutdown")
	}

	pubKey, _, err := audit.LoadPublicKey(initialCfg.Audit.PublicKeyPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	vres, err := audit.VerifyFile(initialCfg.Audit.LedgerPath, pubKey)
	if err != nil || vres.VerifiedCount < 2 {
		t.Fatalf("expected >=2 cryptographically verified audit records, got res=%+v err=%v", vres, err)
	}
}
