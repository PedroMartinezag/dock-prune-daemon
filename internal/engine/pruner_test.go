package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

func TestLogTruncator_OAppendZeroHole_SymlinkEscape_AndRotationRace(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	containersDir := filepath.Join(rootDir, "containers", "c_live")
	if err := os.MkdirAll(containersDir, 0o755); err != nil {
		t.Fatalf("mkdir containers: %v", err)
	}

	// 1. Live container holding an O_APPEND file descriptor while Stage 0 truncates 2 MiB -> 0B!
	liveLogPath := filepath.Join(containersDir, "c_live-json.log")
	appendWriter, err := os.OpenFile(liveLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatalf("open O_APPEND writer: %v", err)
	}
	defer appendWriter.Close()

	payload2MiB := bytes.Repeat([]byte("{\"log\":\"burst\"}\n"), 128*1024) // 2 MiB
	if _, err := appendWriter.Write(payload2MiB); err != nil {
		t.Fatalf("seed 2MiB log: %v", err)
	}

	// 2. Malicious container planting a symlink escaping outside ContainerRootDir
	outsideSecret := filepath.Join(t.TempDir(), "host-secret-json.log")
	if err := os.WriteFile(outsideSecret, payload2MiB, 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	escapeDir := filepath.Join(rootDir, "containers", "c_escape")
	_ = os.MkdirAll(escapeDir, 0o755)
	escapeSymlink := filepath.Join(escapeDir, "c_escape-json.log")
	symlinkCreated := os.Symlink(outsideSecret, escapeSymlink) == nil

	eng := newSimulatedEngine(100*giB, 85*giB)
	eng.containers = []docker.ContainerSummary{
		{ID: "c_live", Names: []string{"/api-live"}, State: "running"},
	}
	eng.containerInspects["c_live"] = docker.ContainerInspect{
		ID:      "c_live",
		Name:    "/api-live",
		LogPath: liveLogPath,
	}
	if symlinkCreated {
		eng.containers = append(eng.containers, docker.ContainerSummary{
			ID: "c_escape", Names: []string{"/evil"}, State: "running",
		})
		eng.containerInspects["c_escape"] = docker.ContainerInspect{
			ID:      "c_escape",
			Name:    "/evil",
			LogPath: escapeSymlink,
		}
	}

	pruneCfg := config.Default().Prune
	pruneCfg.EnableLogTruncate = true
	pruneCfg.MaxContainerLogBytes = 1 * config.MiB

	trunc := NewLogTruncator(pruneCfg, rootDir)
	guard := NewGuard(pruneCfg)

	rep, err := trunc.TruncateOversizedLogs(context.Background(), eng, guard, false)
	if err != nil {
		t.Fatalf("TruncateOversizedLogs error: %v", err)
	}
	if rep.TruncatedCount != 1 || rep.BytesReclaimed != uint64(len(payload2MiB)) {
		t.Fatalf("unexpected truncate report: %+v", rep)
	}
	if len(rep.Entries) != 1 || len(rep.Entries[0].ForensicSHA256) != 64 {
		t.Fatalf("missing 64-hex SHA-256 forensic digest: %+v", rep.Entries)
	}

	// Write a new line through the STILL-OPEN O_APPEND descriptor and verify NO sparse null hole!
	nextLine := []byte("{\"log\":\"post-truncate-clean\"}\n")
	if _, err := appendWriter.Write(nextLine); err != nil {
		t.Fatalf("post-truncate O_APPEND write failed: %v", err)
	}
	afterRaw, err := os.ReadFile(liveLogPath)
	if err != nil {
		t.Fatalf("read truncated log: %v", err)
	}
	if !bytes.Equal(afterRaw, nextLine) {
		t.Fatalf("O_APPEND write after truncate produced corrupt/sparse bytes (len=%d)", len(afterRaw))
	}

	// Outside file pointed to by symlink must remain untouched!
	if symlinkCreated {
		st, _ := os.Stat(outsideSecret)
		if st.Size() != int64(len(payload2MiB)) {
			t.Fatal("SECURITY VIOLATION: symlink escape truncated file outside ContainerRootDir")
		}
	}

	// 3. Deterministic Concurrent Log Rotation Race Test
	raceDir := filepath.Join(rootDir, "containers", "c_race")
	_ = os.MkdirAll(raceDir, 0o755)
	raceLogPath := filepath.Join(raceDir, "c_race-json.log")
	if err := os.WriteFile(raceLogPath, payload2MiB, 0o640); err != nil {
		t.Fatalf("write race log: %v", err)
	}

	eng.containers = []docker.ContainerSummary{
		{ID: "c_race", Names: []string{"/rotated-app"}, State: "running"},
	}
	eng.containerInspects["c_race"] = docker.ContainerInspect{
		ID:      "c_race",
		Name:    "/rotated-app",
		LogPath: raceLogPath,
	}

	freshData := bytes.Repeat([]byte("{\"log\":\"brand-new-inode\"}\n"), 64*1024) // >1.5 MiB
	truncRace := NewLogTruncator(pruneCfg, rootDir)
	truncRace.beforeTruncateHook = func(cleanPath string) {
		// Simulate dockerd rotating c_race-json.log -> c_race-json.log.1 and creating a brand-new file!
		_ = os.Rename(cleanPath, cleanPath+".1")
		_ = os.WriteFile(cleanPath, freshData, 0o640)
	}

	raceRep, err := truncRace.TruncateOversizedLogs(context.Background(), eng, guard, false)
	if err != nil {
		t.Fatalf("concurrent rotation test returned error: %v", err)
	}
	if raceRep.SkippedRotationRace != 1 || raceRep.TruncatedCount != 0 {
		t.Fatalf("expected SkippedRotationRace=1 and TruncatedCount=0, got %+v", raceRep)
	}
	rotatedStat, _ := os.Stat(raceLogPath + ".1")
	freshStat, _ := os.Stat(raceLogPath)
	if rotatedStat.Size() != int64(len(payload2MiB)) || freshStat.Size() != int64(len(freshData)) {
		t.Fatal("concurrent rotation race guard failed: truncated rotated or fresh log file")
	}
}

func TestPruner_HysteresisEarlyExitAfterStage1_PreservesBuildCacheAndDAG(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	// Start at 84 GiB / 100 GiB (84% ELEVATED > 80% HighPercent; TargetPercent = 70%).
	sim := newSimulatedEngine(100*giB, 84*giB)
	sim.containers = []docker.ContainerSummary{
		{
			ID:      "ctr_exited_heavy",
			Names:   []string{"/ci-build-job-99"},
			State:   "exited",
			Created: now.Add(-4 * time.Hour).Unix(),
			SizeRw:  int64(16 * giB), // Removing frees 16 GiB -> drops usage from 84% to 68%!
		},
		{
			ID:      "ctr_protected_k8s",
			Names:   []string{"/k8s_sidecar"},
			State:   "exited",
			Created: now.Add(-4 * time.Hour).Unix(),
			SizeRw:  int64(5 * giB),
		},
	}
	sim.buildCacheReclaim = 10 * giB

	cfg := config.Default()
	cfg.Docker.ContainerRootDir = t.TempDir()
	cfg.Prune.EnableLogTruncate = false

	pruner, err := NewPruner(Dependencies{
		Engine:  sim,
		Probe:   sim,
		NowFn:   func() time.Time { return now },
		SleepFn: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewPruner: %v", err)
	}

	rep, err := pruner.RunCycle(context.Background(), cfg, RunOptions{Trigger: "periodic"})
	if err != nil {
		t.Fatalf("RunCycle error: %v", err)
	}

	if rep.InitialRegime != disk.RegimeElevated || !rep.TargetSatisfied {
		t.Fatalf("expected ELEVATED -> TargetSatisfied=true, got %+v", rep)
	}
	if len(rep.Stages) != 1 || rep.Stages[0].Stage != Stage1ContainersNetworks || !rep.Stages[0].StoppedEarlyAfter {
		t.Fatalf("expected waterfall to stop early right after Stage 1, got stages: %+v", rep.Stages)
	}
	if sim.buildPruneCalled {
		t.Fatal("Stage 3 BuildKit cache was pruned despite reaching 68% target in Stage 1")
	}
	if !rep.BuildCachePreserved {
		t.Fatal("expected BuildCachePreserved=true")
	}
	if slices.ContainsString(sim.removedContainers, "ctr_protected_k8s") {
		t.Fatal("protected k8s_ container was erroneously deleted")
	}
}

func TestPruner_CriticalWaterfall_DAGCliqueEviction_VolumeSafety_AndDryRun(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// Helper builds an identical 93% CRITICAL host (needs 23 GiB freed to reach 70%).
	setupCriticalSim := func() (*simulatedEngine, config.Config) {
		sim := newSimulatedEngine(100*giB, 93*giB)
		sim.danglingReclaim = 2 * giB   // 93 -> 91 GiB
		sim.buildCacheReclaim = 3 * giB // 91 -> 88 GiB (still needs 18 GiB in Stage 4!)

		// Protected postgres image (must NEVER be touched)
		sim.addImage("sha256:pg16", []string{"postgres:16"}, now.Add(-100*time.Hour),
			[]simLayer{{"sha256:L_pg", int64(8 * giB)}})

		// 2-member unpinned orphan clique unlocking 16 GiB shared CUDA layer + 2 GiB + 2 GiB = 20 GiB total!
		sim.addImage("sha256:ml1", []string{"trainer:v1"}, now.Add(-72*time.Hour),
			[]simLayer{{"sha256:L_cuda", int64(16 * giB)}, {"sha256:L_m1", int64(2 * giB)}})
		sim.addImage("sha256:ml2", []string{"trainer:v2"}, now.Add(-72*time.Hour),
			[]simLayer{{"sha256:L_cuda", int64(16 * giB)}, {"sha256:L_m2", int64(2 * giB)}})

		// Named volume (immune) vs Anonymous 64-hex volume (eligible when EnableVolumePrune=true)
		anonVol := strings.Repeat("f", 64)
		sim.volumes = []docker.Volume{
			{
				Name:      "prod_database_vol",
				CreatedAt: now.Add(-200 * time.Hour).Format(time.RFC3339),
				UsageData: &docker.VolumeUsageData{Size: int64(10 * giB)},
			},
			{
				Name:      anonVol,
				CreatedAt: now.Add(-200 * time.Hour).Format(time.RFC3339),
				UsageData: &docker.VolumeUsageData{Size: int64(4 * giB)},
			},
		}

		cfg := config.Default()
		cfg.Docker.ContainerRootDir = t.TempDir()
		cfg.Prune.EnableLogTruncate = false
		cfg.Prune.EnableStage4Images = true
		cfg.Prune.EnableVolumePrune = true
		cfg.Prune.ProtectedImagePatterns = []string{"postgres:*"}
		return sim, cfg
	}

	// Part A: Dry-Run must plan everything accurately with ZERO destructive calls.
	drySim, dryCfg := setupCriticalSim()
	dryCfg.DryRun = true
	dryPruner, _ := NewPruner(Dependencies{
		Engine:  drySim,
		Probe:   drySim,
		NowFn:   func() time.Time { return now },
		SleepFn: func(context.Context, time.Duration) error { return nil },
	})
	dryRep, err := dryPruner.RunCycle(context.Background(), dryCfg, RunOptions{Trigger: "cli-dry-run"})
	if err != nil {
		t.Fatalf("dry-run RunCycle failed: %v", err)
	}
	if !dryRep.DryRun || drySim.mutations > 0 {
		t.Fatalf("dry-run executed %d mutations on Docker Engine", drySim.mutations)
	}
	if dryRep.DAGPlan == nil || dryRep.DAGPlan.SelectedImageCount != 2 {
		t.Fatalf("expected dry-run DAG plan to select 2 clique images, got %+v", dryRep.DAGPlan)
	}

	// Part B: Live execution reclaims 2 + 3 + 20 = 25 GiB (93% -> 68% <= 70%), averting ENOSPC!
	liveSim, liveCfg := setupCriticalSim()
	var sleptTotal time.Duration
	livePruner, _ := NewPruner(Dependencies{
		Engine: liveSim,
		Probe:  liveSim,
		NowFn:  func() time.Time { return now },
		SleepFn: func(_ context.Context, d time.Duration) error {
			sleptTotal += d
			return nil
		},
	})
	liveRep, err := livePruner.RunCycle(context.Background(), liveCfg, RunOptions{Trigger: "periodic"})
	if err != nil {
		t.Fatalf("live RunCycle failed: %v", err)
	}
	if !liveRep.TargetSatisfied || !liveRep.ENOSPCAverted {
		t.Fatalf("expected TargetSatisfied=true and ENOSPCAverted=true, got %+v", liveRep)
	}
	if slices.ContainsString(liveSim.removedImages, "sha256:pg16") {
		t.Fatal("protected postgres:16 image was deleted in Stage 4")
	}
	if slices.ContainsString(liveSim.removedVolumes, "prod_database_vol") {
		t.Fatal("named volume prod_database_vol was deleted")
	}

	// Part C: Read-only Explain() inspection works cleanly
	expRep, err := livePruner.Explain(context.Background(), liveCfg)
	if err != nil {
		t.Fatalf("Explain() error: %v", err)
	}
	if expRep.DAG == nil {
		t.Fatal("Explain() returned nil DAG")
	}
}

func TestPruner_PanicBypassesPSIPause_AndCircuitOpenEntersDegraded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// Setup synthetic high-PSI /proc/pressure/io (60% stall)
	procDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(procDir, "pressure"), 0o755)
	_ = os.WriteFile(filepath.Join(procDir, "pressure", "io"),
		[]byte("some avg10=60.00 avg60=40.00 avg300=10.00 total=999999\nfull avg10=30.00 avg60=10.00 avg300=2.00 total=444444\n"), 0o600)

	cfg := config.Default()
	cfg.Docker.ContainerRootDir = t.TempDir()
	cfg.Kernel.ProcRoot = procDir
	cfg.Prune.EnableLogTruncate = false

	// 98% usage => PANIC regime must apply 0ms PSI sleep despite 60% I/O stall!
	panicSim := newSimulatedEngine(100*giB, 98*giB)
	var sleeps []time.Duration
	pruner, _ := NewPruner(Dependencies{
		Engine:   panicSim,
		Probe:    panicSim,
		Governor: kernel.NewGovernor(cfg.Kernel),
		NowFn:    func() time.Time { return now },
		SleepFn: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	})

	panicRep, err := pruner.RunCycle(context.Background(), cfg, RunOptions{Trigger: "panic-test"})
	if err != nil {
		t.Fatalf("panic RunCycle error: %v", err)
	}
	if panicRep.InitialRegime != disk.RegimePanic || len(sleeps) != 0 {
		t.Fatalf("expected PANIC regime with 0 PSI sleeps, got regime=%s sleeps=%v", panicRep.InitialRegime, sleeps)
	}

	// Open Circuit Breaker => transitions safely to DEGRADED without crashing
	panicSim.breakerState = docker.BreakerOpen
	degRep, err := pruner.RunCycle(context.Background(), cfg, RunOptions{Trigger: "breaker-open"})
	if err != nil {
		t.Fatalf("degraded RunCycle returned error instead of isolating fault: %v", err)
	}
	if degRep.FinalRegime != disk.RegimeDegraded {
		t.Fatalf("expected FinalRegime=DEGRADED when breaker is OPEN, got %s", degRep.FinalRegime)
	}
}

const giB = uint64(1024 * 1024 * 1024)

type simLayer struct {
	digest string
	size   int64
}

type simulatedEngine struct {
	docker.Engine
	mu                sync.Mutex
	totalBytes        uint64
	usedBytes         uint64
	breakerState      docker.BreakerState
	mutations         int
	containers        []docker.ContainerSummary
	containerInspects map[string]docker.ContainerInspect
	imageSummaries    []docker.ImageSummary
	imageInspects     map[string]docker.ImageInspect
	imageHistories    map[string][]docker.ImageHistoryItem
	layerHolders      map[string]map[string]bool
	layerSizes        map[string]int64
	volumes           []docker.Volume
	danglingReclaim   uint64
	buildCacheReclaim uint64
	buildPruneCalled  bool
	removedContainers []string
	removedImages     []string
	removedVolumes    []string
}

func newSimulatedEngine(total, used uint64) *simulatedEngine {
	return &simulatedEngine{
		totalBytes:        total,
		usedBytes:         used,
		breakerState:      docker.BreakerClosed,
		containerInspects: make(map[string]docker.ContainerInspect),
		imageInspects:     make(map[string]docker.ImageInspect),
		imageHistories:    make(map[string][]docker.ImageHistoryItem),
		layerHolders:      make(map[string]map[string]bool),
		layerSizes:        make(map[string]int64),
	}
}

func (s *simulatedEngine) addImage(id string, tags []string, created time.Time, layers []simLayer) {
	var total int64
	digests := make([]string, 0, len(layers))
	hist := make([]docker.ImageHistoryItem, 0, len(layers))
	for _, l := range layers {
		total += l.size
		digests = append(digests, l.digest)
		s.layerSizes[l.digest] = l.size
		if s.layerHolders[l.digest] == nil {
			s.layerHolders[l.digest] = make(map[string]bool)
		}
		s.layerHolders[l.digest][id] = true
	}
	for i := len(layers) - 1; i >= 0; i-- {
		hist = append(hist, docker.ImageHistoryItem{
			ID:      layers[i].digest,
			Created: created.Unix(),
			Size:    layers[i].size,
		})
	}
	s.imageSummaries = append(s.imageSummaries, docker.ImageSummary{
		ID:       id,
		RepoTags: tags,
		Created:  created.Unix(),
		Size:     total,
	})
	s.imageInspects[id] = docker.ImageInspect{
		ID:       id,
		RepoTags: tags,
		Created:  created.Format(time.RFC3339),
		Size:     total,
		RootFS:   docker.RootFS{Type: "layers", Layers: digests},
	}
	s.imageHistories[id] = hist
}

func (s *simulatedEngine) Measure(path string) (disk.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	free := s.totalBytes - s.usedBytes
	pct := (float64(s.usedBytes) / float64(s.totalBytes)) * 100.0
	return disk.Snapshot{
		Path:             path,
		SampledAt:        time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
		TotalBytes:       s.totalBytes,
		FreeBytes:        free,
		RawFreeBytes:     free,
		UsedBytes:        s.usedBytes,
		UsedPercent:      pct,
		TotalInodes:      1_000_000,
		FreeInodes:       800_000,
		UsedInodes:       200_000,
		InodeUsedPercent: 20.0,
	}, nil
}

func (s *simulatedEngine) freeSpaceLocked(bytes uint64) {
	if bytes >= s.usedBytes {
		s.usedBytes = 0
	} else {
		s.usedBytes -= bytes
	}
}

func (s *simulatedEngine) BreakerStats() docker.BreakerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return docker.BreakerStats{State: s.breakerState}
}

func (s *simulatedEngine) ListContainers(context.Context, docker.ListContainersOptions) ([]docker.ContainerSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.breakerState == docker.BreakerOpen {
		return nil, docker.ErrCircuitOpen
	}
	out := make([]docker.ContainerSummary, len(s.containers))
	copy(out, s.containers)
	return out, nil
}

func (s *simulatedEngine) InspectContainer(_ context.Context, id string) (docker.ContainerInspect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	insp, ok := s.containerInspects[id]
	if !ok {
		return docker.ContainerInspect{}, &docker.APIError{StatusCode: 404, Method: "GET", Endpoint: "/containers/" + id}
	}
	return insp, nil
}

func (s *simulatedEngine) RemoveContainer(_ context.Context, id string, _ docker.RemoveContainerOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	for i, c := range s.containers {
		if c.ID == id {
			if c.SizeRw > 0 {
				s.freeSpaceLocked(uint64(c.SizeRw))
			}
			s.containers = append(s.containers[:i], s.containers[i+1:]...)
			s.removedContainers = append(s.removedContainers, id)
			return nil
		}
	}
	return errors.New("not found")
}

func (s *simulatedEngine) PruneNetworks(context.Context, docker.Filters) (docker.NetworksPruneReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	return docker.NetworksPruneReport{}, nil
}

func (s *simulatedEngine) ListImages(context.Context, docker.ListImagesOptions) ([]docker.ImageSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]docker.ImageSummary, len(s.imageSummaries))
	copy(out, s.imageSummaries)
	return out, nil
}

func (s *simulatedEngine) InspectImage(_ context.Context, id string) (docker.ImageInspect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	insp, ok := s.imageInspects[id]
	if !ok {
		return docker.ImageInspect{}, &docker.APIError{StatusCode: 404, Method: "GET", Endpoint: "/images/" + id}
	}
	return insp, nil
}

func (s *simulatedEngine) ImageHistory(_ context.Context, id string) ([]docker.ImageHistoryItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imageHistories[id], nil
}

func (s *simulatedEngine) PruneImages(context.Context, bool, docker.Filters) (docker.ImagesPruneReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	reclaimed := s.danglingReclaim
	s.danglingReclaim = 0
	s.freeSpaceLocked(reclaimed)
	return docker.ImagesPruneReport{SpaceReclaimed: reclaimed}, nil
}

func (s *simulatedEngine) PruneBuildCache(context.Context, docker.BuildCachePruneOptions) (docker.BuildCachePruneReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	s.buildPruneCalled = true
	reclaimed := s.buildCacheReclaim
	s.buildCacheReclaim = 0
	s.freeSpaceLocked(reclaimed)
	return docker.BuildCachePruneReport{SpaceReclaimed: reclaimed}, nil
}

func (s *simulatedEngine) RemoveImage(_ context.Context, id string, _ docker.RemoveImageOptions) ([]docker.ImageDeleteItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	insp, ok := s.imageInspects[id]
	if !ok {
		return nil, &docker.APIError{StatusCode: 404, Method: "DELETE", Endpoint: "/images/" + id}
	}
	delete(s.imageInspects, id)
	for i, sum := range s.imageSummaries {
		if sum.ID == id {
			s.imageSummaries = append(s.imageSummaries[:i], s.imageSummaries[i+1:]...)
			break
		}
	}
	for _, digest := range insp.RootFS.Layers {
		holders := s.layerHolders[digest]
		delete(holders, id)
		if len(holders) == 0 {
			s.freeSpaceLocked(uint64(s.layerSizes[digest]))
		}
	}
	s.removedImages = append(s.removedImages, id)
	return []docker.ImageDeleteItem{{Deleted: id}}, nil
}

func (s *simulatedEngine) ListVolumes(context.Context, docker.Filters) (docker.VolumeListResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return docker.VolumeListResponse{Volumes: append([]docker.Volume(nil), s.volumes...)}, nil
}

func (s *simulatedEngine) RemoveVolume(_ context.Context, name string, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	for i, v := range s.volumes {
		if v.Name == name {
			if v.UsageData != nil && v.UsageData.Size > 0 {
				s.freeSpaceLocked(uint64(v.UsageData.Size))
			}
			s.volumes = append(s.volumes[:i], s.volumes[i+1:]...)
			s.removedVolumes = append(s.removedVolumes, name)
			return nil
		}
	}
	return nil
}

type sliceHelper struct{}

var slices sliceHelper

func (sliceHelper) ContainsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
