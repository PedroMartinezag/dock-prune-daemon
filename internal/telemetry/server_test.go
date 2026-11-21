package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/graph"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

func TestControlPlane_Auth_Readyz_Metrics_Trigger_DAG_ROI_AndSSE(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	cfg.Telemetry.BearerToken = "sre-production-token-99"
	cfg.Normalize()

	store, err := config.NewStore(cfg, "", nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	reg := NewRegistry()
	tracker, err := finops.LoadOrNew(cfg.StateDir)
	if err != nil {
		t.Fatalf("finops.LoadOrNew: %v", err)
	}

	const gib = uint64(1024 * 1024 * 1024)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	sampleCycle := engine.CycleReport{
		CycleID:                  "cyc-http-01",
		Trigger:                  "api-manual",
		StartedAt:                now,
		CompletedAt:              now.Add(350 * time.Millisecond),
		Duration:                 350 * time.Millisecond,
		InitialRegime:            disk.RegimeCritical,
		FinalRegime:              disk.RegimeNominal,
		BeforeDisk:               disk.Snapshot{TotalBytes: 100 * gib, UsedBytes: 91 * gib, FreeBytes: 9 * gib, UsedPercent: 91.0},
		AfterDisk:                disk.Snapshot{TotalBytes: 100 * gib, UsedBytes: 68 * gib, FreeBytes: 32 * gib, UsedPercent: 68.0},
		ActualDiskReclaimedBytes: 23 * gib,
		ReportedReclaimedBytes:   23 * gib,
		TargetSatisfied:          true,
		BuildCachePreserved:      true,
		ENOSPCAverted:            true,
		Stages: []engine.StageResult{
			{Stage: engine.Stage4DAGAndVolumes, Executed: true, ItemsDeleted: 2, ReportedReclaimedBytes: 23 * gib},
		},
	}
	_ = tracker.RecordCycle(sampleCycle)
	reg.ObserveCycle(sampleCycle, tracker.Snapshot(cfg.Telemetry))

	srv, err := NewServer(ServerOptions{
		ConfigStore: store,
		Registry:    reg,
		FinOps:      tracker,
		TriggerFn: func(_ context.Context, dryRun bool, _ bool) (engine.CycleReport, error) {
			rep := sampleCycle
			rep.DryRun = dryRun
			return rep, nil
		},
		ExplainFn: func(context.Context) (engine.ExplainReport, error) {
			return engine.ExplainReport{
				CapturedAt: now,
				DAG:        &graph.DAG{TotalUniqueLayerBytes: int64(20 * gib)},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. /healthz and /readyz work unauthenticated for Kubernetes/systemd probes
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz unexpected status: %v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz expected 200 when CLOSED, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Simulate circuit breaker tripping OPEN -> /readyz must return 503 Service Unavailable!
	reg.UpdateSensors(disk.RegimeDegraded, sampleCycle.AfterDisk, disk.ForecastResult{}, kernel.PSISnapshot{},
		docker.BreakerStats{State: docker.BreakerOpen, TotalTrips: 1}, 0, 0)
	resp, _ = http.Get(ts.URL + "/readyz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on /readyz when breaker OPEN, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Restore healthy CLOSED state
	reg.UpdateSensors(disk.RegimeNominal, sampleCycle.AfterDisk, disk.ForecastResult{}, kernel.PSISnapshot{},
		docker.BreakerStats{State: docker.BreakerClosed}, 0, 0)

	// 2. Protected endpoints reject missing or wrong Bearer token with 401
	unauthResp, _ := http.Get(ts.URL + "/v1/status")
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", unauthResp.StatusCode)
	}
	_ = unauthResp.Body.Close()

	wrongReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	wrongReq.Header.Set("Authorization", "Bearer short")
	wrongResp, _ := http.DefaultClient.Do(wrongReq)
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", wrongResp.StatusCode)
	}
	_ = wrongResp.Body.Close()

	authGet := func(path string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer sre-production-token-99")
		r, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			t.Fatalf("GET %s failed: %v", path, doErr)
		}
		defer r.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		return r, buf.String()
	}

	// 3. /metrics exposes Prometheus counters, histogram, and FinOps savings
	mResp, mBody := authGet("/metrics")
	if mResp.StatusCode != http.StatusOK ||
		!strings.Contains(mBody, `dockprune_enospc_averted_total 1`) ||
		!strings.Contains(mBody, `dockprune_cycle_duration_seconds_count 1`) ||
		!strings.Contains(mBody, `dockprune_finops_estimated_savings_usd`) {
		t.Fatalf("unexpected /metrics output:\n%s", mBody)
	}

	// 4. /v1/status redacts BearerToken so secrets never leak in status dumps
	stResp, stBody := authGet("/v1/status")
	if stResp.StatusCode != http.StatusOK || strings.Contains(stBody, "sre-production-token-99") {
		t.Fatalf("/v1/status leaked raw BearerToken:\n%s", stBody)
	}

	// 5. /v1/roi?format=markdown & /v1/dag & /ui
	roiResp, roiMD := authGet("/v1/roi?format=markdown")
	if roiResp.StatusCode != http.StatusOK || !strings.Contains(roiMD, "FinOps ROI Report") {
		t.Fatalf("unexpected /v1/roi markdown: %s", roiMD)
	}

	dagResp, dagBody := authGet("/v1/dag")
	if dagResp.StatusCode != http.StatusOK || !strings.Contains(dagBody, "total_unique_layer_bytes") {
		t.Fatalf("unexpected /v1/dag response: %s", dagBody)
	}

	uiResp, _ := http.Get(ts.URL + "/ui")
	if uiResp.StatusCode != http.StatusOK || uiResp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("unexpected /ui response headers: %+v", uiResp.Header)
	}
	_ = uiResp.Body.Close()

	// 6. POST /v1/trigger executes immediate dry-run cycle
	trigReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/trigger", bytes.NewReader([]byte(`{"dry_run":true,"force":true}`)))
	trigReq.Header.Set("Authorization", "Bearer sre-production-token-99")
	trigResp, err := http.DefaultClient.Do(trigReq)
	if err != nil || trigResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/trigger failed: %v", err)
	}
	var triggered engine.CycleReport
	_ = json.NewDecoder(trigResp.Body).Decode(&triggered)
	_ = trigResp.Body.Close()
	if !triggered.DryRun || triggered.CycleID != "cyc-http-01" {
		t.Fatalf("unexpected triggered cycle report: %+v", triggered)
	}

	// 7. Live Server-Sent Events (/v1/events) pushes initial snapshot immediately
	sseCtx, cancelSSE := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelSSE()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL+"/v1/events", nil)
	sseReq.Header.Set("Authorization", "Bearer sre-production-token-99")
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil || sseResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/events failed: %v", err)
	}
	defer sseResp.Body.Close()

	sc := bufio.NewScanner(sseResp.Body)
	if !sc.Scan() || !strings.HasPrefix(sc.Text(), "data: ") {
		t.Fatalf("expected immediate SSE data frame, got %q (err=%v)", sc.Text(), sc.Err())
	}
}
