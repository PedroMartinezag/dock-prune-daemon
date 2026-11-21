package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

func TestCLI_Help_Version_AndUnknownSubcommand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. Root invocation with zero args prints usage banner and exits 0.
	var out, errBuf bytes.Buffer
	if code := run(ctx, nil, &out, &errBuf); code != exitOK {
		t.Fatalf("run(nil) code = %d, want %d; stderr=%s", code, exitOK, errBuf.String())
	}
	if !strings.Contains(out.String(), "Subcommands:") {
		t.Fatalf("root usage missing Subcommands header:\n%s", out.String())
	}

	// 2. version --json emits valid build provenance with zero_external_deps=true.
	out.Reset()
	errBuf.Reset()
	if code := run(ctx, []string{"version", "--json"}, &out, &errBuf); code != exitOK {
		t.Fatalf("run(version --json) code = %d, want %d", code, exitOK)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if !info.ZeroExternalDeps {
		t.Fatal("expected ZeroExternalDeps=true in version JSON")
	}

	// 3. Unknown subcommand returns exitBadUsage (2).
	out.Reset()
	errBuf.Reset()
	if code := run(ctx, []string{"nonexistent-subcmd"}, &out, &errBuf); code != exitBadUsage {
		t.Fatalf("run(unknown) code = %d, want %d", code, exitBadUsage)
	}
}

func TestCLI_EndToEnd_Once_VerifyAudit_ROI_Explain_Top_Doctor_AndDaemon(t *testing.T) {
	t.Parallel()

	dockerSrv := newMockDockerHTTPServer(t)
	defer dockerSrv.Close()

	u, err := url.Parse(dockerSrv.URL)
	if err != nil {
		t.Fatalf("parse mock server URL: %v", err)
	}
	dockerHost := "tcp://" + u.Host
	stateDir := t.TempDir()
	dockerRoot := t.TempDir()

	commonFlags := []string{
		"--state-dir", stateDir,
		"--docker-host", dockerHost,
		"--docker-root", dockerRoot,
		// Set target-percent=1 and min-free=1TiB so --force triggers a full waterfall cycle on any host disk.
		"--target-percent", "1",
		"--high-percent", "80",
		"--critical-percent", "90",
		"--panic-percent", "96",
		"--min-free", "1TiB",
	}

	ctx := context.Background()

	// 1. 'once --force --json' executes the surgical waterfall and signs audit.jsonl!
	var out, errBuf bytes.Buffer
	onceArgs := append([]string{"once", "--force", "--json"}, commonFlags...)
	if code := run(ctx, onceArgs, &out, &errBuf); code != exitOK {
		t.Fatalf("once --force failed (code=%d): %s", code, errBuf.String())
	}
	var cycRep engine.CycleReport
	if err := json.Unmarshal(out.Bytes(), &cycRep); err != nil {
		t.Fatalf("decode once CycleReport JSON: %v\nraw=%s", err, out.String())
	}
	if cycRep.Trigger != "cli-once" || len(cycRep.Stages) == 0 {
		t.Fatalf("unexpected once CycleReport: %+v", cycRep)
	}

	// 2. 'verify-audit --json' cryptographically verifies the Ed25519 Merkle ledger written by 'once'!
	out.Reset()
	errBuf.Reset()
	if code := run(ctx, []string{"verify-audit", "--state-dir", stateDir, "--json"}, &out, &errBuf); code != exitOK {
		t.Fatalf("verify-audit failed (code=%d): %s", code, errBuf.String())
	}
	var vres audit.VerifyResult
	if err := json.Unmarshal(out.Bytes(), &vres); err != nil {
		t.Fatalf("decode verify-audit JSON: %v", err)
	}
	if vres.VerifiedCount != 1 || vres.LastSequence != 1 {
		t.Fatalf("expected 1 verified audit record, got %+v", vres)
	}

	// 3. 'roi --markdown' renders FinOps report from persisted finops_state.json
	out.Reset()
	errBuf.Reset()
	if code := run(ctx, []string{"roi", "--state-dir", stateDir, "--markdown"}, &out, &errBuf); code != exitOK {
		t.Fatalf("roi --markdown failed (code=%d): %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "FinOps ROI Report") {
		t.Fatalf("unexpected roi --markdown output:\n%s", out.String())
	}

	// 4. 'explain --json' builds the non-destructive OCI Layer Reference DAG
	out.Reset()
	errBuf.Reset()
	explainArgs := append([]string{"explain", "--json"}, commonFlags...)
	if code := run(ctx, explainArgs, &out, &errBuf); code != exitOK {
		t.Fatalf("explain --json failed (code=%d): %s", code, errBuf.String())
	}
	var expRep engine.ExplainReport
	if err := json.Unmarshal(out.Bytes(), &expRep); err != nil {
		t.Fatalf("decode explain JSON: %v", err)
	}
	if expRep.DAG == nil || len(expRep.DAG.ImageOrder) != 1 {
		t.Fatalf("expected 1 image in Explain DAG, got %+v", expRep.DAG)
	}

	// 5. 'top --iterations 1 --interval 250ms' renders single live telemetry frame and exits cleanly
	out.Reset()
	errBuf.Reset()
	topArgs := append([]string{"top", "--iterations", "1", "--interval", "250ms"}, commonFlags...)
	if code := run(ctx, topArgs, &out, &errBuf); code != exitOK {
		t.Fatalf("top --iterations 1 failed (code=%d): %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "dock-prune-daemon top") {
		t.Fatalf("unexpected top output:\n%s", out.String())
	}

	// 6. 'doctor' validates live socket, Statfs, PSI, Phantom FDs, and the Ed25519 audit ledger
	out.Reset()
	errBuf.Reset()
	docArgs := append([]string{"doctor"}, commonFlags...)
	if code := run(ctx, docArgs, &out, &errBuf); code != exitOK {
		t.Fatalf("doctor failed (code=%d): stderr=%s\nstdout=%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "HEALTHY") {
		t.Fatalf("expected HEALTHY verdict in doctor output:\n%s", out.String())
	}

	// 7. 'daemon' starts, acquires exclusive Flock PID lock, serves telemetry, and shuts down cleanly
	daemonCtx, cancelDaemon := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancelDaemon()
	out.Reset()
	errBuf.Reset()
	daemonArgs := []string{
		"daemon",
		"--state-dir", stateDir,
		"--docker-host", dockerHost,
		"--docker-root", dockerRoot,
		"--listen-addr", "127.0.0.1:0",
		"--poll-interval", "5s",
	}
	if code := run(daemonCtx, daemonArgs, &out, &errBuf); code != exitOK {
		t.Fatalf("daemon run failed (code=%d): %s", code, errBuf.String())
	}
}

func TestProductionConfigProfile_ValidatesCleanlyIfPresent(t *testing.T) {
	t.Parallel()

	prodCfgPath := filepath.Join("..", "..", "deploy", "config.production.json")
	if _, err := os.Stat(prodCfgPath); err != nil {
		t.Skip("deploy/config.production.json not present yet; skipping")
	}

	cfg := config.Default()
	if err := config.MergeJSONFile(&cfg, prodCfgPath); err != nil {
		t.Fatalf("deploy/config.production.json failed strict JSON decode: %v", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("deploy/config.production.json failed validation: %v", err)
	}
}

func newMockDockerHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", "1.46")
		w.Header().Set("OSType", "linux")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/v1.46/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.VersionInfo{
			Version:    "27.3.1",
			APIVersion: "1.46",
			Os:         "linux",
			Arch:       "amd64",
		})
	})
	mux.HandleFunc("/v1.46/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]docker.ContainerSummary{})
	})
	mux.HandleFunc("/v1.46/networks/prune", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.NetworksPruneReport{})
	})
	mux.HandleFunc("/v1.46/images/prune", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.ImagesPruneReport{SpaceReclaimed: 64 * 1024 * 1024})
	})
	mux.HandleFunc("/v1.46/build/prune", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.BuildCachePruneReport{SpaceReclaimed: 128 * 1024 * 1024})
	})
	mux.HandleFunc("/v1.46/images/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]docker.ImageSummary{
			{
				ID:       "sha256:orphan01",
				RepoTags: []string{"ci-artifact:old"},
				Created:  1700000000,
				Size:     50 * 1024 * 1024,
			},
		})
	})
	mux.HandleFunc("/v1.46/images/sha256:orphan01/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.ImageInspect{
			ID:       "sha256:orphan01",
			RepoTags: []string{"ci-artifact:old"},
			Created:  "2026-01-01T00:00:00Z",
			Size:     50 * 1024 * 1024,
			RootFS: docker.RootFS{
				Type:   "layers",
				Layers: []string{"sha256:layer_orphan_01"},
			},
		})
	})
	mux.HandleFunc("/v1.46/images/sha256:orphan01/history", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]docker.ImageHistoryItem{
			{ID: "layer_orphan_01", Created: 1700000000, Size: 50 * 1024 * 1024},
		})
	})
	mux.HandleFunc("/v1.46/images/sha256:orphan01", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			_ = json.NewEncoder(w).Encode([]docker.ImageDeleteItem{{Deleted: "sha256:orphan01"}})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/v1.46/volumes", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(docker.VolumeListResponse{})
	})
	mux.HandleFunc("/v1.46/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if ok {
			_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"die","Actor":{"ID":"c1"},"time":1700000100}`)
			flusher.Flush()
		}
		<-r.Context().Done()
	})

	return httptest.NewServer(mux)
}
