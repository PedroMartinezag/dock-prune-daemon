package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

func TestFilters_DeterministicJSONAndQueryEncoding(t *testing.T) {
	t.Parallel()

	f := NewFilters()
	f.AddUntil(90 * time.Minute).
		AddDangling(true).
		ExcludeLabels([]string{"io.dockprune.keep=true", "env=prod"}).
		IncludeLabels([]string{"managed-by=ci"})

	first, err := f.EncodeJSON()
	if err != nil {
		t.Fatalf("EncodeJSON() error: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := f.EncodeJSON()
		if err != nil || again != first {
			t.Fatalf("non-deterministic filter serialization: got %q, want %q", again, first)
		}
	}

	want := `{"dangling":{"true":true},"label":{"managed-by=ci":true},"label!":{"env=prod":true,"io.dockprune.keep=true":true},"until":{"5400s":true}}`
	if first != want {
		t.Fatalf("EncodeJSON() = %s, want %s", first, want)
	}

	q := make(url.Values)
	if err := f.ApplyQuery(q); err != nil {
		t.Fatalf("ApplyQuery error: %v", err)
	}
	if q.Get("filters") != want {
		t.Fatalf("query filters = %s, want %s", q.Get("filters"), want)
	}

	// Clone isolation
	cloned := f.Clone()
	cloned.Add("dangling", "false")
	afterOrig, _ := f.EncodeJSON()
	if afterOrig != want {
		t.Fatal("mutating cloned Filters modified original Filters")
	}
}

func TestCircuitBreaker_StateTransitions_SingleProbe_And4xxExemption(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	cb := NewCircuitBreaker(3, 30*time.Second)
	cb.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	ctx := context.Background()

	// 1. Benign 404 APIError and context.Canceled must NEVER increment consecutiveFailures
	for i := 0; i < 5; i++ {
		_ = cb.Execute(ctx, func(context.Context) error {
			return &APIError{StatusCode: 404, Method: "DELETE", Endpoint: "/containers/x", Message: "not found"}
		})
		_ = cb.Execute(ctx, func(context.Context) error {
			return context.Canceled
		})
	}
	if st := cb.Stats(); st.State != BreakerClosed || st.ConsecutiveFailures != 0 {
		t.Fatalf("expected CLOSED with 0 failures after 404/Canceled, got %+v", st)
	}

	// 2. Three consecutive 500/socket failures trip breaker to OPEN
	sockErr := errors.New("dial unix /var/run/docker.sock: i/o timeout")
	for i := 0; i < 3; i++ {
		_ = cb.Execute(ctx, func(context.Context) error { return sockErr })
	}
	if st := cb.Stats(); st.State != BreakerOpen || st.TotalTrips != 1 {
		t.Fatalf("expected OPEN with 1 trip, got %+v", st)
	}

	// 3. Immediate rejection while OPEN
	if err := cb.Execute(ctx, func(context.Context) error { return nil }); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen while OPEN, got %v", err)
	}

	// 4. Advance past openTimeout -> Half-Open allows ONLY ONE single-flight probe
	advanceClock(31 * time.Second)
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})

	var probeWG sync.WaitGroup
	probeWG.Add(1)
	go func() {
		defer probeWG.Done()
		err := cb.Execute(ctx, func(context.Context) error {
			close(probeEntered)
			<-releaseProbe
			return nil
		})
		if err != nil {
			t.Errorf("half-open winning probe failed: %v", err)
		}
	}()

	<-probeEntered
	// Concurrent second caller during active Half-Open probe must be rejected immediately!
	if err := cb.Execute(ctx, func(context.Context) error { return nil }); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected concurrent caller during Half-Open probe to get ErrCircuitOpen, got %v", err)
	}

	close(releaseProbe)
	probeWG.Wait()

	// 5. Successful probe closes the circuit breaker cleanly
	finalStats := cb.Stats()
	if finalStats.State != BreakerClosed || finalStats.ConsecutiveFailures != 0 || finalStats.TotalRejected != 2 {
		t.Fatalf("unexpected final breaker stats: %+v", finalStats)
	}
}

func TestClient_UnixDomainSocket_APINegotiation_AndFullLifecycle(t *testing.T) {
	t.Parallel()

	// Short temp directory ensures socket path stays well below macOS 104-byte sun_path limit.
	shortDir, err := os.MkdirTemp("", "dpd-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })

	sockPath := filepath.Join(shortDir, "d.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable in current test sandbox: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", "1.46")
		w.Header().Set("OSType", "linux")
		w.Header().Set("Builder-Version", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/v1.46/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "true" {
			http.Error(w, `{"message":"expected all=true"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode([]ContainerSummary{
			{
				ID:      "c11111111111222222222222",
				Names:   []string{"/api-gateway"},
				Image:   "ghcr.io/org/api:v1",
				ImageID: "sha256:img1",
				State:   "running",
				Created: 1700000000,
			},
		})
	})
	mux.HandleFunc("/v1.46/images/sha256:img1/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ImageInspect{
			ID:       "sha256:img1",
			RepoTags: []string{"ghcr.io/org/api:v1"},
			Size:     120 * 1024 * 1024,
			RootFS: RootFS{
				Type:   "layers",
				Layers: []string{"sha256:layerA", "sha256:layerB"},
			},
		})
	})
	mux.HandleFunc("/v1.46/build/prune", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"message":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("keep-storage") != "5368709120" {
			http.Error(w, `{"message":"missing keep-storage"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(BuildCachePruneReport{
			CachesDeleted:  []string{"bc1", "bc2"},
			SpaceReclaimed: 2 * 1024 * 1024 * 1024,
		})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	cfg := config.Default().Docker
	cfg.Host = "unix://" + sockPath
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(unix): %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Lazy API version negotiation triggers transparently on first ListContainers call!
	containers, err := client.ListContainers(ctx, ListContainersOptions{All: true})
	if err != nil {
		t.Fatalf("ListContainers error: %v", err)
	}
	if len(containers) != 1 || containers[0].PrimaryName() != "api-gateway" || !containers[0].IsRunning() {
		t.Fatalf("unexpected container summary: %+v", containers)
	}

	inspect, err := client.InspectImage(ctx, "sha256:img1")
	if err != nil {
		t.Fatalf("InspectImage error: %v", err)
	}
	if len(inspect.RootFS.Layers) != 2 {
		t.Fatalf("expected 2 OCI layers, got %+v", inspect.RootFS.Layers)
	}

	bcReport, err := client.PruneBuildCache(ctx, BuildCachePruneOptions{
		KeepStorage: 5 * 1024 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("PruneBuildCache error: %v", err)
	}
	if bcReport.SpaceReclaimed != 2*1024*1024*1024 {
		t.Fatalf("unexpected SpaceReclaimed: %d", bcReport.SpaceReclaimed)
	}

	// Path traversal injection must be rejected locally before touching the socket.
	if _, err := client.InspectContainer(ctx, "../../_ping"); err == nil {
		t.Fatal("expected error on path-traversal container ID")
	}
}

func TestClient_TCPEndpoint_ErrorClassification_AndStreamEventsReconnect(t *testing.T) {
	t.Parallel()

	var streamConnections atomic.Int32
	var failMode atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		// Version 1.99 should be safely clamped down to maxSupportedAPIVersion (1.47)
		w.Header().Set("Api-Version", "1.99")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1.47/volumes/missing-vol", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no such volume: missing-vol"}`))
	})
	mux.HandleFunc("/v1.47/images/prune", func(w http.ResponseWriter, _ *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"overlay2 metadata lock timeout"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(ImagesPruneReport{SpaceReclaimed: 1024})
	})
	mux.HandleFunc("/v1.47/events", func(w http.ResponseWriter, r *http.Request) {
		connNum := streamConnections.Add(1)
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if connNum == 1 {
			// Emit 2 events and drop connection abruptly to test auto-reconnect + since cursor!
			_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"die","Actor":{"ID":"c1"},"time":1700000100}`)
			_, _ = fmt.Fprintln(w, `{"Type":"image","Action":"pull","Actor":{"ID":"img2"},"time":1700000200}`)
			flusher.Flush()
			return
		}

		// Second connection must carry since=1700000200 from last seen event!
		if gotSince := r.URL.Query().Get("since"); gotSince != "1700000200" {
			_, _ = fmt.Fprintf(w, `{"Type":"error","Action":"bad_since_%s","time":1700000201}`+"\n", gotSince)
			flusher.Flush()
			return
		}
		_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"oom","Actor":{"ID":"c3"},"time":1700000300}`)
		flusher.Flush()
		<-r.Context().Done()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	cfg := config.Default().Docker
	cfg.Host = "tcp://" + u.Host
	cfg.BreakerFailureThreshold = 2
	cfg.BreakerOpenTimeout = config.Duration(10 * time.Second)

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(tcp): %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// 1. Verify 404 NotFound classification without tripping breaker
	err = client.RemoveVolume(ctx, "missing-vol", false)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.IsNotFound() {
		t.Fatalf("expected 404 APIError, got %v", err)
	}

	// 2. Verify live NDJSON /events streaming + automatic reconnect with 'since' cursor
	streamCtx, cancelStream := context.WithTimeout(ctx, 5*time.Second)
	defer cancelStream()

	var received []EventMessage
	var mu sync.Mutex
	err = client.StreamEvents(streamCtx, EventsOptions{}, func(ev EventMessage) {
		mu.Lock()
		received = append(received, ev)
		count := len(received)
		mu.Unlock()
		if count >= 3 {
			cancelStream()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled after 3 events, got %v", err)
	}
	if len(received) != 3 || received[2].Action != "oom" || received[2].Actor.ID != "c3" {
		t.Fatalf("unexpected streamed events across reconnect: %+v", received)
	}

	// 3. Two 500 server errors trip the circuit breaker into OPEN
	failMode.Store(true)
	_, _ = client.PruneImages(ctx, true, NewFilters())
	_, _ = client.PruneImages(ctx, true, NewFilters())

	if _, err := client.PruneImages(ctx, true, NewFilters()); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after 2 server faults, got %v", err)
	}
}
