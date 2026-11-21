package telemetry

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

//go:embed assets/index.html
var embeddedDashboardHTML []byte

// TriggerFunc executes an immediate reclamation cycle on demand via POST /v1/trigger.
type TriggerFunc func(ctx context.Context, dryRun bool, force bool) (engine.CycleReport, error)

// ExplainFunc computes a live non-destructive OCI Layer DAG diagnostic via GET /v1/dag.
type ExplainFunc func(ctx context.Context) (engine.ExplainReport, error)

// StatusSnapshot is serialized by GET /v1/status and broadcast over GET /v1/events SSE.
type StatusSnapshot struct {
	Timestamp  time.Time           `json:"timestamp"`
	Build      buildinfo.Info      `json:"build"`
	Regime     disk.Regime         `json:"regime"`
	Disk       disk.Snapshot       `json:"disk"`
	Forecast   disk.ForecastResult `json:"forecast"`
	PSI        kernel.PSISnapshot  `json:"psi"`
	Breaker    docker.BreakerStats `json:"breaker"`
	FinOps     finops.Report       `json:"finops"`
	LastCycle  *engine.CycleReport `json:"last_cycle,omitempty"`
	Config     config.Config       `json:"config"`
}

// ServerOptions bundles dependencies for the HTTP observability and control plane.
type ServerOptions struct {
	ConfigStore *config.Store
	Registry    *Registry
	FinOps      *finops.Tracker
	TriggerFn   TriggerFunc
	ExplainFn   ExplainFunc
}

// Server serves /healthz, /readyz, /metrics, /v1/status, /v1/roi, /v1/dag, /v1/trigger,
// /v1/events (SSE), and /ui over a hardened stdlib net/http server.
type Server struct {
	cfgStore  *config.Store
	registry  *Registry
	finops    *finops.Tracker
	triggerFn TriggerFunc
	explainFn ExplainFunc
	httpSrv   *http.Server

	sseMu   sync.Mutex
	sseSubs map[chan []byte]struct{}
}

// NewServer constructs the telemetry & control plane HTTP server.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.ConfigStore == nil {
		return nil, errors.New("telemetry server requires a non-nil config.Store")
	}
	reg := opts.Registry
	if reg == nil {
		reg = NewRegistry()
	}

	s := &Server{
		cfgStore:  opts.ConfigStore,
		registry:  reg,
		finops:    opts.FinOps,
		triggerFn: opts.TriggerFn,
		explainFn: opts.ExplainFn,
		sseSubs:   make(map[chan []byte]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/metrics", s.withBearerAuth(s.handleMetrics))
	mux.HandleFunc("/v1/status", s.withBearerAuth(s.handleStatus))
	mux.HandleFunc("/v1/roi", s.withBearerAuth(s.handleROI))
	mux.HandleFunc("/v1/dag", s.withBearerAuth(s.handleDAG))
	mux.HandleFunc("/v1/trigger", s.withBearerAuth(s.handleTrigger))
	mux.HandleFunc("/v1/events", s.withBearerAuth(s.handleSSE))
	mux.HandleFunc("/ui", s.handleUI)
	mux.HandleFunc("/", s.handleRoot)

	cfg := s.cfgStore.Current()
	s.httpSrv = &http.Server{
		Addr:              cfg.Telemetry.ListenAddr,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// WriteTimeout is intentionally 0 so long-lived /v1/events SSE streams stay open;
		// per-request deadlines are enforced inside synchronous handlers.
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Handler exposes the root http.Handler for in-memory httptest verification.
func (s *Server) Handler() http.Handler {
	return s.httpSrv.Handler
}

// Serve binds the listener and serves HTTP until Shutdown is called.
func (s *Server) Serve(ln net.Listener) error {
	err := s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ListenAndServe opens a TCP socket on Telemetry.ListenAddr and starts serving.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("listen telemetry %s: %w", s.httpSrv.Addr, err)
	}
	return s.Serve(ln)
}

// Shutdown closes active SSE streams and gracefully drains in-flight HTTP requests.
func (s *Server) Shutdown(ctx context.Context) error {
	s.sseMu.Lock()
	for ch := range s.sseSubs {
		delete(s.sseSubs, ch)
		close(ch)
	}
	s.sseMu.Unlock()
	return s.httpSrv.Shutdown(ctx)
}

// BroadcastSnapshot pushes a live JSON StatusSnapshot to all connected SSE subscribers.
func (s *Server) BroadcastSnapshot() {
	snap := s.currentStatusSnapshot()
	raw, err := json.Marshal(snap)
	if err != nil {
		return
	}

	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for ch := range s.sseSubs {
		select {
		case ch <- raw:
		default:
			// Drop slow client frame rather than blocking the daemon control loop.
		}
	}
}

func (s *Server) currentStatusSnapshot() StatusSnapshot {
	cfg := s.cfgStore.Current()

	s.registry.mu.RLock()
	reg := s.registry.currentRegime
	dSnap := s.registry.diskSnap
	fc := s.registry.forecast
	psi := s.registry.psi
	brk := s.registry.breaker
	roi := s.registry.finopsRep
	var lastCyc *engine.CycleReport
	if s.registry.lastCycle != nil {
		cp := *s.registry.lastCycle
		lastCyc = &cp
	}
	s.registry.mu.RUnlock()

	if s.finops != nil {
		roi = s.finops.Snapshot(cfg.Telemetry)
	}

	return StatusSnapshot{
		Timestamp: time.Now().UTC(),
		Build:     buildinfo.Get(),
		Regime:    reg,
		Disk:      dSnap,
		Forecast:  fc,
		PSI:       psi,
		Breaker:   brk,
		FinOps:    roi,
		LastCycle: lastCyc,
		Config:    cfg.Redacted(),
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": buildinfo.Get().Version,
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.registry.mu.RLock()
	brkState := s.registry.breaker.State
	reg := s.registry.currentRegime
	s.registry.mu.RUnlock()

	if brkState == docker.BreakerOpen || reg == disk.RegimeDegraded {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":        "degraded",
			"breaker_state": brkState,
			"regime":        reg,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ready",
		"breaker_state": brkState,
		"regime":        reg,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.finops != nil {
		cfg := s.cfgStore.Current()
		s.registry.UpdateFinOps(s.finops.Snapshot(cfg.Telemetry))
	}
	payload := s.registry.RenderPrometheus()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(payload))
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.currentStatusSnapshot())
}

func (s *Server) handleROI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg := s.cfgStore.Current()
	var rep finops.Report
	if s.finops != nil {
		rep = s.finops.Snapshot(cfg.Telemetry)
	} else {
		s.registry.mu.RLock()
		rep = s.registry.finopsRep
		s.registry.mu.RUnlock()
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "markdown") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(finops.FormatMarkdown(rep)))
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleDAG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.explainFn == nil {
		writeJSONError(w, http.StatusNotImplemented, "OCI DAG explain provider is not wired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	exp, err := s.explainFn(ctx)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, exp)
}

func (s *Server) handleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "expected POST")
		return
	}
	if s.triggerFn == nil {
		writeJSONError(w, http.StatusNotImplemented, "reclamation trigger is not wired")
		return
	}

	var reqBody struct {
		DryRun bool `json:"dry_run"`
		Force  bool `json:"force"`
	}
	reqBody.Force = true

	raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &reqBody); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON trigger payload")
			return
		}
	}

	cfg := s.cfgStore.Current()
	ctx, cancel := context.WithTimeout(r.Context(), cfg.Docker.PruneTimeout.Std())
	defer cancel()

	rep, err := s.triggerFn(ctx, reqBody.DryRun, reqBody.Force)
	if err != nil {
		if errors.Is(err, engine.ErrCycleAlreadyRunning) {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := make(chan []byte, 8)
	s.sseMu.Lock()
	s.sseSubs[ch] = struct{}{}
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		if _, exists := s.sseSubs[ch]; exists {
			delete(s.sseSubs, ch)
			close(ch)
		}
		s.sseMu.Unlock()
	}()

	if initial, err := json.Marshal(s.currentStatusSnapshot()); err == nil {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", initial)
		flusher.Flush()
	}

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.cfgStore.Current().Telemetry.EnableWebUI {
		writeJSONError(w, http.StatusNotFound, "embedded web UI is disabled")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(embeddedDashboardHTML)
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if s.cfgStore.Current().Telemetry.EnableWebUI {
		http.Redirect(w, r, "/ui", http.StatusTemporaryRedirect)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "dock-prune-daemon",
		"metrics": "/metrics",
		"status":  "/v1/status",
	})
}

// withBearerAuth enforces constant-time Bearer token validation over fixed-size SHA-256
// digests so neither token contents nor secret token length leak via timing side channels.
func (s *Server) withBearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedToken := s.cfgStore.Current().Telemetry.BearerToken
		if expectedToken == "" {
			next(w, r)
			return
		}

		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if len(authHeader) <= len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="dock-prune-daemon"`)
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid Authorization Bearer header")
			return
		}

		providedToken := strings.TrimSpace(authHeader[len(prefix):])
		expectedDigest := sha256.Sum256([]byte(expectedToken))
		providedDigest := sha256.Sum256([]byte(providedToken))

		if subtle.ConstantTimeCompare(expectedDigest[:], providedDigest[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="dock-prune-daemon"`)
			writeJSONError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}

		next(w, r)
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeJSONError(w http.ResponseWriter, statusCode int, msg string) {
	writeJSON(w, statusCode, map[string]any{
		"error":       msg,
		"status_code": statusCode,
	})
}
