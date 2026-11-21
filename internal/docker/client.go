package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

const (
	minSupportedAPIVersion  = "1.41"
	fallbackAPIVersion      = "1.43"
	maxSupportedAPIVersion  = "1.47"
	maxControlResponseBytes = 32 << 20 // 32 MiB hard ceiling on JSON control responses
	maxEventLineBytes       = 1 << 20  // 1 MiB max single NDJSON event frame
)

// Client is a concurrency-safe, zero-dependency Docker/Moby Engine API client.
type Client struct {
	baseURL        string
	pinnedVersion  string
	requestTimeout time.Duration
	pruneTimeout   time.Duration
	userAgent      string

	transport  *http.Transport
	httpClient *http.Client
	breaker    *CircuitBreaker

	verMu             sync.RWMutex
	negotiatedVersion string
}

// NewClient constructs a pure-stdlib Docker Engine client supporting unix://, tcp://,
// http://, and https:// daemon endpoints.
func NewClient(cfg config.DockerConfig) (*Client, error) {
	dialTarget, baseURL, err := parseEndpoint(cfg.Host)
	if err != nil {
		return nil, err
	}

	reqTimeout := cfg.RequestTimeout.Std()
	if reqTimeout <= 0 {
		reqTimeout = 15 * time.Second
	}
	pruneTimeout := cfg.PruneTimeout.Std()
	if pruneTimeout < reqTimeout {
		pruneTimeout = 5 * time.Minute
	}

	dialer := &net.Dialer{
		Timeout:   reqTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: pruneTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if dialTarget.isUnix {
		sockPath := dialTarget.address
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", sockPath)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}

	pinnedVer := normalizeAPIVersion(cfg.APIVersion)
	breaker := NewCircuitBreaker(cfg.BreakerFailureThreshold, cfg.BreakerOpenTimeout.Std())

	return &Client{
		baseURL:        baseURL,
		pinnedVersion:  pinnedVer,
		requestTimeout: reqTimeout,
		pruneTimeout:   pruneTimeout,
		userAgent:      buildinfo.UserAgent(),
		transport:      transport,
		// Per-call deadlines are enforced via context.WithTimeout so long-lived
		// /events streams and prolonged /prune calls share the same transport safely.
		httpClient:        &http.Client{Transport: transport},
		breaker:           breaker,
		negotiatedVersion: pinnedVer,
	}, nil
}

type endpointSpec struct {
	isUnix  bool
	address string
}

func parseEndpoint(rawHost string) (endpointSpec, string, error) {
	trimmed := strings.TrimSpace(rawHost)
	if trimmed == "" {
		return endpointSpec{}, "", errors.New("docker host endpoint cannot be empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return endpointSpec{}, "", fmt.Errorf("parse docker host %q: %w", trimmed, err)
	}

	switch u.Scheme {
	case "unix":
		sockPath := u.Path
		if sockPath == "" && u.Host != "" {
			sockPath = "/" + u.Host
		}
		if strings.TrimSpace(sockPath) == "" {
			return endpointSpec{}, "", fmt.Errorf("unix endpoint %q missing socket path", trimmed)
		}
		return endpointSpec{isUnix: true, address: sockPath}, "http://docker", nil

	case "tcp", "http":
		if u.Host == "" {
			return endpointSpec{}, "", fmt.Errorf("%s endpoint %q missing host:port", u.Scheme, trimmed)
		}
		base := "http://" + u.Host + strings.TrimRight(u.Path, "/")
		return endpointSpec{isUnix: false, address: u.Host}, base, nil

	case "https":
		if u.Host == "" {
			return endpointSpec{}, "", fmt.Errorf("https endpoint %q missing host:port", trimmed)
		}
		base := "https://" + u.Host + strings.TrimRight(u.Path, "/")
		return endpointSpec{isUnix: false, address: u.Host}, base, nil

	default:
		return endpointSpec{}, "", fmt.Errorf("unsupported docker host scheme %q", u.Scheme)
	}
}

// Close releases idle keep-alive socket connections held by the underlying HTTP transport.
func (c *Client) Close() error {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

// BreakerStats returns a point-in-time snapshot of the client's 3-state circuit breaker.
func (c *Client) BreakerStats() BreakerStats {
	return c.breaker.Stats()
}

// Ping verifies daemon connectivity via GET /_ping and caches the negotiated API version.
func (c *Client) Ping(ctx context.Context) (PingInfo, error) {
	var info PingInfo
	err := c.breaker.Execute(ctx, func(callCtx context.Context) error {
		tCtx, cancel := context.WithTimeout(callCtx, c.requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(tCtx, http.MethodGet, c.baseURL+"/_ping", nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("ping docker daemon: %w", err)
		}
		defer drainAndClose(resp.Body)

		if resp.StatusCode >= 400 {
			return decodeAPIError(http.MethodGet, "/_ping", resp)
		}

		apiVer := clampAPIVersion(resp.Header.Get("Api-Version"))
		info = PingInfo{
			APIVersion:     apiVer,
			OSType:         resp.Header.Get("OSType"),
			BuilderVersion: resp.Header.Get("Builder-Version"),
			Experimental:   strings.EqualFold(resp.Header.Get("Docker-Experimental"), "true"),
		}
		c.cacheNegotiatedVersion(apiVer)
		return nil
	})
	return info, err
}

// Version queries GET /v{api}/version for engine metadata.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var out VersionInfo
	err := c.doJSON(ctx, http.MethodGet, "/version", nil, c.requestTimeout, &out)
	return out, err
}

// ListContainers queries GET /v{api}/containers/json.
func (c *Client) ListContainers(ctx context.Context, opts ListContainersOptions) ([]ContainerSummary, error) {
	q := make(url.Values)
	if opts.All {
		q.Set("all", "true")
	}
	if opts.Size {
		q.Set("size", "true")
	}
	if err := opts.Filters.ApplyQuery(q); err != nil {
		return nil, err
	}

	var out []ContainerSummary
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", q, c.requestTimeout, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InspectContainer queries GET /v{api}/containers/{id}/json, returning LogPath and state.
func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInspect, error) {
	cleanID, err := sanitizeResourceID(id)
	if err != nil {
		return ContainerInspect{}, err
	}
	var out ContainerInspect
	err = c.doJSON(ctx, http.MethodGet, "/containers/"+cleanID+"/json", nil, c.requestTimeout, &out)
	return out, err
}

// RemoveContainer deletes a stopped (or forced) container via DELETE /v{api}/containers/{id}.
func (c *Client) RemoveContainer(ctx context.Context, id string, opts RemoveContainerOptions) error {
	cleanID, err := sanitizeResourceID(id)
	if err != nil {
		return err
	}
	q := make(url.Values)
	if opts.Force {
		q.Set("force", "true")
	}
	if opts.RemoveVolumes {
		q.Set("v", "true")
	}
	return c.doJSON(ctx, http.MethodDelete, "/containers/"+cleanID, q, c.pruneTimeout, nil)
}

// PruneContainers invokes POST /v{api}/containers/prune.
func (c *Client) PruneContainers(ctx context.Context, filters Filters) (ContainersPruneReport, error) {
	q := make(url.Values)
	if err := filters.ApplyQuery(q); err != nil {
		return ContainersPruneReport{}, err
	}
	var out ContainersPruneReport
	err := c.doJSON(ctx, http.MethodPost, "/containers/prune", q, c.pruneTimeout, &out)
	return out, err
}

// ListImages queries GET /v{api}/images/json.
func (c *Client) ListImages(ctx context.Context, opts ListImagesOptions) ([]ImageSummary, error) {
	q := make(url.Values)
	if opts.All {
		q.Set("all", "true")
	}
	if opts.SharedSize {
		q.Set("shared-size", "true")
	}
	if err := opts.Filters.ApplyQuery(q); err != nil {
		return nil, err
	}
	var out []ImageSummary
	if err := c.doJSON(ctx, http.MethodGet, "/images/json", q, c.requestTimeout, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InspectImage queries GET /v{api}/images/{id}/json including RootFS.Layers diff_ids.
func (c *Client) InspectImage(ctx context.Context, id string) (ImageInspect, error) {
	cleanID, err := sanitizeResourceID(id)
	if err != nil {
		return ImageInspect{}, err
	}
	var out ImageInspect
	err = c.doJSON(ctx, http.MethodGet, "/images/"+cleanID+"/json", nil, c.requestTimeout, &out)
	return out, err
}

// ImageHistory queries GET /v{api}/images/{id}/history for per-layer byte sizes.
func (c *Client) ImageHistory(ctx context.Context, id string) ([]ImageHistoryItem, error) {
	cleanID, err := sanitizeResourceID(id)
	if err != nil {
		return nil, err
	}
	var out []ImageHistoryItem
	if err := c.doJSON(ctx, http.MethodGet, "/images/"+cleanID+"/history", nil, c.requestTimeout, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveImage deletes an image reference or digest via DELETE /v{api}/images/{id}.
func (c *Client) RemoveImage(ctx context.Context, id string, opts RemoveImageOptions) ([]ImageDeleteItem, error) {
	cleanID, err := sanitizeResourceID(id)
	if err != nil {
		return nil, err
	}
	q := make(url.Values)
	if opts.Force {
		q.Set("force", "true")
	}
	if opts.NoPrune {
		q.Set("noprune", "true")
	}
	var out []ImageDeleteItem
	if err := c.doJSON(ctx, http.MethodDelete, "/images/"+cleanID, q, c.pruneTimeout, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PruneImages invokes POST /v{api}/images/prune.
func (c *Client) PruneImages(ctx context.Context, danglingOnly bool, filters Filters) (ImagesPruneReport, error) {
	merged := filters.Clone()
	merged.AddDangling(danglingOnly)

	q := make(url.Values)
	if err := merged.ApplyQuery(q); err != nil {
		return ImagesPruneReport{}, err
	}
	var out ImagesPruneReport
	err := c.doJSON(ctx, http.MethodPost, "/images/prune", q, c.pruneTimeout, &out)
	return out, err
}

// PruneNetworks invokes POST /v{api}/networks/prune.
func (c *Client) PruneNetworks(ctx context.Context, filters Filters) (NetworksPruneReport, error) {
	q := make(url.Values)
	if err := filters.ApplyQuery(q); err != nil {
		return NetworksPruneReport{}, err
	}
	var out NetworksPruneReport
	err := c.doJSON(ctx, http.MethodPost, "/networks/prune", q, c.pruneTimeout, &out)
	return out, err
}

// PruneBuildCache invokes POST /v{api}/build/prune with optional keep-storage byte budget.
func (c *Client) PruneBuildCache(ctx context.Context, opts BuildCachePruneOptions) (BuildCachePruneReport, error) {
	q := make(url.Values)
	if opts.All {
		q.Set("all", "true")
	}
	if opts.KeepStorage > 0 {
		q.Set("keep-storage", strconv.FormatInt(opts.KeepStorage, 10))
	}
	if err := opts.Filters.ApplyQuery(q); err != nil {
		return BuildCachePruneReport{}, err
	}
	var out BuildCachePruneReport
	err := c.doJSON(ctx, http.MethodPost, "/build/prune", q, c.pruneTimeout, &out)
	return out, err
}

// ListVolumes queries GET /v{api}/volumes.
func (c *Client) ListVolumes(ctx context.Context, filters Filters) (VolumeListResponse, error) {
	q := make(url.Values)
	if err := filters.ApplyQuery(q); err != nil {
		return VolumeListResponse{}, err
	}
	var out VolumeListResponse
	err := c.doJSON(ctx, http.MethodGet, "/volumes", q, c.requestTimeout, &out)
	return out, err
}

// RemoveVolume deletes an unused volume via DELETE /v{api}/volumes/{name}.
func (c *Client) RemoveVolume(ctx context.Context, name string, force bool) error {
	cleanName, err := sanitizeResourceID(name)
	if err != nil {
		return err
	}
	q := make(url.Values)
	if force {
		q.Set("force", "true")
	}
	return c.doJSON(ctx, http.MethodDelete, "/volumes/"+cleanName, q, c.pruneTimeout, nil)
}

// PruneVolumes invokes POST /v{api}/volumes/prune.
func (c *Client) PruneVolumes(ctx context.Context, filters Filters) (VolumesPruneReport, error) {
	q := make(url.Values)
	if err := filters.ApplyQuery(q); err != nil {
		return VolumesPruneReport{}, err
	}
	var out VolumesPruneReport
	err := c.doJSON(ctx, http.MethodPost, "/volumes/prune", q, c.pruneTimeout, &out)
	return out, err
}

// StreamEvents connects to GET /v{api}/events, invokes onEvent for each decoded NDJSON
// frame, and automatically reconnects with bounded exponential backoff (advancing 'since'
// to the latest observed event timestamp) until ctx is canceled.
func (c *Client) StreamEvents(ctx context.Context, opts EventsOptions, onEvent func(EventMessage)) error {
	sinceCursor := strings.TrimSpace(opts.Since)
	backoff := 250 * time.Millisecond
	const maxBackoff = 5 * time.Second

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		apiVer, err := c.resolveAPIVersion(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := sleepWithContext(ctx, backoff); err != nil {
				return err
			}
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}

		curOpts := opts
		curOpts.Since = sinceCursor
		receivedAny, latestUnix, streamErr := c.streamEventsOnce(ctx, apiVer, curOpts, onEvent)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if latestUnix > 0 {
			sinceCursor = strconv.FormatInt(latestUnix, 10)
		}
		if streamErr == nil && curOpts.Until != "" {
			// Bounded historical stream completed cleanly.
			return nil
		}

		if receivedAny {
			backoff = 250 * time.Millisecond
		}
		if err := sleepWithContext(ctx, backoff); err != nil {
			return err
		}
		backoff = minDuration(backoff*2, maxBackoff)
	}
}

func (c *Client) streamEventsOnce(
	ctx context.Context,
	apiVer string,
	opts EventsOptions,
	onEvent func(EventMessage),
) (receivedAny bool, latestUnix int64, err error) {
	q := make(url.Values)
	if opts.Since != "" {
		q.Set("since", opts.Since)
	}
	if opts.Until != "" {
		q.Set("until", opts.Until)
	}
	if err := opts.Filters.ApplyQuery(q); err != nil {
		return false, 0, err
	}

	endpoint := c.versionedURL(apiVer, "/events", q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	var resp *http.Response
	err = c.breaker.Execute(ctx, func(callCtx context.Context) error {
		var doErr error
		resp, doErr = c.httpClient.Do(req.WithContext(callCtx))
		if doErr != nil {
			return doErr
		}
		if resp.StatusCode >= 400 {
			defer drainAndClose(resp.Body)
			return decodeAPIError(http.MethodGet, "/events", resp)
		}
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), maxEventLineBytes)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev EventMessage
		if decErr := json.Unmarshal(line, &ev); decErr != nil {
			continue
		}
		receivedAny = true
		if ev.Time > latestUnix {
			latestUnix = ev.Time
		}
		if onEvent != nil {
			onEvent(ev)
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return receivedAny, latestUnix, scanErr
	}
	return receivedAny, latestUnix, io.EOF
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	relPath string,
	query url.Values,
	timeout time.Duration,
	dst any,
) error {
	apiVer, err := c.resolveAPIVersion(ctx)
	if err != nil {
		return err
	}

	fullURL := c.versionedURL(apiVer, relPath, query)
	return c.breaker.Execute(ctx, func(callCtx context.Context) error {
		tCtx, cancel := context.WithTimeout(callCtx, timeout)
		defer cancel()

		req, err := http.NewRequestWithContext(tCtx, method, fullURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("docker %s %s: %w", method, relPath, err)
		}
		defer drainAndClose(resp.Body)

		if resp.StatusCode >= 400 {
			return decodeAPIError(method, relPath, resp)
		}

		if dst == nil || resp.StatusCode == http.StatusNoContent {
			return nil
		}

		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlResponseBytes+1))
		if err != nil {
			return fmt.Errorf("read %s %s body: %w", method, relPath, err)
		}
		if len(raw) > maxControlResponseBytes {
			return fmt.Errorf("docker %s %s response exceeded %d-byte safety ceiling", method, relPath, maxControlResponseBytes)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			return nil
		}
		if err := json.Unmarshal(trimmed, dst); err != nil {
			return fmt.Errorf("decode %s %s JSON: %w", method, relPath, err)
		}
		return nil
	})
}

func (c *Client) resolveAPIVersion(ctx context.Context) (string, error) {
	c.verMu.RLock()
	ver := c.negotiatedVersion
	c.verMu.RUnlock()
	if ver != "" {
		return ver, nil
	}

	info, err := c.Ping(ctx)
	if err != nil {
		return "", err
	}
	if info.APIVersion != "" {
		return info.APIVersion, nil
	}
	return fallbackAPIVersion, nil
}

func (c *Client) cacheNegotiatedVersion(apiVer string) {
	c.verMu.Lock()
	defer c.verMu.Unlock()
	if c.pinnedVersion != "" {
		c.negotiatedVersion = c.pinnedVersion
		return
	}
	c.negotiatedVersion = apiVer
}

func (c *Client) versionedURL(apiVer, relPath string, query url.Values) string {
	var b strings.Builder
	b.WriteString(c.baseURL)
	b.WriteString("/v")
	b.WriteString(apiVer)
	if !strings.HasPrefix(relPath, "/") {
		b.WriteByte('/')
	}
	b.WriteString(relPath)
	if len(query) > 0 {
		b.WriteByte('?')
		b.WriteString(query.Encode())
	}
	return b.String()
}

func decodeAPIError(method, endpoint string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	trimmed := bytes.TrimSpace(raw)

	var envelope struct {
		Message string `json:"message"`
	}
	msg := ""
	if len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &envelope); err == nil && strings.TrimSpace(envelope.Message) != "" {
			msg = strings.TrimSpace(envelope.Message)
		} else {
			msg = string(trimmed)
		}
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Method:     method,
		Endpoint:   endpoint,
		Message:    msg,
	}
}

func sanitizeResourceID(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("docker resource identifier cannot be empty")
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, "?#\\ \t\r\n\x00") {
		return "", fmt.Errorf("unsafe characters in docker resource identifier %q", raw)
	}
	return strings.TrimPrefix(s, "/"), nil
}

func normalizeAPIVersion(raw string) string {
	s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "v")
	if s == "" {
		return ""
	}
	return s
}

func clampAPIVersion(raw string) string {
	clean := normalizeAPIVersion(raw)
	maj, min, ok := parseMajorMinor(clean)
	if !ok || maj != 1 {
		return fallbackAPIVersion
	}
	_, minFloor, _ := parseMajorMinor(minSupportedAPIVersion)
	_, maxCeil, _ := parseMajorMinor(maxSupportedAPIVersion)
	if min < minFloor {
		return minSupportedAPIVersion
	}
	if min > maxCeil {
		return maxSupportedAPIVersion
	}
	return fmt.Sprintf("%d.%d", maj, min)
}

func parseMajorMinor(ver string) (int, int, bool) {
	parts := strings.Split(ver, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || maj < 1 || min < 0 {
		return 0, 0, false
	}
	return maj, min, true
}

func drainAndClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 4096))
	_ = rc.Close()
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
