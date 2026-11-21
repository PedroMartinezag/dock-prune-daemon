package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

const (
	webhookQueueCapacity = 64
	headerEvent          = "X-DockPrune-Event"
	headerDelivery       = "X-DockPrune-Delivery"
	headerTimestamp      = "X-DockPrune-Timestamp"
	headerSignature256   = "X-DockPrune-Signature-256"
)

// WebhookPayload is the JSON body delivered to enterprise SIEM, Slack, or PagerDuty endpoints.
type WebhookPayload struct {
	Event        string       `json:"event"`
	SentAt       time.Time    `json:"sent_at"`
	AgentVersion string       `json:"agent_version"`
	LedgerSeq    uint64       `json:"ledger_sequence,omitempty"`
	RecordHash   string       `json:"record_hash,omitempty"`
	Summary      CycleSummary `json:"summary"`
}

// ComputeWebhookSignature generates a replay-protected HMAC-SHA256 signature ("sha256=<hex>")
// over "<unix_timestamp>.<raw_json_body>".
func ComputeWebhookSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature validates X-DockPrune-Signature-256 in constant time using hmac.Equal.
func VerifyWebhookSignature(secret, timestamp, signatureHeader string, body []byte) bool {
	if secret == "" || timestamp == "" || !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	gotHex := strings.TrimPrefix(signatureHeader, "sha256=")
	gotBytes, err := hex.DecodeString(gotHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	expectedBytes := mac.Sum(nil)
	return hmac.Equal(gotBytes, expectedBytes)
}

// Notifier dispatches non-blocking, retryable HMAC-SHA256 webhook alerts on a bounded queue.
type Notifier struct {
	url        string
	hmacSecret string
	timeout    time.Duration
	maxRetries int
	baseDelay  time.Duration
	userAgent  string
	httpClient *http.Client
	nowFn      func() time.Time

	queue   chan WebhookPayload
	closed  atomic.Bool
	wg      sync.WaitGroup

	deliveredCount atomic.Uint64
	failedCount    atomic.Uint64
	droppedCount   atomic.Uint64
}

// NewNotifier initializes a background webhook dispatcher when cfg.WebhookURL is non-empty.
func NewNotifier(cfg config.AuditConfig) *Notifier {
	targetURL := strings.TrimSpace(cfg.WebhookURL)
	timeout := cfg.WebhookTimeout.Std()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxRetries := cfg.WebhookMaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	n := &Notifier{
		url:        targetURL,
		hmacSecret: cfg.WebhookHMACSecret,
		timeout:    timeout,
		maxRetries: maxRetries,
		baseDelay:  200 * time.Millisecond,
		userAgent:  buildinfo.UserAgent(),
		httpClient: &http.Client{Timeout: timeout},
		nowFn:      time.Now,
	}

	if targetURL != "" {
		n.queue = make(chan WebhookPayload, webhookQueueCapacity)
		n.wg.Add(1)
		go n.worker()
	}
	return n
}

// Enabled reports whether a target webhook URL is configured.
func (n *Notifier) Enabled() bool {
	return n != nil && n.url != ""
}

// Stats returns atomic delivery, failure, and queue-drop counters.
func (n *Notifier) Stats() (delivered, failed, dropped uint64) {
	if n == nil {
		return 0, 0, 0
	}
	return n.deliveredCount.Load(), n.failedCount.Load(), n.droppedCount.Load()
}

// Enqueue schedules a reclamation cycle notification without blocking the main daemon loop.
func (n *Notifier) Enqueue(report engine.CycleReport, rec Record) bool {
	if !n.Enabled() || n.closed.Load() {
		return false
	}
	payload := WebhookPayload{
		Event:        "cycle.completed",
		SentAt:       n.nowFn().UTC(),
		AgentVersion: buildinfo.Get().Version,
		LedgerSeq:    rec.Sequence,
		RecordHash:   rec.RecordHash,
		Summary:      SummarizeCycle(report),
	}

	select {
	case n.queue <- payload:
		return true
	default:
		n.droppedCount.Add(1)
		return false
	}
}

// DeliverSync sends a webhook synchronously with bounded exponential backoff retries.
func (n *Notifier) DeliverSync(ctx context.Context, payload WebhookPayload) error {
	if !n.Enabled() {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	var lastErr error
	delay := n.baseDelay
	if delay <= 0 {
		delay = 50 * time.Millisecond
	}

	for attempt := 0; attempt <= n.maxRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			delay = minBackoff(delay*2, 5*time.Second)
		}

		retryable, sendErr := n.sendAttempt(ctx, payload.Summary.CycleID, body)
		if sendErr == nil {
			n.deliveredCount.Add(1)
			return nil
		}
		lastErr = sendErr
		if !retryable {
			break
		}
	}

	n.failedCount.Add(1)
	return lastErr
}

// Close stops accepting new events and waits up to ctx deadline for queued deliveries to drain.
func (n *Notifier) Close(ctx context.Context) error {
	if !n.Enabled() {
		return nil
	}
	if n.closed.CompareAndSwap(false, true) {
		close(n.queue)
	}

	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Notifier) worker() {
	defer n.wg.Done()
	for payload := range n.queue {
		reqCtx, cancel := context.WithTimeout(context.Background(), n.timeout*time.Duration(n.maxRetries+1))
		_ = n.DeliverSync(reqCtx, payload)
		cancel()
	}
}

func (n *Notifier) sendAttempt(ctx context.Context, deliveryID string, body []byte) (retryable bool, err error) {
	tCtx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(tCtx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}

	ts := strconv.FormatInt(n.nowFn().UTC().Unix(), 10)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", n.userAgent)
	req.Header.Set(headerEvent, "cycle.completed")
	req.Header.Set(headerDelivery, deliveryID)
	req.Header.Set(headerTimestamp, ts)
	if n.hmacSecret != "" {
		req.Header.Set(headerSignature256, ComputeWebhookSignature(n.hmacSecret, ts, body))
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false, err
		}
		return true, fmt.Errorf("post webhook: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return true, fmt.Errorf("webhook transient HTTP %d", resp.StatusCode)
	}
	return false, fmt.Errorf("webhook rejected permanently with HTTP %d", resp.StatusCode)
}

func minBackoff(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
