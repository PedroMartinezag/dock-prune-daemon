package docker

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned immediately when the Docker socket circuit breaker is open
// or when another goroutine already holds the single-flight Half-Open recovery probe.
var ErrCircuitOpen = errors.New("docker engine circuit breaker is open")

// BreakerState represents one of the 3 states of the resilience circuit breaker.
type BreakerState string

const (
	BreakerClosed   BreakerState = "CLOSED"
	BreakerOpen     BreakerState = "OPEN"
	BreakerHalfOpen BreakerState = "HALF_OPEN"
)

// BreakerStats exposes atomic point-in-time circuit breaker telemetry for /metrics and UI.
type BreakerStats struct {
	State               BreakerState `json:"state"`
	ConsecutiveFailures int          `json:"consecutive_failures"`
	FailureThreshold    int          `json:"failure_threshold"`
	TotalTrips          uint64       `json:"total_trips"`
	TotalSuccesses      uint64       `json:"total_successes"`
	TotalFailures       uint64       `json:"total_failures"`
	TotalRejected       uint64       `json:"total_rejected"`
	OpenedAt            time.Time    `json:"opened_at,omitempty"`
	OpenUntil           time.Time    `json:"open_until,omitempty"`
	LastError           string       `json:"last_error,omitempty"`
}

// CircuitBreaker protects a degraded or I/O-wedged Docker daemon from cascading
// request storms using Closed -> Open -> single-probe Half-Open transitions.
type CircuitBreaker struct {
	mu               sync.Mutex
	failureThreshold int
	openTimeout      time.Duration
	nowFn            func() time.Time

	state               BreakerState
	probeInFlight       bool
	consecutiveFailures int
	totalTrips          uint64
	totalSuccesses      uint64
	totalFailures       uint64
	totalRejected       uint64
	openedAt            time.Time
	openUntil           time.Time
	lastError           string
}

// NewCircuitBreaker constructs a 3-state circuit breaker with sane production bounds.
func NewCircuitBreaker(failureThreshold int, openTimeout time.Duration) *CircuitBreaker {
	if failureThreshold < 1 {
		failureThreshold = 5
	}
	if openTimeout <= 0 {
		openTimeout = 60 * time.Second
	}
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		openTimeout:      openTimeout,
		nowFn:            time.Now,
		state:            BreakerClosed,
	}
}

// Execute runs fn under circuit breaker protection.
// Domain-level HTTP 4xx responses (such as 404 Not Found or 409 Conflict) and
// caller-initiated context.Canceled errors never trip the breaker.
func (b *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	isProbe, err := b.beforeCall()
	if err != nil {
		return err
	}

	callErr := fn(ctx)
	b.afterCall(isProbe, callErr)
	return callErr
}

// Stats returns a thread-safe snapshot of current breaker state and counters.
func (b *CircuitBreaker) Stats() BreakerStats {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.nowFn().UTC()
	effectiveState := b.state
	if effectiveState == BreakerOpen && !now.Before(b.openUntil) {
		effectiveState = BreakerHalfOpen
	}

	return BreakerStats{
		State:               effectiveState,
		ConsecutiveFailures: b.consecutiveFailures,
		FailureThreshold:    b.failureThreshold,
		TotalTrips:          b.totalTrips,
		TotalSuccesses:      b.totalSuccesses,
		TotalFailures:       b.totalFailures,
		TotalRejected:       b.totalRejected,
		OpenedAt:            b.openedAt,
		OpenUntil:           b.openUntil,
		LastError:           b.lastError,
	}
}

func (b *CircuitBreaker) beforeCall() (isHalfOpenProbe bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.nowFn().UTC()

	switch b.state {
	case BreakerClosed:
		return false, nil

	case BreakerOpen:
		if now.Before(b.openUntil) {
			b.totalRejected++
			return false, ErrCircuitOpen
		}
		// Cooldown window elapsed: promote to Half-Open and grant single-flight probe lease.
		b.state = BreakerHalfOpen
		b.probeInFlight = true
		return true, nil

	case BreakerHalfOpen:
		if b.probeInFlight {
			b.totalRejected++
			return false, ErrCircuitOpen
		}
		b.probeInFlight = true
		return true, nil

	default:
		return false, nil
	}
}

func (b *CircuitBreaker) afterCall(wasProbe bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Caller-initiated cancellation does not reflect daemon health; release probe lease cleanly.
	if errors.Is(err, context.Canceled) {
		if wasProbe && b.state == BreakerHalfOpen {
			b.probeInFlight = false
		}
		return
	}

	// HTTP 4xx responses prove dockerd is responsive and healthy at the socket/HTTP layer.
	if err == nil || isBenignDomainError(err) {
		b.totalSuccesses++
		b.consecutiveFailures = 0
		b.probeInFlight = false
		b.state = BreakerClosed
		b.openedAt = time.Time{}
		b.openUntil = time.Time{}
		return
	}

	// Transport error, socket hang/timeout, or HTTP 5xx server failure.
	now := b.nowFn().UTC()
	b.totalFailures++
	b.consecutiveFailures++
	b.lastError = err.Error()

	if wasProbe || b.state == BreakerHalfOpen || b.consecutiveFailures >= b.failureThreshold {
		b.tripLocked(now)
	}
}

func (b *CircuitBreaker) tripLocked(now time.Time) {
	b.state = BreakerOpen
	b.probeInFlight = false
	b.totalTrips++
	b.openedAt = now
	b.openUntil = now.Add(b.openTimeout)
}

func isBenignDomainError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
	}
	return false
}
