// Package config implements strict, zero-dependency layered configuration loading
// (Defaults -> JSON -> DPD_* Environment -> Explicit CLI Flags), mathematical
// hysteresis validation, secret redaction, and lock-free atomic hot-reloading.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MaxConfigFileBytes caps JSON configuration file reads at 1 MiB to prevent memory exhaustion.
const MaxConfigFileBytes = 1 << 20

// RedactedMask replaces sensitive tokens when exporting configuration to logs or status APIs.
const RedactedMask = "[REDACTED]"

// ByteSize represents a non-negative byte count with human-readable JSON and CLI parsing.
type ByteSize int64

// Binary storage unit constants.
const (
	KiB ByteSize = 1024
	MiB ByteSize = 1024 * KiB
	GiB ByteSize = 1024 * MiB
	TiB ByteSize = 1024 * GiB
)

// Bytes returns the raw int64 byte count.
func (b ByteSize) Bytes() int64 {
	return int64(b)
}

// GiBFloat returns the byte count expressed as floating-point gibibytes.
func (b ByteSize) GiBFloat() float64 {
	return float64(b) / float64(GiB)
}

// String renders ByteSize using the largest exact binary unit for lossless round-tripping.
func (b ByteSize) String() string {
	if b < 0 {
		return fmt.Sprintf("-%s", (-b).String())
	}
	if b == 0 {
		return "0B"
	}
	switch {
	case b%TiB == 0:
		return fmt.Sprintf("%dTiB", b/TiB)
	case b%GiB == 0:
		return fmt.Sprintf("%dGiB", b/GiB)
	case b%MiB == 0:
		return fmt.Sprintf("%dMiB", b/MiB)
	case b%KiB == 0:
		return fmt.Sprintf("%dKiB", b/KiB)
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// MarshalJSON serializes ByteSize as a canonical string (for example, "5GiB").
func (b ByteSize) MarshalJSON() ([]byte, error) {
	if b < 0 {
		return nil, fmt.Errorf("cannot marshal negative byte size: %d", b)
	}
	return json.Marshal(b.String())
}

// UnmarshalJSON parses either a human-readable string ("256MiB", "5GiB") or a raw integer byte count.
func (b *ByteSize) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return errors.New("byte size cannot be null or empty")
	}
	if trimmed[0] == '"' {
		var raw string
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return fmt.Errorf("invalid byte size string: %w", err)
		}
		parsed, err := ParseByteSize(raw)
		if err != nil {
			return err
		}
		*b = parsed
		return nil
	}
	rawInt, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid numeric byte size %q: %w", string(trimmed), err)
	}
	if rawInt < 0 {
		return fmt.Errorf("byte size cannot be negative: %d", rawInt)
	}
	*b = ByteSize(rawInt)
	return nil
}

// ParseByteSize parses strings like "0", "4096B", "64MiB", "1.5GiB", or "500MB" with overflow guards.
func ParseByteSize(raw string) (ByteSize, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("empty byte size")
	}
	if s[0] == '-' || s[0] == '+' {
		return 0, fmt.Errorf("signed byte size %q is not allowed", raw)
	}

	splitIdx := len(s)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= '0' && ch <= '9') || ch == '.' {
			continue
		}
		splitIdx = i
		break
	}

	numPart := s[:splitIdx]
	unitPart := strings.ToUpper(strings.TrimSpace(s[splitIdx:]))
	if numPart == "" {
		return 0, fmt.Errorf("missing numeric value in byte size %q", raw)
	}

	dotCount := 0
	digitCount := 0
	for i := 0; i < len(numPart); i++ {
		if numPart[i] == '.' {
			dotCount++
		} else if numPart[i] >= '0' && numPart[i] <= '9' {
			digitCount++
		} else {
			return 0, fmt.Errorf("invalid character in numeric part of %q", raw)
		}
	}
	if dotCount > 1 || digitCount == 0 {
		return 0, fmt.Errorf("malformed numeric value in byte size %q", raw)
	}

	var mult uint64
	switch unitPart {
	case "", "B":
		mult = 1
	case "K", "KI", "KIB":
		mult = uint64(KiB)
	case "KB":
		mult = 1000
	case "M", "MI", "MIB":
		mult = uint64(MiB)
	case "MB":
		mult = 1000 * 1000
	case "G", "GI", "GIB":
		mult = uint64(GiB)
	case "GB":
		mult = 1000 * 1000 * 1000
	case "T", "TI", "TIB":
		mult = uint64(TiB)
	case "TB":
		mult = 1000 * 1000 * 1000 * 1000
	default:
		return 0, fmt.Errorf("unsupported byte unit %q in %q", unitPart, raw)
	}

	if dotCount == 0 {
		val, err := strconv.ParseUint(numPart, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("byte size integer overflow in %q: %w", raw, err)
		}
		if val > uint64(math.MaxInt64)/mult {
			return 0, fmt.Errorf("byte size exceeds int64 maximum in %q", raw)
		}
		return ByteSize(int64(val * mult)), nil
	}

	fVal, err := strconv.ParseFloat(numPart, 64)
	if err != nil || math.IsNaN(fVal) || math.IsInf(fVal, 0) || fVal < 0 {
		return 0, fmt.Errorf("invalid fractional byte size %q", raw)
	}
	product := fVal * float64(mult)
	if math.IsNaN(product) || math.IsInf(product, 0) || product >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("fractional byte size overflow in %q", raw)
	}
	return ByteSize(int64(math.Round(product))), nil
}

// Duration wraps time.Duration with human-readable JSON string marshaling ("30s", "15m").
type Duration time.Duration

// Std converts Duration to standard library time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// String formats Duration using time.Duration.String.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// MarshalJSON encodes a non-negative Duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	if d < 0 {
		return nil, fmt.Errorf("cannot marshal negative duration: %s", d.String())
	}
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts a duration string ("30s", "2m") or raw integer nanoseconds.
func (d *Duration) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return errors.New("duration cannot be null or empty")
	}
	if trimmed[0] == '"' {
		var raw string
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return fmt.Errorf("invalid duration string: %w", err)
		}
		parsed, err := ParseDuration(raw)
		if err != nil {
			return err
		}
		*d = parsed
		return nil
	}
	ns, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid numeric duration %q: %w", string(trimmed), err)
	}
	if ns < 0 {
		return fmt.Errorf("duration cannot be negative: %d", ns)
	}
	*d = Duration(ns)
	return nil
}

// ParseDuration parses a non-negative duration string.
func ParseDuration(raw string) (Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("negative duration %q is not allowed", raw)
	}
	return Duration(parsed), nil
}

// Config is the root strongly typed configuration contract for dock-prune-daemon.
type Config struct {
	LogLevel   string          `json:"log_level"`
	LogFormat  string          `json:"log_format"`
	StateDir   string          `json:"state_dir"`
	DryRun     bool            `json:"dry_run"`
	Daemon     DaemonConfig    `json:"daemon"`
	Docker     DockerConfig    `json:"docker"`
	Watermarks WatermarkConfig `json:"watermarks"`
	Forecast   ForecastConfig  `json:"forecast"`
	Kernel     KernelConfig    `json:"kernel"`
	Prune      PruneConfig     `json:"prune"`
	Audit      AuditConfig     `json:"audit"`
	Telemetry  TelemetryConfig `json:"telemetry"`
}

// DaemonConfig controls event loops, cooldown pacing, and exclusive PID locking.
type DaemonConfig struct {
	PollInterval    Duration `json:"poll_interval"`
	Cooldown        Duration `json:"cooldown"`
	EventDriven     bool     `json:"event_driven"`
	EventDebounce   Duration `json:"event_debounce"`
	PIDFile         string   `json:"pid_file"`
	ShutdownTimeout Duration `json:"shutdown_timeout"`
}

// DockerConfig governs Unix/TCP socket transport and circuit breaker resilience.
type DockerConfig struct {
	Host                    string   `json:"host"`
	APIVersion              string   `json:"api_version"`
	ContainerRootDir        string   `json:"container_root_dir"`
	RequestTimeout          Duration `json:"request_timeout"`
	PruneTimeout            Duration `json:"prune_timeout"`
	BreakerFailureThreshold int      `json:"breaker_failure_threshold"`
	BreakerOpenTimeout      Duration `json:"breaker_open_timeout"`
}

// WatermarkConfig defines hysteresis bands across all operating pressure regimes.
type WatermarkConfig struct {
	PreemptivePercent    float64  `json:"preemptive_percent"`
	TargetPercent        float64  `json:"target_percent"`
	HighPercent          float64  `json:"high_percent"`
	CriticalPercent      float64  `json:"critical_percent"`
	PanicPercent         float64  `json:"panic_percent"`
	MinFreeBytes         ByteSize `json:"min_free_bytes"`
	PanicFreeBytes       ByteSize `json:"panic_free_bytes"`
	InodeTargetPercent   float64  `json:"inode_target_percent"`
	InodeHighPercent     float64  `json:"inode_high_percent"`
	InodeCriticalPercent float64  `json:"inode_critical_percent"`
}

// ForecastConfig parameterizes Holt-Winters double-exponential TTE forecasting.
type ForecastConfig struct {
	Enabled         bool     `json:"enabled"`
	Horizon         Duration `json:"horizon"`
	Alpha           float64  `json:"alpha"`
	Beta            float64  `json:"beta"`
	ZScoreThreshold float64  `json:"z_score_threshold"`
	WindowSize      int      `json:"window_size"`
}

// KernelConfig configures Linux PSI I/O stall pacing and ProcFS phantom FD scanning.
type KernelConfig struct {
	PSIEnabled         bool     `json:"psi_enabled"`
	ProcRoot           string   `json:"proc_root"`
	PSIIOBudgetPercent float64  `json:"psi_io_budget_percent"`
	PSIGamma           float64  `json:"psi_gamma"`
	BaseStagePause     Duration `json:"base_stage_pause"`
	MaxStagePause      Duration `json:"max_stage_pause"`
	PhantomScanEnabled bool     `json:"phantom_scan_enabled"`
	PhantomMinBytes    ByteSize `json:"phantom_min_bytes"`
}

// PruneConfig controls the 5-stage surgical waterfall and resource immunity rules.
type PruneConfig struct {
	EnableLogTruncate          bool     `json:"enable_log_truncate"`
	MaxContainerLogBytes       ByteSize `json:"max_container_log_bytes"`
	MinResourceAge             Duration `json:"min_resource_age"`
	BuildCacheKeepBytes        ByteSize `json:"build_cache_keep_bytes"`
	EnableStage4Images         bool     `json:"enable_stage4_images"`
	EnableVolumePrune          bool     `json:"enable_volume_prune"`
	ProtectedLabels            []string `json:"protected_labels"`
	ProtectedImagePatterns     []string `json:"protected_image_patterns"`
	ProtectedContainerPrefixes []string `json:"protected_container_prefixes"`
}

// AuditConfig configures Ed25519-signed Merkle JSONL ledgers and HMAC-SHA256 webhooks.
type AuditConfig struct {
	Enabled           bool     `json:"enabled"`
	LedgerPath        string   `json:"ledger_path"`
	PrivateKeyPath    string   `json:"private_key_path"`
	PublicKeyPath     string   `json:"public_key_path"`
	MaxLedgerBytes    ByteSize `json:"max_ledger_bytes"`
	WebhookURL        string   `json:"webhook_url"`
	WebhookHMACSecret string   `json:"webhook_hmac_secret"`
	WebhookTimeout    Duration `json:"webhook_timeout"`
	WebhookMaxRetries int      `json:"webhook_max_retries"`
}

// TelemetryConfig governs the OpenMetrics HTTP server, SSE UI, and FinOps ROI model.
type TelemetryConfig struct {
	Enabled                  bool    `json:"enabled"`
	ListenAddr               string  `json:"listen_addr"`
	BearerToken              string  `json:"bearer_token"`
	EnableWebUI              bool    `json:"enable_web_ui"`
	FinOpsCostPerGiBMonthUSD float64 `json:"finops_cost_per_gib_month_usd"`
	FinOpsIncidentCostUSD    float64 `json:"finops_incident_cost_usd"`
	FinOpsCIMinuteCostUSD    float64 `json:"finops_ci_minute_cost_usd"`
}

// Default returns a production-hardened baseline configuration.
func Default() Config {
	cfg := Config{
		LogLevel:  "info",
		LogFormat: "json",
		StateDir:  "/var/lib/dock-prune-daemon",
		DryRun:    false,
		Daemon: DaemonConfig{
			PollInterval:    Duration(30 * time.Second),
			Cooldown:        Duration(2 * time.Minute),
			EventDriven:     true,
			EventDebounce:   Duration(5 * time.Second),
			PIDFile:         "",
			ShutdownTimeout: Duration(20 * time.Second),
		},
		Docker: DockerConfig{
			Host:                    "unix:///var/run/docker.sock",
			APIVersion:              "",
			ContainerRootDir:        "/var/lib/docker",
			RequestTimeout:          Duration(15 * time.Second),
			PruneTimeout:            Duration(5 * time.Minute),
			BreakerFailureThreshold: 5,
			BreakerOpenTimeout:      Duration(60 * time.Second),
		},
		Watermarks: WatermarkConfig{
			PreemptivePercent:    65.0,
			TargetPercent:        70.0,
			HighPercent:          80.0,
			CriticalPercent:      90.0,
			PanicPercent:         96.0,
			MinFreeBytes:         5 * GiB,
			PanicFreeBytes:       2 * GiB,
			InodeTargetPercent:   70.0,
			InodeHighPercent:     80.0,
			InodeCriticalPercent: 92.0,
		},
		Forecast: ForecastConfig{
			Enabled:         true,
			Horizon:         Duration(30 * time.Minute),
			Alpha:           0.35,
			Beta:            0.20,
			ZScoreThreshold: 3.0,
			WindowSize:      32,
		},
		Kernel: KernelConfig{
			PSIEnabled:         true,
			ProcRoot:           "/proc",
			PSIIOBudgetPercent: 25.0,
			PSIGamma:           2.0,
			BaseStagePause:     Duration(250 * time.Millisecond),
			MaxStagePause:      Duration(10 * time.Second),
			PhantomScanEnabled: true,
			PhantomMinBytes:    64 * MiB,
		},
		Prune: PruneConfig{
			EnableLogTruncate:          true,
			MaxContainerLogBytes:       256 * MiB,
			MinResourceAge:             Duration(1 * time.Hour),
			BuildCacheKeepBytes:        5 * GiB,
			EnableStage4Images:         true,
			EnableVolumePrune:          false,
			ProtectedLabels:            []string{"io.dockprune.keep=true"},
			ProtectedImagePatterns:     []string{},
			ProtectedContainerPrefixes: []string{"k8s_"},
		},
		Audit: AuditConfig{
			Enabled:           true,
			LedgerPath:        "",
			PrivateKeyPath:    "",
			PublicKeyPath:     "",
			MaxLedgerBytes:    50 * MiB,
			WebhookURL:        "",
			WebhookHMACSecret: "",
			WebhookTimeout:    Duration(10 * time.Second),
			WebhookMaxRetries: 3,
		},
		Telemetry: TelemetryConfig{
			Enabled:                  true,
			ListenAddr:               "127.0.0.1:9402",
			BearerToken:              "",
			EnableWebUI:              true,
			FinOpsCostPerGiBMonthUSD: 0.10,
			FinOpsIncidentCostUSD:    250.0,
			FinOpsCIMinuteCostUSD:    0.016,
		},
	}
	cfg.Normalize()
	return cfg
}

// Clone returns a deep copy of Config so callers cannot mutate shared slice backing arrays.
func (c Config) Clone() Config {
	cp := c
	cp.Prune.ProtectedLabels = cloneStringSlice(c.Prune.ProtectedLabels)
	cp.Prune.ProtectedImagePatterns = cloneStringSlice(c.Prune.ProtectedImagePatterns)
	cp.Prune.ProtectedContainerPrefixes = cloneStringSlice(c.Prune.ProtectedContainerPrefixes)
	return cp
}

// Redacted returns a deep copy with secret credentials masked for safe logging and API exposure.
func (c Config) Redacted() Config {
	cp := c.Clone()
	if cp.Audit.WebhookHMACSecret != "" {
		cp.Audit.WebhookHMACSecret = RedactedMask
	}
	if cp.Telemetry.BearerToken != "" {
		cp.Telemetry.BearerToken = RedactedMask
	}
	return cp
}

// Normalize canonicalizes strings and derives state-dependent file paths when left unset.
func (c *Config) Normalize() {
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.LogFormat = strings.ToLower(strings.TrimSpace(c.LogFormat))
	c.StateDir = strings.TrimSpace(c.StateDir)
	c.Docker.Host = strings.TrimSpace(c.Docker.Host)
	c.Docker.APIVersion = strings.TrimSpace(c.Docker.APIVersion)
	c.Docker.ContainerRootDir = strings.TrimSpace(c.Docker.ContainerRootDir)
	c.Kernel.ProcRoot = strings.TrimSpace(c.Kernel.ProcRoot)
	c.Audit.WebhookURL = strings.TrimSpace(c.Audit.WebhookURL)
	c.Telemetry.ListenAddr = strings.TrimSpace(c.Telemetry.ListenAddr)

	if c.StateDir != "" {
		if strings.TrimSpace(c.Daemon.PIDFile) == "" {
			c.Daemon.PIDFile = filepath.Join(c.StateDir, "dock-prune.pid")
		}
		if strings.TrimSpace(c.Audit.LedgerPath) == "" {
			c.Audit.LedgerPath = filepath.Join(c.StateDir, "audit.jsonl")
		}
		if strings.TrimSpace(c.Audit.PrivateKeyPath) == "" {
			c.Audit.PrivateKeyPath = filepath.Join(c.StateDir, "ed25519.key")
		}
		if strings.TrimSpace(c.Audit.PublicKeyPath) == "" {
			c.Audit.PublicKeyPath = filepath.Join(c.StateDir, "ed25519.pub")
		}
	}

	c.Prune.ProtectedLabels = compactNonEmpty(c.Prune.ProtectedLabels)
	c.Prune.ProtectedImagePatterns = compactNonEmpty(c.Prune.ProtectedImagePatterns)
	c.Prune.ProtectedContainerPrefixes = compactNonEmpty(c.Prune.ProtectedContainerPrefixes)
}

// Validate checks all mathematical, hysteresis, security, and network invariants.
func (c Config) Validate() error {
	var errs []error

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log_level must be one of debug|info|warn|error, got %q", c.LogLevel))
	}

	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log_format must be json or text, got %q", c.LogFormat))
	}

	if c.StateDir == "" {
		errs = append(errs, errors.New("state_dir cannot be empty"))
	}

	// Daemon invariants
	if c.Daemon.PollInterval.Std() < time.Second {
		errs = append(errs, fmt.Errorf("daemon.poll_interval must be >= 1s, got %s", c.Daemon.PollInterval))
	}
	if c.Daemon.Cooldown.Std() < 0 {
		errs = append(errs, errors.New("daemon.cooldown cannot be negative"))
	}
	if c.Daemon.EventDebounce.Std() < 100*time.Millisecond {
		errs = append(errs, fmt.Errorf("daemon.event_debounce must be >= 100ms, got %s", c.Daemon.EventDebounce))
	}
	if c.Daemon.ShutdownTimeout.Std() < time.Second {
		errs = append(errs, fmt.Errorf("daemon.shutdown_timeout must be >= 1s, got %s", c.Daemon.ShutdownTimeout))
	}
	if strings.TrimSpace(c.Daemon.PIDFile) == "" {
		errs = append(errs, errors.New("daemon.pid_file cannot be empty"))
	}

	// Docker socket & breaker invariants
	if err := validateDockerHost(c.Docker.Host); err != nil {
		errs = append(errs, err)
	}
	if c.Docker.ContainerRootDir == "" {
		errs = append(errs, errors.New("docker.container_root_dir cannot be empty"))
	}
	if c.Docker.RequestTimeout.Std() < time.Second {
		errs = append(errs, fmt.Errorf("docker.request_timeout must be >= 1s, got %s", c.Docker.RequestTimeout))
	}
	if c.Docker.PruneTimeout.Std() < c.Docker.RequestTimeout.Std() {
		errs = append(errs, fmt.Errorf("docker.prune_timeout (%s) must be >= docker.request_timeout (%s)", c.Docker.PruneTimeout, c.Docker.RequestTimeout))
	}
	if c.Docker.BreakerFailureThreshold < 1 {
		errs = append(errs, fmt.Errorf("docker.breaker_failure_threshold must be >= 1, got %d", c.Docker.BreakerFailureThreshold))
	}
	if c.Docker.BreakerOpenTimeout.Std() < time.Second {
		errs = append(errs, fmt.Errorf("docker.breaker_open_timeout must be >= 1s, got %s", c.Docker.BreakerOpenTimeout))
	}

	// Watermarks & strict hysteresis ordering
	w := c.Watermarks
	if !isFiniteInRange(w.PreemptivePercent, 1.0, 99.0) ||
		!isFiniteInRange(w.TargetPercent, 1.0, 99.0) ||
		!isFiniteInRange(w.HighPercent, 1.0, 99.5) ||
		!isFiniteInRange(w.CriticalPercent, 1.0, 99.5) ||
		!isFiniteInRange(w.PanicPercent, 1.0, 99.9) {
		errs = append(errs, errors.New("all block watermark percentages must be finite values within [1.0, 99.9]"))
	} else {
		if w.PreemptivePercent > w.TargetPercent {
			errs = append(errs, fmt.Errorf("watermarks.preemptive_percent (%.2f) must be <= target_percent (%.2f)", w.PreemptivePercent, w.TargetPercent))
		}
		if w.TargetPercent >= w.HighPercent {
			errs = append(errs, fmt.Errorf("watermarks.target_percent (%.2f) must be < high_percent (%.2f) for hysteresis", w.TargetPercent, w.HighPercent))
		}
		if w.HighPercent >= w.CriticalPercent {
			errs = append(errs, fmt.Errorf("watermarks.high_percent (%.2f) must be < critical_percent (%.2f)", w.HighPercent, w.CriticalPercent))
		}
		if w.CriticalPercent >= w.PanicPercent {
			errs = append(errs, fmt.Errorf("watermarks.critical_percent (%.2f) must be < panic_percent (%.2f)", w.CriticalPercent, w.PanicPercent))
		}
	}

	if w.MinFreeBytes < 0 || w.PanicFreeBytes < 0 {
		errs = append(errs, errors.New("watermarks free byte thresholds cannot be negative"))
	} else if w.PanicFreeBytes > w.MinFreeBytes {
		errs = append(errs, fmt.Errorf("watermarks.panic_free_bytes (%s) must be <= min_free_bytes (%s)", w.PanicFreeBytes, w.MinFreeBytes))
	}

	if !isFiniteInRange(w.InodeTargetPercent, 1.0, 99.0) ||
		!isFiniteInRange(w.InodeHighPercent, 1.0, 99.5) ||
		!isFiniteInRange(w.InodeCriticalPercent, 1.0, 99.9) {
		errs = append(errs, errors.New("all inode watermark percentages must be finite values within [1.0, 99.9]"))
	} else {
		if w.InodeTargetPercent >= w.InodeHighPercent {
			errs = append(errs, fmt.Errorf("watermarks.inode_target_percent (%.2f) must be < inode_high_percent (%.2f)", w.InodeTargetPercent, w.InodeHighPercent))
		}
		if w.InodeHighPercent >= w.InodeCriticalPercent {
			errs = append(errs, fmt.Errorf("watermarks.inode_high_percent (%.2f) must be < inode_critical_percent (%.2f)", w.InodeHighPercent, w.InodeCriticalPercent))
		}
	}
	// Holt-Winters forecast invariants
	if !isFiniteOpenRange(c.Forecast.Alpha, 0.0, 1.0) {
		errs = append(errs, fmt.Errorf("forecast.alpha must be strictly within (0, 1), got %v", c.Forecast.Alpha))
	}
	if !isFiniteOpenRange(c.Forecast.Beta, 0.0, 1.0) {
		errs = append(errs, fmt.Errorf("forecast.beta must be strictly within (0, 1), got %v", c.Forecast.Beta))
	}
	if c.Forecast.Horizon.Std() < time.Minute {
		errs = append(errs, fmt.Errorf("forecast.horizon must be >= 1m, got %s", c.Forecast.Horizon))
	}
	if !isFiniteInRange(c.Forecast.ZScoreThreshold, 1.0, 20.0) {
		errs = append(errs, fmt.Errorf("forecast.z_score_threshold must be within [1.0, 20.0], got %v", c.Forecast.ZScoreThreshold))
	}
	if c.Forecast.WindowSize < 8 || c.Forecast.WindowSize > 1024 {
		errs = append(errs, fmt.Errorf("forecast.window_size must be within [8, 1024], got %d", c.Forecast.WindowSize))
	}

	// Kernel PSI & phantom FD scanner invariants
	if c.Kernel.ProcRoot == "" {
		errs = append(errs, errors.New("kernel.proc_root cannot be empty"))
	}
	if !isFiniteInRange(c.Kernel.PSIIOBudgetPercent, 0.5, 99.0) {
		errs = append(errs, fmt.Errorf("kernel.psi_io_budget_percent must be within [0.5, 99.0], got %v", c.Kernel.PSIIOBudgetPercent))
	}
	if !isFiniteInRange(c.Kernel.PSIGamma, 0.1, 50.0) {
		errs = append(errs, fmt.Errorf("kernel.psi_gamma must be within [0.1, 50.0], got %v", c.Kernel.PSIGamma))
	}
	if c.Kernel.BaseStagePause.Std() < 0 || c.Kernel.MaxStagePause.Std() < c.Kernel.BaseStagePause.Std() {
		errs = append(errs, fmt.Errorf("kernel.max_stage_pause (%s) must be >= base_stage_pause (%s) >= 0", c.Kernel.MaxStagePause, c.Kernel.BaseStagePause))
	}
	if c.Kernel.PhantomMinBytes < 1*MiB {
		errs = append(errs, fmt.Errorf("kernel.phantom_min_bytes must be >= 1MiB, got %s", c.Kernel.PhantomMinBytes))
	}

	// Prune policy invariants
	if c.Prune.EnableLogTruncate && c.Prune.MaxContainerLogBytes < 1*MiB {
		errs = append(errs, fmt.Errorf("prune.max_container_log_bytes must be >= 1MiB when log truncation is enabled, got %s", c.Prune.MaxContainerLogBytes))
	}
	if c.Prune.MinResourceAge.Std() < 0 {
		errs = append(errs, errors.New("prune.min_resource_age cannot be negative"))
	}
	if c.Prune.BuildCacheKeepBytes < 0 {
		errs = append(errs, errors.New("prune.build_cache_keep_bytes cannot be negative"))
	}

	// Audit ledger & webhook invariants
	if c.Audit.Enabled {
		if strings.TrimSpace(c.Audit.LedgerPath) == "" ||
			strings.TrimSpace(c.Audit.PrivateKeyPath) == "" ||
			strings.TrimSpace(c.Audit.PublicKeyPath) == "" {
			errs = append(errs, errors.New("audit ledger_path, private_key_path, and public_key_path are required when audit.enabled=true"))
		}
		if c.Audit.MaxLedgerBytes < 1*MiB {
			errs = append(errs, fmt.Errorf("audit.max_ledger_bytes must be >= 1MiB, got %s", c.Audit.MaxLedgerBytes))
		}
	}
	if c.Audit.WebhookURL != "" {
		parsedURL, err := url.Parse(c.Audit.WebhookURL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			errs = append(errs, fmt.Errorf("audit.webhook_url must be a valid http:// or https:// URL, got %q", c.Audit.WebhookURL))
		}
	}
	if c.Audit.WebhookTimeout.Std() < time.Second {
		errs = append(errs, fmt.Errorf("audit.webhook_timeout must be >= 1s, got %s", c.Audit.WebhookTimeout))
	}
	if c.Audit.WebhookMaxRetries < 0 || c.Audit.WebhookMaxRetries > 10 {
		errs = append(errs, fmt.Errorf("audit.webhook_max_retries must be within [0, 10], got %d", c.Audit.WebhookMaxRetries))
	}

	// Telemetry & FinOps invariants
	if c.Telemetry.Enabled {
		if _, _, err := net.SplitHostPort(c.Telemetry.ListenAddr); err != nil {
			errs = append(errs, fmt.Errorf("telemetry.listen_addr %q is not a valid host:port: %w", c.Telemetry.ListenAddr, err))
		}
	}
	if !isFiniteNonNegative(c.Telemetry.FinOpsCostPerGiBMonthUSD) ||
		!isFiniteNonNegative(c.Telemetry.FinOpsIncidentCostUSD) ||
		!isFiniteNonNegative(c.Telemetry.FinOpsCIMinuteCostUSD) {
		errs = append(errs, errors.New("telemetry FinOps cost rates must be finite non-negative numbers"))
	}

	return errors.Join(errs...)
}

// MergeJSONBytes decodes strict JSON (rejecting unknown fields and trailing data) onto dst.
func MergeJSONBytes(dst *Config, raw []byte) error {
	if dst == nil {
		return errors.New("nil destination config")
	}
	if len(raw) > MaxConfigFileBytes {
		return fmt.Errorf("config payload exceeds maximum size of %d bytes", MaxConfigFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing tokens after root JSON object")
	}
	return nil
}

// MergeJSONFile reads a JSON configuration file up to MaxConfigFileBytes and merges it into dst.
func MergeJSONFile(dst *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config file %q: %w", path, err)
	}
	defer f.Close()

	limited := io.LimitReader(f, MaxConfigFileBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	if err := MergeJSONBytes(dst, raw); err != nil {
		return fmt.Errorf("config file %q: %w", path, err)
	}
	return nil
}

// EnvLookupFunc abstracts os.LookupEnv for deterministic concurrent testing.
type EnvLookupFunc func(key string) (string, bool)

// ApplyEnv overlays DPD_* environment variables onto dst.
func ApplyEnv(dst *Config, lookup EnvLookupFunc) error {
	if dst == nil || lookup == nil {
		return nil
	}
	var errs []error

	setStr := func(envKey string, target *string) {
		if v, ok := lookup(envKey); ok {
			*target = strings.TrimSpace(v)
		}
	}
	setBool := func(envKey string, target *bool) {
		if v, ok := lookup(envKey); ok {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid boolean in %s=%q: %w", envKey, v, err))
				return
			}
			*target = b
		}
	}
	setFloat := func(envKey string, target *float64) {
		if v, ok := lookup(envKey); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				errs = append(errs, fmt.Errorf("invalid float in %s=%q", envKey, v))
				return
			}
			*target = f
		}
	}
	setDur := func(envKey string, target *Duration) {
		if v, ok := lookup(envKey); ok {
			d, err := ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid duration in %s=%q: %w", envKey, v, err))
				return
			}
			*target = d
		}
	}
	setBytes := func(envKey string, target *ByteSize) {
		if v, ok := lookup(envKey); ok {
			b, err := ParseByteSize(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid byte size in %s=%q: %w", envKey, v, err))
				return
			}
			*target = b
		}
	}
	setCSV := func(envKey string, target *[]string) {
		if v, ok := lookup(envKey); ok {
			*target = splitCSV(v)
		}
	}

	setStr("DPD_LOG_LEVEL", &dst.LogLevel)
	setStr("DPD_LOG_FORMAT", &dst.LogFormat)
	setStr("DPD_STATE_DIR", &dst.StateDir)
	setBool("DPD_DRY_RUN", &dst.DryRun)

	setDur("DPD_POLL_INTERVAL", &dst.Daemon.PollInterval)
	setDur("DPD_COOLDOWN", &dst.Daemon.Cooldown)
	setBool("DPD_EVENT_DRIVEN", &dst.Daemon.EventDriven)
	setStr("DPD_PID_FILE", &dst.Daemon.PIDFile)

	setStr("DPD_DOCKER_HOST", &dst.Docker.Host)
	setStr("DPD_DOCKER_API_VERSION", &dst.Docker.APIVersion)
	setStr("DPD_DOCKER_ROOT_DIR", &dst.Docker.ContainerRootDir)

	setFloat("DPD_WATERMARK_PREEMPTIVE", &dst.Watermarks.PreemptivePercent)
	setFloat("DPD_WATERMARK_TARGET", &dst.Watermarks.TargetPercent)
	setFloat("DPD_WATERMARK_HIGH", &dst.Watermarks.HighPercent)
	setFloat("DPD_WATERMARK_CRITICAL", &dst.Watermarks.CriticalPercent)
	setFloat("DPD_WATERMARK_PANIC", &dst.Watermarks.PanicPercent)
	setBytes("DPD_MIN_FREE_BYTES", &dst.Watermarks.MinFreeBytes)

	setBool("DPD_FORECAST_ENABLED", &dst.Forecast.Enabled)
	setDur("DPD_FORECAST_HORIZON", &dst.Forecast.Horizon)

	setBool("DPD_PSI_ENABLED", &dst.Kernel.PSIEnabled)
	setStr("DPD_PROC_ROOT", &dst.Kernel.ProcRoot)
	setFloat("DPD_PSI_IO_BUDGET", &dst.Kernel.PSIIOBudgetPercent)

	setBool("DPD_ENABLE_LOG_TRUNCATE", &dst.Prune.EnableLogTruncate)
	setBytes("DPD_MAX_CONTAINER_LOG_BYTES", &dst.Prune.MaxContainerLogBytes)
	setDur("DPD_MIN_RESOURCE_AGE", &dst.Prune.MinResourceAge)
	setBytes("DPD_BUILD_CACHE_KEEP_BYTES", &dst.Prune.BuildCacheKeepBytes)
	setBool("DPD_ENABLE_VOLUME_PRUNE", &dst.Prune.EnableVolumePrune)
	setCSV("DPD_PROTECTED_LABELS", &dst.Prune.ProtectedLabels)
	setCSV("DPD_PROTECTED_IMAGE_PATTERNS", &dst.Prune.ProtectedImagePatterns)

	setBool("DPD_AUDIT_ENABLED", &dst.Audit.Enabled)
	setStr("DPD_AUDIT_LEDGER_PATH", &dst.Audit.LedgerPath)
	setStr("DPD_WEBHOOK_URL", &dst.Audit.WebhookURL)
	setStr("DPD_WEBHOOK_HMAC_SECRET", &dst.Audit.WebhookHMACSecret)

	setBool("DPD_TELEMETRY_ENABLED", &dst.Telemetry.Enabled)
	setStr("DPD_TELEMETRY_LISTEN_ADDR", &dst.Telemetry.ListenAddr)
	setStr("DPD_TELEMETRY_BEARER_TOKEN", &dst.Telemetry.BearerToken)

	return errors.Join(errs...)
}

// FlagOverrides captures CLI flags bound to a FlagSet and applies only explicitly visited flags.
type FlagOverrides struct {
	fs              *flag.FlagSet
	configPath      string
	logLevel        string
	logFormat       string
	stateDir        string
	dryRun          bool
	dockerHost      string
	dockerRoot      string
	pollInterval    string
	targetPercent   float64
	highPercent     float64
	criticalPercent float64
	panicPercent    float64
	minFree         string
	listenAddr      string
	enableVolumes   bool
}

// BindFlags registers standard CLI flags onto fs without mutating defaults prematurely.
func BindFlags(fs *flag.FlagSet) *FlagOverrides {
	o := &FlagOverrides{fs: fs}
	fs.StringVar(&o.configPath, "config", "", "Path to optional JSON configuration file")
	fs.StringVar(&o.logLevel, "log-level", "info", "Log verbosity (debug|info|warn|error)")
	fs.StringVar(&o.logFormat, "log-format", "json", "Log output format (json|text)")
	fs.StringVar(&o.stateDir, "state-dir", "/var/lib/dock-prune-daemon", "Directory for PID lock, Ed25519 keys, and audit ledger")
	fs.BoolVar(&o.dryRun, "dry-run", false, "Simulate waterfall reclamation without deleting resources")
	fs.StringVar(&o.dockerHost, "docker-host", "unix:///var/run/docker.sock", "Docker Engine socket endpoint")
	fs.StringVar(&o.dockerRoot, "docker-root", "/var/lib/docker", "Docker data root directory monitored by Statfs")
	fs.StringVar(&o.pollInterval, "poll-interval", "30s", "Periodic disk pressure check interval")
	fs.Float64Var(&o.targetPercent, "target-percent", 70.0, "Target disk usage percentage where pruning stops")
	fs.Float64Var(&o.highPercent, "high-percent", 80.0, "High disk usage watermark triggering ELEVATED pruning")
	fs.Float64Var(&o.criticalPercent, "critical-percent", 90.0, "Critical disk usage watermark unlocking OCI DAG pruning")
	fs.Float64Var(&o.panicPercent, "panic-percent", 96.0, "Panic disk usage watermark bypassing PSI I/O throttling")
	fs.StringVar(&o.minFree, "min-free", "5GiB", "Minimum free disk space floor (for example, 5GiB)")
	fs.StringVar(&o.listenAddr, "listen-addr", "127.0.0.1:9402", "Telemetry and control plane HTTP listen address")
	fs.BoolVar(&o.enableVolumes, "enable-volumes", false, "Allow Stage 4 pruning of anonymous unreferenced volumes")
	return o
}

// ConfigPath returns the --config path resolved from CLI flags or DPD_CONFIG_FILE.
func (o *FlagOverrides) ConfigPath(lookup EnvLookupFunc) string {
	if o != nil && strings.TrimSpace(o.configPath) != "" {
		return strings.TrimSpace(o.configPath)
	}
	if lookup != nil {
		if v, ok := lookup("DPD_CONFIG_FILE"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Apply overlays only the flags explicitly passed on the command line onto dst.
func (o *FlagOverrides) Apply(dst *Config) error {
	if o == nil || o.fs == nil || dst == nil {
		return nil
	}
	var errs []error
	o.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "log-level":
			dst.LogLevel = o.logLevel
		case "log-format":
			dst.LogFormat = o.logFormat
		case "state-dir":
			dst.StateDir = o.stateDir
		case "dry-run":
			dst.DryRun = o.dryRun
		case "docker-host":
			dst.Docker.Host = o.dockerHost
		case "docker-root":
			dst.Docker.ContainerRootDir = o.dockerRoot
		case "poll-interval":
			d, err := ParseDuration(o.pollInterval)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid --poll-interval: %w", err))
				return
			}
			dst.Daemon.PollInterval = d
		case "target-percent":
			dst.Watermarks.TargetPercent = o.targetPercent
			if o.targetPercent >= 1.0 && dst.Watermarks.PreemptivePercent > o.targetPercent {
				dst.Watermarks.PreemptivePercent = o.targetPercent
			}
		case "high-percent":
			dst.Watermarks.HighPercent = o.highPercent
		case "critical-percent":
			dst.Watermarks.CriticalPercent = o.criticalPercent
		case "panic-percent":
			dst.Watermarks.PanicPercent = o.panicPercent
		case "min-free":
			b, err := ParseByteSize(o.minFree)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid --min-free: %w", err))
				return
			}
			dst.Watermarks.MinFreeBytes = b
		case "listen-addr":
			dst.Telemetry.ListenAddr = o.listenAddr
		case "enable-volumes":
			dst.Prune.EnableVolumePrune = o.enableVolumes
		}
	})
	return errors.Join(errs...)
}

// Load executes the 4-layer configuration pipeline:
// 1. Built-in defaults -> 2. Optional JSON file -> 3. DPD_* Env -> 4. Visited CLI flags.
func Load(configPath string, lookup EnvLookupFunc, flags *FlagOverrides) (Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	// Start with unset derived state paths so custom state_dir overrides cascade cleanly.
	cfg := Default()
	cfg.Daemon.PIDFile = ""
	cfg.Audit.LedgerPath = ""
	cfg.Audit.PrivateKeyPath = ""
	cfg.Audit.PublicKeyPath = ""

	resolvedPath := strings.TrimSpace(configPath)
	if resolvedPath == "" && flags != nil {
		resolvedPath = flags.ConfigPath(lookup)
	}
	if resolvedPath != "" {
		if err := MergeJSONFile(&cfg, resolvedPath); err != nil {
			return Config{}, err
		}
	}

	if err := ApplyEnv(&cfg, lookup); err != nil {
		return Config{}, err
	}

	if flags != nil {
		if err := flags.Apply(&cfg); err != nil {
			return Config{}, err
		}
	}

	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Store holds the active Config inside a lock-free atomic pointer for SIGHUP hot-reloading.
type Store struct {
	active     atomic.Pointer[Config]
	configPath string
	lookup     EnvLookupFunc
}

// NewStore validates initial and initializes an atomic configuration store.
func NewStore(initial Config, configPath string, lookup EnvLookupFunc) (*Store, error) {
	initial.Normalize()
	if err := initial.Validate(); err != nil {
		return nil, fmt.Errorf("invalid initial config: %w", err)
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	cloned := initial.Clone()
	s := &Store{
		configPath: strings.TrimSpace(configPath),
		lookup:     lookup,
	}
	s.active.Store(&cloned)
	return s, nil
}

// Current returns an isolated deep copy of the active configuration in O(1) lock-free time.
func (s *Store) Current() Config {
	ptr := s.active.Load()
	if ptr == nil {
		return Default()
	}
	return ptr.Clone()
}

// Update validates next and atomically swaps it in; invalid configs leave the active state untouched.
func (s *Store) Update(next Config) error {
	next.Normalize()
	if err := next.Validate(); err != nil {
		return err
	}
	cloned := next.Clone()
	s.active.Store(&cloned)
	return nil
}

// Reload re-reads the JSON file and environment variables, swapping atomically only if valid.
func (s *Store) Reload() (Config, error) {
	next, err := Load(s.configPath, s.lookup, nil)
	if err != nil {
		return s.Current(), err
	}
	if err := s.Update(next); err != nil {
		return s.Current(), err
	}
	return next.Clone(), nil
}

func validateDockerHost(host string) error {
	if host == "" {
		return errors.New("docker.host cannot be empty")
	}
	u, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("invalid docker.host %q: %w", host, err)
	}
	switch u.Scheme {
	case "unix":
		if strings.TrimSpace(u.Path) == "" {
			return fmt.Errorf("unix docker.host %q requires a non-empty socket path", host)
		}
	case "http", "https", "tcp":
		if strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("%s docker.host %q requires host:port", u.Scheme, host)
		}
	default:
		return fmt.Errorf("unsupported docker.host scheme %q (expected unix, http, https, or tcp)", u.Scheme)
	}
	return nil
}

func isFiniteInRange(v, minVal, maxVal float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= minVal && v <= maxVal
}

func isFiniteOpenRange(v, minVal, maxVal float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > minVal && v < maxVal
}

func isFiniteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func compactNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	return compactNonEmpty(parts)
}
