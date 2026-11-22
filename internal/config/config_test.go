package config

import (
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfigIsValidAndNormalized(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default() config failed validation: %v", err)
	}
	if cfg.Prune.EnableVolumePrune {
		t.Fatal("EnableVolumePrune must default to false for production safety")
	}
	if cfg.Telemetry.ListenAddr != "127.0.0.1:9402" {
		t.Fatalf("unexpected default ListenAddr: %s", cfg.Telemetry.ListenAddr)
	}
	if !strings.HasPrefix(cfg.Daemon.PIDFile, cfg.StateDir) {
		t.Fatalf("expected PIDFile %q to be derived under StateDir %q", cfg.Daemon.PIDFile, cfg.StateDir)
	}
}

func TestPrecedence_Defaults_JSON_Env_CLIFlags(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	customStateDir := filepath.Join(tmpDir, "runtime-state")

	jsonPayload := `{
		"log_level": "warn",
		"log_format": "text",
		"state_dir": "` + filepath.ToSlash(customStateDir) + `",
		"watermarks": {
			"preemptive_percent": 60,
			"target_percent": 68,
			"high_percent": 78,
			"critical_percent": 88,
			"panic_percent": 95,
			"min_free_bytes": "8GiB"
		},
		"prune": {
			"max_container_log_bytes": "512MiB"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonPayload), 0o600); err != nil {
		t.Fatalf("write temp config JSON: %v", err)
	}

	envMap := map[string]string{
		"DPD_LOG_LEVEL":           "debug",
		"DPD_WATERMARK_HIGH":      "82.5",
		"DPD_PROTECTED_LABELS":    "env.keep=true, team.critical=1",
		"DPD_WEBHOOK_HMAC_SECRET": "top-secret-hmac-key",
	}
	lookup := func(k string) (string, bool) {
		v, ok := envMap[k]
		return v, ok
	}

	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	overrides := BindFlags(fs)
	// Pass only --config and --high-percent; unvisited flags must NOT overwrite Env or JSON!
	if err := fs.Parse([]string{"--config", cfgPath, "--high-percent", "84"}); err != nil {
		t.Fatalf("parse CLI flags: %v", err)
	}

	loaded, err := Load("", lookup, overrides)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	// JSON overrode Default ("text" vs "json") and remained untouched by Env/CLI
	if loaded.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want %q (from JSON)", loaded.LogFormat, "text")
	}
	// Env overrode JSON ("debug" vs "warn") and unvisited --log-level flag did not clobber it
	if loaded.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q (from Env)", loaded.LogLevel, "debug")
	}
	// Explicit CLI flag overrode both Env (82.5) and JSON (78)
	if loaded.Watermarks.HighPercent != 84.0 {
		t.Errorf("HighPercent = %.2f, want 84.0 (from CLI flag)", loaded.Watermarks.HighPercent)
	}
	// Derived state paths cascaded from JSON state_dir
	expectedLedger := filepath.Join(filepath.FromSlash(filepath.ToSlash(customStateDir)), "audit.jsonl")
	if loaded.Audit.LedgerPath != expectedLedger {
		t.Errorf("LedgerPath = %q, want %q", loaded.Audit.LedgerPath, expectedLedger)
	}
	// ByteSize parsed cleanly from JSON
	if loaded.Prune.MaxContainerLogBytes != 512*MiB {
		t.Errorf("MaxContainerLogBytes = %s, want 512MiB", loaded.Prune.MaxContainerLogBytes)
	}
	// CSV labels parsed cleanly from Env
	if len(loaded.Prune.ProtectedLabels) != 2 || loaded.Prune.ProtectedLabels[1] != "team.critical=1" {
		t.Errorf("unexpected ProtectedLabels: %#v", loaded.Prune.ProtectedLabels)
	}
}

func TestStrictJSON_RejectsUnknownFieldsAndTrailingTokens(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "unknown field typo",
			payload: `{"log_level": "info", "typo_field": true}`,
		},
		{
			name:    "trailing JSON object",
			payload: `{"log_level": "info"}{"dry_run": true}`,
		},
		{
			name:    "negative duration",
			payload: `{"daemon": {"poll_interval": "-5s"}}`,
		},
		{
			name:    "negative byte size",
			payload: `{"watermarks": {"min_free_bytes": -1024}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			if err := MergeJSONBytes(&cfg, []byte(tc.payload)); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestWatermarkHysteresisAndSafetyValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "preemptive above target",
			mutate: func(c *Config) {
				c.Watermarks.PreemptivePercent = 72
				c.Watermarks.TargetPercent = 70
			},
		},
		{
			name: "target equals high (missing hysteresis band)",
			mutate: func(c *Config) {
				c.Watermarks.TargetPercent = 80
				c.Watermarks.HighPercent = 80
			},
		},
		{
			name: "high above critical",
			mutate: func(c *Config) {
				c.Watermarks.HighPercent = 91
				c.Watermarks.CriticalPercent = 90
			},
		},
		{
			name: "critical equals panic",
			mutate: func(c *Config) {
				c.Watermarks.CriticalPercent = 96
				c.Watermarks.PanicPercent = 96
			},
		},
		{
			name: "NaN watermark",
			mutate: func(c *Config) {
				c.Watermarks.HighPercent = math.NaN()
			},
		},
		{
			name: "panic free bytes greater than min free bytes",
			mutate: func(c *Config) {
				c.Watermarks.PanicFreeBytes = 10 * GiB
				c.Watermarks.MinFreeBytes = 5 * GiB
			},
		},
		{
			name: "inverted inode watermarks",
			mutate: func(c *Config) {
				c.Watermarks.InodeTargetPercent = 85
				c.Watermarks.InodeHighPercent = 80
			},
		},
		{
			name: "zero poll interval",
			mutate: func(c *Config) {
				c.Daemon.PollInterval = 0
			},
		},
		{
			name: "unsupported docker host scheme",
			mutate: func(c *Config) {
				c.Docker.Host = "ftp://127.0.0.1:2375"
			},
		},
		{
			name: "invalid webhook scheme",
			mutate: func(c *Config) {
				c.Audit.WebhookURL = "javascript:alert(1)"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for case %q, got nil", tc.name)
			}
		})
	}
}

func TestByteSizeAndDurationRoundTrip(t *testing.T) {
	t.Parallel()

	size, err := ParseByteSize("1.5GiB")
	if err != nil {
		t.Fatalf("ParseByteSize(1.5GiB) error: %v", err)
	}
	if size != 1536*MiB {
		t.Fatalf("1.5GiB = %d bytes, want %d", size.Bytes(), (1536 * MiB).Bytes())
	}

	if _, err := ParseByteSize("99999999999999999999TiB"); err == nil {
		t.Fatal("expected overflow error on huge TiB value")
	}

	orig := Default()
	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal(Default) error: %v", err)
	}
	var decoded Config
	if err := MergeJSONBytes(&decoded, encoded); err != nil {
		t.Fatalf("MergeJSONBytes round-trip error: %v", err)
	}
	if decoded.Watermarks.MinFreeBytes != orig.Watermarks.MinFreeBytes {
		t.Errorf("MinFreeBytes mismatch: got %s, want %s", decoded.Watermarks.MinFreeBytes, orig.Watermarks.MinFreeBytes)
	}
	if decoded.Daemon.PollInterval != orig.Daemon.PollInterval {
		t.Errorf("PollInterval mismatch: got %s, want %s", decoded.Daemon.PollInterval, orig.Daemon.PollInterval)
	}
}

func TestRedactionAndCloneIsolation(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Audit.WebhookHMACSecret = "super-secret-hmac"
	cfg.Telemetry.BearerToken = "super-secret-bearer"

	redacted := cfg.Redacted()
	if redacted.Audit.WebhookHMACSecret != RedactedMask || redacted.Telemetry.BearerToken != RedactedMask {
		t.Fatalf("secrets were not redacted: %+v", redacted)
	}
	if cfg.Audit.WebhookHMACSecret == RedactedMask {
		t.Fatal("Redacted() mutated original secret in place")
	}

	redacted.Prune.ProtectedLabels[0] = "mutated=1"
	if cfg.Prune.ProtectedLabels[0] == "mutated=1" {
		t.Fatal("Clone/Redacted shared underlying slice memory with original Config")
	}
}

func TestAtomicStoreConcurrentHotReload(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "live.json")
	if err := os.WriteFile(cfgPath, []byte(`{"log_level":"info","daemon":{"poll_interval":"15s"}}`), 0o600); err != nil {
		t.Fatalf("seed live.json: %v", err)
	}

	initial, err := Load(cfgPath, func(string) (string, bool) { return "", false }, nil)
	if err != nil {
		t.Fatalf("initial Load: %v", err)
	}
	store, err := NewStore(initial, cfgPath, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				snap := store.Current()
				if err := snap.Validate(); err != nil {
					t.Errorf("concurrent reader observed invalid snapshot: %v", err)
				}
			}
		}()
	}

	// Valid reload swaps poll_interval to 45s
	if err := os.WriteFile(cfgPath, []byte(`{"log_level":"debug","daemon":{"poll_interval":"45s"}}`), 0o600); err != nil {
		t.Fatalf("update live.json: %v", err)
	}
	reloaded, err := store.Reload()
	if err != nil {
		t.Fatalf("valid Reload() failed: %v", err)
	}
	if reloaded.Daemon.PollInterval != Duration(45*time.Second) {
		t.Fatalf("PollInterval after reload = %s, want 45s", reloaded.Daemon.PollInterval)
	}

	// Corrupt reload must fail and preserve previous valid 45s snapshot
	if err := os.WriteFile(cfgPath, []byte(`{"watermarks":{"target_percent":95,"high_percent":80}}`), 0o600); err != nil {
		t.Fatalf("write invalid live.json: %v", err)
	}
	if _, err := store.Reload(); err == nil {
		t.Fatal("expected error reloading inverted watermarks, got nil")
	}
	if got := store.Current().Daemon.PollInterval; got != Duration(45*time.Second) {
		t.Fatalf("failed reload corrupted active config: PollInterval = %s, want 45s", got)
	}

	wg.Wait()
}
