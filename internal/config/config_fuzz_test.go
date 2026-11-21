package config

import (
	"encoding/json"
	"math"
	"testing"
)

func FuzzParseByteSize(f *testing.F) {
	seeds := []string{
		"0",
		"0B",
		"1024",
		"512KiB",
		"256MiB",
		"1.5GiB",
		"10TiB",
		"500MB",
		"-10GiB",
		"999999999999999999999999GiB",
		"NaNGiB",
		"InfMiB",
		"1..2GiB",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := ParseByteSize(input)
		if err != nil {
			return
		}
		if parsed < 0 {
			t.Fatalf("ParseByteSize(%q) produced negative ByteSize: %d", input, parsed)
		}

		wire, err := parsed.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON failed for valid ByteSize %d: %v", parsed, err)
		}
		var roundTrip ByteSize
		if err := roundTrip.UnmarshalJSON(wire); err != nil {
			t.Fatalf("UnmarshalJSON(%s) failed: %v", string(wire), err)
		}
		if roundTrip != parsed {
			t.Fatalf("round-trip mismatch for %q: got %d, want %d", input, roundTrip, parsed)
		}
	})
}

func FuzzLoadJSON(f *testing.F) {
	f.Add([]byte(`{"log_level":"info","watermarks":{"target_percent":70,"high_percent":80}}`))
	f.Add([]byte(`{"daemon":{"poll_interval":"10s"},"prune":{"enable_volume_prune":true}}`))
	f.Add([]byte(`{"unknown":123}`))
	f.Add([]byte(`{}{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		cfg := Default()
		if err := MergeJSONBytes(&cfg, payload); err != nil {
			return
		}
		cfg.Normalize()
		if err := cfg.Validate(); err != nil {
			return
		}

		// Any validated config must preserve hysteresis invariants and survive JSON re-serialization.
		if !(cfg.Watermarks.PreemptivePercent <= cfg.Watermarks.TargetPercent &&
			cfg.Watermarks.TargetPercent < cfg.Watermarks.HighPercent &&
			cfg.Watermarks.HighPercent < cfg.Watermarks.CriticalPercent &&
			cfg.Watermarks.CriticalPercent < cfg.Watermarks.PanicPercent) {
			t.Fatalf("validated config violated watermark ordering: %+v", cfg.Watermarks)
		}

		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("json.Marshal failed on validated config: %v", err)
		}
		reloaded := Default()
		if err := MergeJSONBytes(&reloaded, encoded); err != nil {
			t.Fatalf("MergeJSONBytes failed on marshaled valid config: %v", err)
		}
		reloaded.Normalize()
		if err := reloaded.Validate(); err != nil {
			t.Fatalf("re-validated config failed: %v", err)
		}
	})
}

func FuzzEnvOverrides(f *testing.F) {
	f.Add("debug", "json", "65", "75", "85", "92", "97", "4GiB", "20s")
	f.Add("invalid", "xml", "NaN", "90", "80", "70", "105", "-5B", "-1s")

	f.Fuzz(func(
		t *testing.T,
		level, format, pre, target, high, crit, panicPct, minFree, poll string,
	) {
		env := map[string]string{
			"DPD_LOG_LEVEL":            level,
			"DPD_LOG_FORMAT":           format,
			"DPD_WATERMARK_PREEMPTIVE": pre,
			"DPD_WATERMARK_TARGET":     target,
			"DPD_WATERMARK_HIGH":       high,
			"DPD_WATERMARK_CRITICAL":   crit,
			"DPD_WATERMARK_PANIC":      panicPct,
			"DPD_MIN_FREE_BYTES":       minFree,
			"DPD_POLL_INTERVAL":        poll,
		}
		cfg, err := Load("", func(k string) (string, bool) {
			v, ok := env[k]
			return v, ok
		}, nil)
		if err != nil {
			return
		}
		if math.IsNaN(cfg.Watermarks.HighPercent) || math.IsInf(cfg.Watermarks.HighPercent, 0) {
			t.Fatalf("NaN/Inf leaked past validation: %+v", cfg.Watermarks)
		}
		if cfg.Watermarks.TargetPercent >= cfg.Watermarks.HighPercent {
			t.Fatalf("hysteresis invariant broken: target=%v high=%v", cfg.Watermarks.TargetPercent, cfg.Watermarks.HighPercent)
		}
	})
}
