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
		val, err := strconv.
