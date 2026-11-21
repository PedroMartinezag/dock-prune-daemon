package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
)

// LogTruncateEntry records forensic provenance for a single truncated container JSON log.
type LogTruncateEntry struct {
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	LogPath        string `json:"log_path"`
	BytesReclaimed int64  `json:"bytes_reclaimed"`
	HashedBytes    int64  `json:"hashed_bytes"`
	ForensicSHA256 string `json:"forensic_sha256,omitempty"`
	DryRun         bool   `json:"dry_run"`
}

// LogTruncateReport aggregates Stage 0 zero-disruption container log truncation results.
type LogTruncateReport struct {
	InspectedContainers int                `json:"inspected_containers"`
	TruncatedCount      int                `json:"truncated_count"`
	SkippedProtected    int                `json:"skipped_protected"`
	SkippedRotationRace int                `json:"skipped_rotation_race"`
	BytesReclaimed      uint64             `json:"bytes_reclaimed"`
	Entries             []LogTruncateEntry `json:"entries,omitempty"`
}

// LogTruncator executes Stage 0 O_APPEND-safe truncation of oversized *-json.log files
// while computing pre-truncation SHA-256 forensic digests and preventing symlink/rotation races.
type LogTruncator struct {
	enabled          bool
	maxLogBytes      int64
	containerRootDir string
	// beforeTruncateHook is nil in production and used strictly by unit tests to inject
	// deterministic concurrent log-rotation races between hashing and f.Truncate(0).
	beforeTruncateHook func(cleanPath string)
}

// NewLogTruncator creates a hardened Stage 0 log truncator.
func NewLogTruncator(cfg config.PruneConfig, containerRootDir string) *LogTruncator {
	maxBytes := cfg.MaxContainerLogBytes.Bytes()
	if maxBytes <= 0 {
		maxBytes = (256 * config.MiB).Bytes()
	}
	return &LogTruncator{
		enabled:          cfg.EnableLogTruncate,
		maxLogBytes:      maxBytes,
		containerRootDir: strings.TrimSpace(containerRootDir),
	}
}

// TruncateOversizedLogs inspects containers via the Docker Engine, verifies log paths
// reside strictly within ContainerRootDir without symlink escapes, hashes contents with
// SHA-256, guards against concurrent rotation via os.SameFile, and truncates in-place.
func (lt *LogTruncator) TruncateOversizedLogs(
	ctx context.Context,
	eng docker.Engine,
	guard *Guard,
	dryRun bool,
) (LogTruncateReport, error) {
	var report LogTruncateReport
	if lt == nil || !lt.enabled || eng == nil {
		return report, nil
	}

	containers, err := eng.ListContainers(ctx, docker.ListContainersOptions{All: true})
	if err != nil {
		return report, fmt.Errorf("list containers for Stage 0 log truncation: %w", err)
	}

	resolvedRoot := resolveCanonicalDir(lt.containerRootDir)

	for _, summary := range containers {
		if err := ctx.Err(); err != nil {
			return report, err
		}

		insp, err := eng.InspectContainer(ctx, summary.ID)
		if err != nil {
			var apiErr *docker.APIError
			if errors.As(err, &apiErr) && apiErr.IsNotFound() {
				continue
			}
			return report, fmt.Errorf("inspect container %s for log path: %w", summary.ID, err)
		}
		report.InspectedContainers++

		if guard != nil {
			if protected, _ := guard.CheckContainerInspect(insp); protected {
				report.SkippedProtected++
				continue
			}
		}

		logDriver := strings.ToLower(strings.TrimSpace(insp.HostConfig.LogConfig.Type))
		if logDriver != "" && logDriver != "json-file" {
			continue
		}

		cleanPath, ok := validateSafeLogPath(insp.LogPath, resolvedRoot)
		if !ok {
			continue
		}

		entry, raced, didTruncate, err := lt.processSingleLogFile(ctx, insp, summary.PrimaryName(), cleanPath, dryRun)
		if err != nil {
			// Permission or transient disappearance on an individual container log must not abort the cycle.
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return report, err
		}
		if raced {
			report.SkippedRotationRace++
			continue
		}
		if !didTruncate {
			continue
		}

		report.TruncatedCount++
		if entry.BytesReclaimed > 0 {
			report.BytesReclaimed += uint64(entry.BytesReclaimed)
		}
		report.Entries = append(report.Entries, entry)
	}

	return report, nil
}

func (lt *LogTruncator) processSingleLogFile(
	ctx context.Context,
	insp docker.ContainerInspect,
	fallbackName string,
	cleanPath string,
	dryRun bool,
) (entry LogTruncateEntry, rotationRaced bool, truncated bool, err error) {
	// Step 1: Lstat without following symlinks to reject container-planted symlink escapes.
	lstatBefore, err := os.Lstat(cleanPath)
	if err != nil {
		return LogTruncateEntry{}, false, false, err
	}
	if !lstatBefore.Mode().IsRegular() {
		return LogTruncateEntry{}, false, false, nil
	}
	if lstatBefore.Size() < lt.maxLogBytes {
		return LogTruncateEntry{}, false, false, nil
	}

	ctrName := strings.TrimPrefix(strings.TrimSpace(insp.Name), "/")
	if ctrName == "" {
		ctrName = fallbackName
	}

	if dryRun {
		return LogTruncateEntry{
			ContainerID:    insp.ID,
			ContainerName:  ctrName,
			LogPath:        cleanPath,
			BytesReclaimed: lstatBefore.Size(),
			DryRun:         true,
		}, false, true, nil
	}

	// Step 2: Open O_RDWR and verify inode identity matches lstatBefore.
	f, err := os.OpenFile(cleanPath, os.O_RDWR, 0)
	if err != nil {
		return LogTruncateEntry{}, false, false, err
	}
	defer f.Close()

	openStat, err := f.Stat()
	if err != nil {
		return LogTruncateEntry{}, false, false, err
	}
	if !openStat.Mode().IsRegular() || !os.SameFile(lstatBefore, openStat) {
		return LogTruncateEntry{}, true, false, nil
	}
	snapshotSize := openStat.Size()
	if snapshotSize < lt.maxLogBytes {
		// Docker's built-in log rotation already truncated or rotated the file concurrently.
		return LogTruncateEntry{}, true, false, nil
	}

	// Step 3: Stream up to snapshotSize bytes through SHA-256 for tamper-evident audit trails.
	digest, hashedBytes, err := streamSHA256Bounded(ctx, f, snapshotSize)
	if err != nil {
		return LogTruncateEntry{}, false, false, err
	}

	if lt.beforeTruncateHook != nil {
		lt.beforeTruncateHook(cleanPath)
	}

	// Step 4: Re-verify path still resolves to the exact same inode before calling f.Truncate(0).
	// If dockerd rotated abc-json.log -> abc-json.log.1 while we hashed, abort cleanly!
	lstatAfterHash, err := os.Lstat(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LogTruncateEntry{}, true, false, nil
		}
		return LogTruncateEntry{}, false, false, err
	}
	if !os.SameFile(openStat, lstatAfterHash) {
		return LogTruncateEntry{}, true, false, nil
	}

	latestStat, err := f.Stat()
	if err != nil {
		return LogTruncateEntry{}, false, false, err
	}
	reclaimed := latestStat.Size()
	if reclaimed < lt.maxLogBytes {
		return LogTruncateEntry{}, true, false, nil
	}

	if err := f.Truncate(0); err != nil {
		return LogTruncateEntry{}, false, false, fmt.Errorf("truncate %s: %w", cleanPath, err)
	}
	_ = f.Sync()

	return LogTruncateEntry{
		ContainerID:    insp.ID,
		ContainerName:  ctrName,
		LogPath:        cleanPath,
		BytesReclaimed: reclaimed,
		HashedBytes:    hashedBytes,
		ForensicSHA256: digest,
		DryRun:         false,
	}, false, true, nil
}

func streamSHA256Bounded(ctx context.Context, r io.Reader, limit int64) (hexDigest string, n int64, err error) {
	h := sha256.New()
	buf := make([]byte, 64*1024)
	remaining := limit

	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return "", n, err
		}
		chunkSize := int64(len(buf))
		if remaining < chunkSize {
			chunkSize = remaining
		}
		readN, readErr := r.Read(buf[:chunkSize])
		if readN > 0 {
			_, _ = h.Write(buf[:readN])
			n += int64(readN)
			remaining -= int64(readN)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", n, readErr
		}
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func resolveCanonicalDir(dir string) string {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return ""
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		abs = filepath.Clean(trimmed)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

func validateSafeLogPath(rawLogPath, canonicalRoot string) (string, bool) {
	trimmed := strings.TrimSpace(rawLogPath)
	if trimmed == "" || !strings.HasSuffix(trimmed, "-json.log") {
		return "", false
	}
	absLog, err := filepath.Abs(trimmed)
	if err != nil || !filepath.IsAbs(absLog) {
		return "", false
	}

	// Resolve symlinks strictly on the parent directory so os.Lstat can still detect
	// whether the final *-json.log filename itself was replaced with a symlink.
	parentDir := filepath.Dir(absLog)
	resolvedParent, err := filepath.EvalSymlinks(parentDir)
	if err != nil {
		return "", false
	}
	candidate := filepath.Join(resolvedParent, filepath.Base(absLog))

	if canonicalRoot != "" {
		rel, relErr := filepath.Rel(canonicalRoot, candidate)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
	}
	return candidate, true
}
