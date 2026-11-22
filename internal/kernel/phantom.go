package kernel

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

const deletedSuffix = " (deleted)"

// FDStat holds metadata inspected from an open file descriptor under /proc/<pid>/fd/<fd>.
type FDStat struct {
	IsRegular bool
	SizeBytes int64
}

// ProcReader abstracts /proc filesystem traversal so unlinked open-FD forensics
// can be deterministically unit-tested across Linux, macOS, and Windows.
type ProcReader interface {
	ListDir(relPath string) ([]string, error)
	ReadFile(relPath string, maxBytes int64) (string, error)
	ReadLink(relPath string) (string, error)
	StatTarget(relPath string) (FDStat, error)
}

type osProcReader struct {
	root string
}

func (r osProcReader) fullPath(relPath string) string {
	if relPath == "" || relPath == "." {
		return r.root
	}
	return filepath.Join(r.root, filepath.FromSlash(relPath))
}

func (r osProcReader) ListDir(relPath string) ([]string, error) {
	entries, err := os.ReadDir(r.fullPath(relPath))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (r osProcReader) ReadFile(relPath string, maxBytes int64) (string, error) {
	return readBoundedTextFile(r.fullPath(relPath), maxBytes)
}

func (r osProcReader) ReadLink(relPath string) (string, error) {
	return os.Readlink(r.fullPath(relPath))
}

func (r osProcReader) StatTarget(relPath string) (FDStat, error) {
	info, err := os.Stat(r.fullPath(relPath))
	if err != nil {
		return FDStat{}, err
	}
	return FDStat{
		IsRegular: info.Mode().IsRegular(),
		SizeBytes: info.Size(),
	}, nil
}

// PhantomFD describes an unlinked file still held open on disk by one or more PIDs.
type PhantomFD struct {
	PID             int    `json:"pid"`
	FD              int    `json:"fd"`
	Comm            string `json:"comm"`
	ContainerID     string `json:"container_id,omitempty"`
	DeletedPath     string `json:"deleted_path"`
	SizeBytes       int64  `json:"size_bytes"`
	MountInodeKey   string `json:"mount_inode_key,omitempty"`
	DuplicateRefs   int    `json:"duplicate_refs"`
	InContainerRoot bool   `json:"in_container_root"`
}

// PhantomReport summarizes phantom disk space leaks discovered across /proc.
type PhantomReport struct {
	Supported          bool        `json:"supported"`
	ScannedAt          time.Time   `json:"scanned_at"`
	ScannedPIDs        int         `json:"scanned_pids"`
	SkippedPermPIDs    int         `json:"skipped_perm_pids"`
	TotalLeakedBytes   int64       `json:"total_leaked_bytes"`
	AffectedContainers int         `json:"affected_containers"`
	Findings           []PhantomFD `json:"findings"`
}

// PhantomScanner inspects /proc/[pid]/fd to pinpoint unlinked open files causing
// df vs du space discrepancies that ordinary 'docker prune' commands cannot reclaim.
type PhantomScanner struct {
	enabled          bool
	minBytes         int64
	containerRootDir string
	reader           ProcReader
	nowFn            func() time.Time
}

// NewPhantomScanner constructs a ProcFS unlinked-FD scanner from configuration.
func NewPhantomScanner(cfg config.KernelConfig, containerRootDir string) *PhantomScanner {
	procRoot := strings.TrimSpace(cfg.ProcRoot)
	if procRoot == "" {
		procRoot = "/proc"
	}
	minBytes := cfg.PhantomMinBytes.Bytes()
	if minBytes <= 0 {
		minBytes = (64 * config.MiB).Bytes()
	}
	return &PhantomScanner{
		enabled:          cfg.PhantomScanEnabled,
		minBytes:         minBytes,
		containerRootDir: strings.TrimSpace(containerRootDir),
		reader:           osProcReader{root: procRoot},
		nowFn:            time.Now,
	}
}

// NewPhantomScannerWithReader creates a scanner backed by a custom ProcReader for testing.
func NewPhantomScannerWithReader(reader ProcReader, minBytes int64, containerRootDir string) *PhantomScanner {
	if minBytes <= 0 {
		minBytes = 1024
	}
	return &PhantomScanner{
		enabled:          true,
		minBytes:         minBytes,
		containerRootDir: strings.TrimSpace(containerRootDir),
		reader:           reader,
		nowFn:            time.Now,
	}
}

// Scan traverses /proc/<pid>/fd, deduplicates shared kernel file objects via
// /proc/<pid>/fdinfo/<fd> (mnt_id:ino), and returns sorted phantom space findings.
func (s *PhantomScanner) Scan() (PhantomReport, error) {
	now := s.nowFn().UTC()
	if !s.enabled || s.reader == nil {
		return PhantomReport{Supported: false, ScannedAt: now}, nil
	}

	rootEntries, err := s.reader.ListDir("")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PhantomReport{Supported: false, ScannedAt: now}, nil
		}
		return PhantomReport{}, fmt.Errorf("read proc root: %w", err)
	}

	report := PhantomReport{
		Supported: true,
		ScannedAt: now,
		Findings:  make([]PhantomFD, 0),
	}

	dedupIndex := make(map[string]int)
	containerSet := make(map[string]struct{})

	for _, name := range rootEntries {
		pid, ok := parsePositiveInt(name)
		if !ok {
			continue
		}

		fdNames, err := s.reader.ListDir(name + "/fd")
		if err != nil {
			if isPermErr(err) {
				report.SkippedPermPIDs++
				continue
			}
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			continue
		}

		report.ScannedPIDs++
		var commLoaded bool
		var comm, containerID string

		for _, fdName := range fdNames {
			fdNum, ok := parseNonNegativeInt(fdName)
			if !ok {
				continue
			}

			fdRel := fmt.Sprintf("%s/fd/%s", name, fdName)
			linkTarget, err := s.reader.ReadLink(fdRel)
			if err != nil {
				continue
			}

			cleanPath, isDiskDeleted := classifyDeletedLinkTarget(linkTarget)
			if !isDiskDeleted {
				continue
			}

			st, err := s.reader.StatTarget(fdRel)
			if err != nil || !st.IsRegular || st.SizeBytes < s.minBytes {
				continue
			}

			if !commLoaded {
				if rawComm, cErr := s.reader.ReadFile(name+"/comm", 256); cErr == nil {
					comm = strings.TrimSpace(rawComm)
				}
				if comm == "" {
					comm = "unknown"
				}
				if rawCg, cgErr := s.reader.ReadFile(name+"/cgroup", 16<<10); cgErr == nil {
					containerID = ExtractContainerIDFromCgroup(rawCg)
				}
				commLoaded = true
			}

			fdInfoRel := fmt.Sprintf("%s/fdinfo/%s", name, fdName)
			mntInoKey := ""
			if rawFDInfo, infoErr := s.reader.ReadFile(fdInfoRel, 4096); infoErr == nil {
				mntInoKey = parseFDInfoIdentity(rawFDInfo)
			}

			// Deduplicate dup2'd stdout/stderr or forked workers holding the exact same inode.
			dedupKey := mntInoKey
			if dedupKey == "" {
				dedupKey = fmt.Sprintf("path:%s|size:%d", cleanPath, st.SizeBytes)
			}

			if existingIdx, exists := dedupIndex[dedupKey]; exists {
				report.Findings[existingIdx].DuplicateRefs++
				// Prefer retaining the lowest PID / FD deterministically while preserving container attribution.
				if report.Findings[existingIdx].ContainerID == "" && containerID != "" {
					report.Findings[existingIdx].ContainerID = containerID
					containerSet[containerID] = struct{}{}
				}
				continue
			}

			inRoot := s.containerRootDir != "" && strings.HasPrefix(cleanPath, s.containerRootDir)
			finding := PhantomFD{
				PID:             pid,
				FD:              fdNum,
				Comm:            comm,
				ContainerID:     containerID,
				DeletedPath:     cleanPath,
				SizeBytes:       st.SizeBytes,
				MountInodeKey:   mntInoKey,
				DuplicateRefs:   1,
				InContainerRoot: inRoot,
			}

			dedupIndex[dedupKey] = len(report.Findings)
			report.Findings = append(report.Findings, finding)
			report.TotalLeakedBytes += st.SizeBytes
			if containerID != "" {
				containerSet[containerID] = struct{}{}
			}
		}
	}

	report.AffectedContainers = len(containerSet)

	slices.SortFunc(report.Findings, func(a, b PhantomFD) int {
		if c := cmp.Compare(b.SizeBytes, a.SizeBytes); c != 0 {
			return c
		}
		if c := cmp.Compare(a.PID, b.PID); c != 0 {
			return c
		}
		return cmp.Compare(a.FD, b.FD)
	})

	return report, nil
}

// ExtractContainerIDFromCgroup extracts a 64-character lowercase hex OCI/Docker
// container ID from Linux cgroup v1 or cgroup v2 hierarchy lines.
func ExtractContainerIDFromCgroup(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		cgPath := line
		if len(parts) == 3 {
			cgPath = parts[2]
		}

		segments := strings.Split(cgPath, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := strings.TrimSpace(segments[i])
			if seg == "" {
				continue
			}
			seg = strings.TrimSuffix(seg, ".scope")
			for _, prefix := range []string{"docker-", "cri-containerd-", "libpod-", "containerd-"} {
				if strings.HasPrefix(seg, prefix) {
					seg = strings.TrimPrefix(seg, prefix)
					break
				}
			}
			if is64LowerHex(seg) {
				return seg
			}
		}
	}
	return ""
}

func classifyDeletedLinkTarget(linkTarget string) (cleanPath string, ok bool) {
	if !strings.HasSuffix(linkTarget, deletedSuffix) {
		return "", false
	}
	trimmed := strings.TrimSuffix(linkTarget, deletedSuffix)
	if trimmed == "" || !strings.HasPrefix(trimmed, "/") {
		// Rejects anon_inode:[eventpoll], socket:[...], pipe:[...], etc.
		return "", false
	}

	// Exclude RAM-backed pseudo-filesystems and shared memory segments.
	excludedPrefixes := []string{
		"/memfd:",
		"/dev/",
		"/run/shm/",
		"/SYSV",
		"/proc/",
		"/sys/",
	}
	for _, pfx := range excludedPrefixes {
		if strings.HasPrefix(trimmed, pfx) {
			return "", false
		}
	}
	return trimmed, true
}

func parseFDInfoIdentity(raw string) string {
	var mntID, ino string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "mnt_id:") {
			mntID = strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:"))
		} else if strings.HasPrefix(line, "ino:") {
			ino = strings.TrimSpace(strings.TrimPrefix(line, "ino:"))
		}
	}
	if mntID != "" && ino != "" && ino != "0" {
		return mntID + ":" + ino
	}
	return ""
}

func parsePositiveInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func parseNonNegativeInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

func is64LowerHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isPermErr(err error) bool {
	return errors.Is(err, os.ErrPermission) || os.IsPermission(err)
}
