package kernel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

func TestParsePSI_ValidAndInvalidPayloads(t *testing.T) {
	t.Parallel()

	raw := "some avg10=12.50 avg60=6.25 avg300=1.10 total=987654321\n" +
		"full avg10=4.20 avg60=2.00 avg300=0.40 total=123456789\n"

	some, full, err := ParsePSI(raw)
	if err != nil {
		t.Fatalf("ParsePSI unexpected error: %v", err)
	}
	if some.Avg10 != 12.50 || some.TotalMicros != 987654321 {
		t.Fatalf("unexpected some metrics: %+v", some)
	}
	if full.Avg10 != 4.20 || full.TotalMicros != 123456789 {
		t.Fatalf("unexpected full metrics: %+v", full)
	}

	invalidCases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"missing some line", "full avg10=1.00 avg60=1.00 avg300=1.00 total=10"},
		{"out of range avg10", "some avg10=105.00 avg60=1.00 avg300=1.00 total=10"},
		{"negative avg60", "some avg10=1.00 avg60=-0.50 avg300=1.00 total=10"},
		{"missing total field", "some avg10=1.00 avg60=1.00 avg300=1.00 extra=1"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParsePSI(tc.raw); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestGovernor_QuadraticBackoffAndPanicOverride(t *testing.T) {
	t.Parallel()

	tmpProc := t.TempDir()
	pressureDir := filepath.Join(tmpProc, "pressure")
	if err := os.MkdirAll(pressureDir, 0o755); err != nil {
		t.Fatalf("mkdir pressure: %v", err)
	}

	// Effective stall: IOSome.Avg10 = 50% against 25% budget => ratio = 2.0.
	// With gamma = 2.0 => factor = 1 + 2*(2^2) = 9.0 => 200ms * 9 = 1800ms.
	ioContent := "some avg10=50.00 avg60=20.00 avg300=5.00 total=500000\n" +
		"full avg10=10.00 avg60=4.00 avg300=1.00 total=100000\n"
	memContent := "some avg10=3.00 avg60=1.00 avg300=0.00 total=20000\n" +
		"full avg10=1.00 avg60=0.50 avg300=0.00 total=5000\n"

	if err := os.WriteFile(filepath.Join(pressureDir, "io"), []byte(ioContent), 0o600); err != nil {
		t.Fatalf("write io psi: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pressureDir, "memory"), []byte(memContent), 0o600); err != nil {
		t.Fatalf("write memory psi: %v", err)
	}

	gov := NewGovernor(config.KernelConfig{
		PSIEnabled:         true,
		ProcRoot:           tmpProc,
		PSIIOBudgetPercent: 25.0,
		PSIGamma:           2.0,
		BaseStagePause:     config.Duration(200 * time.Millisecond),
		MaxStagePause:      config.Duration(5 * time.Second),
	})

	snap, err := gov.ReadSnapshot()
	if err != nil {
		t.Fatalf("ReadSnapshot error: %v", err)
	}
	if !snap.Supported {
		t.Fatal("expected PSI Supported=true on synthetic /proc/pressure")
	}

	pause := gov.RecommendedPause(snap, false)
	if pause != 1800*time.Millisecond {
		t.Fatalf("RecommendedPause = %s, want 1.8s", pause)
	}

	// PANIC regime must bypass all I/O yielding immediately.
	if panicPause := gov.RecommendedPause(snap, true); panicPause != 0 {
		t.Fatalf("RecommendedPause(bypassForPanic=true) = %s, want 0", panicPause)
	}

	// Missing /proc/pressure must degrade gracefully without error.
	missingGov := NewGovernor(config.KernelConfig{
		PSIEnabled:     true,
		ProcRoot:       filepath.Join(tmpProc, "nonexistent"),
		BaseStagePause: config.Duration(250 * time.Millisecond),
		MaxStagePause:  config.Duration(5 * time.Second),
	})
	unsupportedSnap, err := missingGov.ReadSnapshot()
	if err != nil {
		t.Fatalf("expected nil error on missing /proc/pressure, got %v", err)
	}
	if unsupportedSnap.Supported {
		t.Fatal("expected Supported=false when /proc/pressure is absent")
	}
	if got := missingGov.RecommendedPause(unsupportedSnap, false); got != 250*time.Millisecond {
		t.Fatalf("fallback pause = %s, want 250ms", got)
	}
}

func TestExtractContainerIDFromCgroup(t *testing.T) {
	t.Parallel()

	const cid = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "cgroup v2 systemd docker scope",
			raw:  "0::/system.slice/docker-" + cid + ".scope\n",
			want: cid,
		},
		{
			name: "cgroup v1 classic docker hierarchy",
			raw:  "11:memory:/docker/" + cid + "\n5:cpu:/docker/" + cid + "\n",
			want: cid,
		},
		{
			name: "containerd k8s pod scope",
			raw:  "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-" + cid + ".scope\n",
			want: cid,
		},
		{
			name: "host systemd service without container",
			raw:  "0::/system.slice/sshd.service\n",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractContainerIDFromCgroup(tc.raw); got != tc.want {
				t.Fatalf("ExtractContainerIDFromCgroup() = %q, want %q", got, tc.want)
			}
		})
	}
}

type fakeProcFS struct {
	dirs      map[string][]string
	files     map[string]string
	links     map[string]string
	stats     map[string]FDStat
	permPaths map[string]bool
}

func (f *fakeProcFS) ListDir(relPath string) ([]string, error) {
	if f.permPaths[relPath] {
		return nil, os.ErrPermission
	}
	entries, ok := f.dirs[relPath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func (f *fakeProcFS) ReadFile(relPath string, _ int64) (string, error) {
	content, ok := f.files[relPath]
	if !ok {
		return "", os.ErrNotExist
	}
	return content, nil
}

func (f *fakeProcFS) ReadLink(relPath string) (string, error) {
	target, ok := f.links[relPath]
	if !ok {
		return "", os.ErrNotExist
	}
	return target, nil
}

func (f *fakeProcFS) StatTarget(relPath string) (FDStat, error) {
	st, ok := f.stats[relPath]
	if !ok {
		return FDStat{}, os.ErrNotExist
	}
	return st, nil
}

func TestPhantomScanner_DeduplicatesSharedInodesAndFiltersPseudoFS(t *testing.T) {
	t.Parallel()

	const containerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const gib = int64(1024 * 1024 * 1024)
	const mib = int64(1024 * 1024)

	mockProc := &fakeProcFS{
		dirs: map[string][]string{
			"":        {"self", "net", "1042", "2080", "9999"},
			"1042/fd": {"0", "1", "2", "3", "4"},
			"2080/fd": {"5"},
		},
		permPaths: map[string]bool{
			"9999/fd": true,
		},
		files: map[string]string{
			"1042/comm":     "node\n",
			"1042/cgroup":   "0::/system.slice/docker-" + containerA + ".scope\n",
			"1042/fdinfo/1": "pos:\t999\nflags:\t0100002\nmnt_id:\t44\nino:\t778899\n",
			"1042/fdinfo/2": "pos:\t999\nflags:\t0100002\nmnt_id:\t44\nino:\t778899\n",
			"2080/comm":     "postgres\n",
			"2080/cgroup":   "0::/system.slice/postgresql.service\n",
			"2080/fdinfo/5": "pos:\t0\nmnt_id:\t12\nino:\t334455\n",
		},
		links: map[string]string{
			// FD 1 and FD 2 point to the exact same unlinked 4 GiB log file (dup2 stdout/stderr)
			"1042/fd/0": "/dev/null",
			"1042/fd/1": "/var/lib/docker/containers/abc/abc-json.log (deleted)",
			"1042/fd/2": "/var/lib/docker/containers/abc/abc-json.log (deleted)",
			// FD 3 is a RAM-backed memfd and must be ignored even though "(deleted)"
			"1042/fd/3": "/memfd:v8-jit-code (deleted)",
			// FD 4 is a tiny 8 KiB deleted file below minBytes threshold
			"1042/fd/4": "/tmp/tiny.tmp (deleted)",
			// PID 2080 holds a separate 512 MiB deleted WAL segment
			"2080/fd/5": "/var/lib/postgresql/data/pg_wal/0001 (deleted)",
		},
		stats: map[string]FDStat{
			"1042/fd/1": {IsRegular: true, SizeBytes: 4 * gib},
			"1042/fd/2": {IsRegular: true, SizeBytes: 4 * gib},
			"1042/fd/3": {IsRegular: true, SizeBytes: 2 * gib},
			"1042/fd/4": {IsRegular: true, SizeBytes: 8 * 1024},
			"2080/fd/5": {IsRegular: true, SizeBytes: 512 * mib},
		},
	}

	scanner := NewPhantomScannerWithReader(mockProc, 64*mib, "/var/lib/docker")
	report, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}

	if !report.Supported {
		t.Fatal("expected report.Supported=true")
	}
	if report.ScannedPIDs != 2 || report.SkippedPermPIDs != 1 {
		t.Fatalf("unexpected PID counts: scanned=%d skipped=%d", report.ScannedPIDs, report.SkippedPermPIDs)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d: %+v", len(report.Findings), report.Findings)
	}

	// Finding 0 must be the 4 GiB container log (sorted largest first, counted once, DuplicateRefs=2)
	top := report.Findings[0]
	if top.SizeBytes != 4*gib || top.DuplicateRefs != 2 || top.ContainerID != containerA || !top.InContainerRoot {
		t.Fatalf("unexpected primary finding: %+v", top)
	}

	// Total leaked bytes must equal 4 GiB + 512 MiB (NOT 8 GiB + 512 MiB)
	wantTotal := 4*gib + 512*mib
	if report.TotalLeakedBytes != wantTotal {
		t.Fatalf("TotalLeakedBytes = %d, want %d", report.TotalLeakedBytes, wantTotal)
	}
	if report.AffectedContainers != 1 {
		t.Fatalf("AffectedContainers = %d, want 1", report.AffectedContainers)
	}
}
